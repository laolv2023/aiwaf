# AIWAF-Stream trace_id 计算方法

> 版本: 1.0 | 最后更新: 2026-06-28
> 源码: `aiwaf/stream/preprocessor.py` 函数 `generate_deterministic_trace_id()`

---

## 1. 概述

trace_id 是 AIWAF-Stream 的**零信任流式指纹**，用于：

- **端到端追溯**：从 Akto 消息 → AIWAF 检测 → 告警输出 → DLQ 死信，全链路可追溯
- **请求去重**：Redis SETNX `aiwaf:idem:{trace_id}` 保证相同请求只处理一次（TTL=24h）
- **确定性**：相同输入永远产生相同输出，客户端不可伪造

---

## 2. 计算流程

```
输入: std_log 中的 4 个字段
  ├── client_ip      (来源 IP)
  ├── uri_path       (URL 路径，不含 query string)
  ├── request_body   (请求体原始内容)
  └── timestamp      (请求时间戳)
        │
        ▼
Step 1: request_body → bytes
  ├── str   → .encode('utf-8')
  ├── bytes → 原样
  └── dict/list → orjson.dumps() 序列化
        │
        ▼
Step 2: 防截断保护
  └── if len(body_bytes) > MAX_BODY_HASH_BYTES (默认 10MB):
        body_bytes = body_bytes[:MAX_BODY_HASH_BYTES]
        │
        ▼
Step 3: body → MD5 哈希
  └── body_hash = MD5(body_bytes).hexdigest()  ← 32 字符十六进制
        │
        ▼
Step 4: 拼接指纹原料
  └── raw = f"{ip}|{uri}|{body_hash}|{timestamp}"
        │
        ▼
Step 5: SHA256 → 截断 32 字符
  └── trace_id = SHA256(raw.encode('utf-8')).hexdigest()[:32]
```

---

## 3. 源码

```python
# aiwaf/stream/preprocessor.py

def generate_deterministic_trace_id(std_log: dict) -> str:
    """零信任流式指纹：基于完整 Body bytes 计算，杜绝截断碰撞"""
    ip = std_log.get("client_ip", "")
    uri = std_log.get("uri_path", "")
    ts = str(std_log.get("timestamp", ""))

    raw_body = std_log.get("request_body", "")

    # Step 1: 强制处理 dict/list 等非字符串类型
    if isinstance(raw_body, str):
        raw_body_bytes = raw_body.encode('utf-8')
    elif isinstance(raw_body, bytes):
        raw_body_bytes = raw_body
    else:
        raw_body_bytes = orjson.dumps(raw_body)

    # Step 2: 防截断保护（仅超 10MB 时截断，防 OOM）
    if len(raw_body_bytes) > MAX_BODY_HASH_BYTES:
        raw_body_bytes = raw_body_bytes[:MAX_BODY_HASH_BYTES]

    # Step 3: body → MD5
    body_hash = hashlib.md5(raw_body_bytes).hexdigest()

    # Step 4 + 5: 拼接 + SHA256 + 截断 32 字符
    raw = f"{ip}|{uri}|{body_hash}|{ts}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]
```

---

## 4. 设计要点

| 设计决策 | 原因 |
|---|---|
| **先 MD5 body，再 SHA256 拼接** | body 可能很大（文件上传），先 MD5 压缩为 32 字符固定长度，再做 SHA256 |
| **截断 10MB 防 OOM** | 文件上传 body 可能数百 MB，直接 SHA256 内存压力大 |
| **截断 SHA256 为 32 字符（128 bit）** | 32 字符十六进制 = 128 bit 有效熵，碰撞概率足够低 |
| **timestamp 参与计算** | 相同 IP + URI + Body 的重复请求有不同的 trace_id（按时间区分） |
| **分隔符 `\|`** | 防止字段拼接歧义（如 `ip="1.1" uri="1.1"` vs `ip="1" uri="1.1.1"`） |
| **确定性** | 相同输入永远产生相同输出，便于去重（Redis SETNX）和端到端追溯 |

---

## 5. 字段来源

trace_id 的 4 个输入字段全部来自 Akto Kafka 消息，经 `akto_adapter.py` 适配和 `preprocessor.py` 标准化后传入：

| 输入字段 | Akto 消息字段 | 适配转换 | 说明 |
|---|---|---|---|
| `client_ip` | `ip` | 直接映射 | 请求来源 IP |
| `uri_path` | `path` | `urlparse(path).path` 拆分 | URL 路径，不含 query string |
| `request_body` | `requestPayload` | 直接映射 | 请求体原始内容 |
| `timestamp` | `time` | `float(time_str)` 类型转换 | 请求时间戳（unix epoch 秒） |

---

## 6. 计算示例

### 示例 1：探测路径（空 body）

```
输入:
  client_ip    = "203.0.113.3"
  uri_path     = "/.env"
  request_body = ""
  timestamp    = 1719500000.0

Step 1: body_bytes = b"" (空字符串)
Step 2: 无截断
Step 3: body_hash = MD5(b"").hexdigest()
       = "d41d8cd98f00b204e9800998ecf8427e"
Step 4: raw = "203.0.113.3|/.env|d41d8cd98f00b204e9800998ecf8427e|1719500000.0"
Step 5: trace_id = SHA256(raw).hexdigest()[:32]
       = "f44ab975e2c81a3b9f0d6e7c4a2b8c1d"
```

### 示例 2：POST 请求（含 body）

```
输入:
  client_ip    = "192.168.1.100"
  uri_path     = "/api/users/create"
  request_body = '{"name":"alice","role":"admin"}'
  timestamp    = 1719500100.0

Step 1: body_bytes = b'{"name":"alice","role":"admin"}'
Step 2: 无截断 (28 字节 < 10MB)
Step 3: body_hash = MD5(body_bytes).hexdigest()
       = "a1b2c3d4e5f6789012345678abcdef01"
Step 4: raw = "192.168.1.100|/api/users/create|a1b2c3d4e5f6789012345678abcdef01|1719500100.0"
Step 5: trace_id = SHA256(raw).hexdigest()[:32]
       = "b5c6d7e8f90123456789012345678901"
```

### 示例 3：相同请求不同时间（trace_id 不同）

```
请求 A: timestamp = 1719500000.0 → trace_id = "f44ab975..."
请求 B: timestamp = 1719500001.0 → trace_id = "e5f6a789..."  ← 不同

原因: timestamp 参与计算，相同内容不同时间产生不同 trace_id
```

### 示例 4：相同 IP + URI 不同 body（trace_id 不同）

```
请求 A: body = ""           → body_hash = "d41d8cd9..." → trace_id = "f44ab975..."
请求 B: body = '{"x":1}'    → body_hash = "a1b2c3d4..." → trace_id = "c3d4e5f6..."  ← 不同

原因: body 的 MD5 参与计算，不同 body 产生不同 trace_id
```

---

## 7. 相关配置项

| 配置项 | 默认值 | 影响 |
|---|---|---|
| `max_body_hash_bytes` | `10485760` (10MB) | body 超过此值时截断后再 MD5，防 OOM。**影响 trace_id** |
| `max_body_store_bytes` | `1024` (1KB) | `req_body_truncated` 字段的存储截断。**不影响 trace_id** |

**关键区别**：

- `max_body_hash_bytes`（10MB）影响 trace_id 计算 — 超过 10MB 的 body 会被截断后再 MD5
- `max_body_store_bytes`（1KB）仅影响告警中的 `req_body_truncated` 字段 — 不影响指纹

两者独立，body 存储截断不影响指纹准确性。

---

## 8. 去重机制

trace_id 用于 Redis SETNX 去重：

```python
# redis_facade.py
async def is_duplicate_and_add(self, trace_id, is_retry=False, retry_count=0):
    idem_key = f"aiwaf:idem:{trace_id}:retry_{retry_count}" if is_retry \
               else f"aiwaf:idem:{trace_id}"
    result = await self.redis.set(idem_key, "1", nx=True, ex=self.dedup_ttl)
    return result is None  # None=已存在（重复），True=新写入
```

- **Key**: `aiwaf:idem:{trace_id}`
- **操作**: `SET NX EX`（不存在时写入，TTL=24h）
- **效果**: 相同 trace_id 的请求在 24 小时内只处理一次

---

## 9. 告警中的 trace_id

trace_id 作为 `akto.aiwaf.alerts` Topic 的第一个字段输出：

```json
{
  "trace_id": "f44ab975e2c81a3b9f0d6e7c4a2b8c1d",
  "rule_id": "KeywordBlock:Keyword block: Inherently suspicious: probe path",
  "alert_timestamp": 1719500000.0,
  "client_ip": "203.0.113.3",
  ...
}
```

下游消费者可通过 trace_id 关联：
- 原始 Akto 消息（在 `akto.api.logs` Topic 中搜索）
- AIWAF 告警（在 `akto.aiwaf.alerts` Topic 中搜索）
- DLQ 死信（在 `akto.aiwaf.dlq` Topic 中搜索）

---

## 10. 相关文档

- [检测能力详解](detection_capabilities.md)
- [检测模式实现机制](detection_implementation.md)
- [部署与配置](deployment.md)
