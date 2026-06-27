# AIWAF 对接 Akto Kafka 数据源 — 设计方案

> 项目：AIWAF (https://github.com/laolv2023/aiwaf)
> 数据源：Akto (https://github.com/akto-api-security/akto)
> 日期：2026-06-27
> 状态：设计评审

---

## 1. 需求概述

AIWAF 从 Akto 的 Kafka Topic `akto.api.logs`（JSON 格式）消费 API 流量数据，经检测引擎处理后，将告警输出到 Kafka Topic `akto.aiwaf.alerts`。

```
┌──────────────────────────────────────────────────────────┐
│                      Akto 平台                              │
│                                                            │
│  data-ingestion-service ──→ Kafka: akto.api.logs (JSON)    │
│  (SDK/Agent/Apigee/Arcade 等多源流量接入)                      │
│                                         │                  │
│  ┌──────────────────────────────────────┤                  │
│  │              │              │         │                  │
│  ▼              ▼              ▼         ▼                  │
│  api-runtime   api-analyser  threat-detection  AIWAF (新增) │
│  (现有消费者)   (现有消费者)   (经 akto.api.logs2)  (新消费者) │
│                                                            │
└──────────────────────────────────┬───────────────────────┘
                                   │
                                   ▼
                        ┌─────────────────────┐
                        │  AIWAF-Stream Engine │
                        │                     │
                        │  Consumer (新增)     │
                        │  ↓                  │
                        │  akto_adapter.py     │
                        │  (JSON → std_log)   │
                        │  ↓                  │
                        │  preprocessor.py     │
                        │  (transform_raw_log) │
                        │  ↓                  │
                        │  acl_bootstrap.py    │
                        │  (run_core_logic)    │
                        │  ↓                  │
                        │  Producer (现有)     │
                        │  → akto.aiwaf.alerts │
                        └─────────────────────┘
```

### 1.1 数据源选择

| Topic | 格式 | 生产者 | AIWAF 消费 |
|---|---|---|---|
| `akto.api.logs` | **JSON 字符串** | data-ingestion-service（完全开源） | ✅ 已选 |
| `akto.api.logs2` | Protobuf bytes | 未在开源仓库中（可能 SaaS infra 层） | ❌ 不选 |

**选择 `akto.api.logs` 的原因：**
- 生产者代码完全开源（`data-ingestion-service/KafkaUtils.java`）
- JSON 格式无需 Protobuf 编译，Python 直接 `json.loads`
- data-ingestion-service 同时支持 SDK / AI Agent / Apigee / Arcade / Dify / TrueFoundry / Syslog 等 7 种流量来源
- 社区版/企业版均产生数据到此 Topic

### 1.2 akto.api.logs 消息格式

```json
{
  "path": "/api/users/123?name=alice&age=30",
  "method": "GET",
  "requestHeaders": "{\"host\":\"api.example.com\",\"authorization\":\"Bearer xxx\"}",
  "responseHeaders": "{\"content-type\":\"application/json\"}",
  "requestPayload": "",
  "responsePayload": "{\"id\":123,\"name\":\"Alice\"}",
  "ip": "10.0.1.5",
  "destIp": "10.0.2.10",
  "time": "1719500000",
  "statusCode": "200",
  "status": "OK",
  "akto_account_id": "1000000",
  "akto_vxlan_id": "1",
  "is_pending": "false",
  "source": "MIRRORING",
  "direction": "REQUEST_RESPONSE",
  "tag": "{\"akto_guardrail_mode\":\"OBSERVE\"}"
}
```

**关键特征：所有字段均为 String 类型**（包括 `statusCode` 和 `time`），适配层需做类型转换。

---

## 2. 兼容性分析

### 2.1 AIWAF 数据流

```
Kafka 消息 (JSON)
    │
    ▼
akto_adapter.py          ← 新增：JSON → raw_log dict
    │ 输出: {client_ip, uri_path, query_params, status, timestamp, method, request_body, ...}
    ▼
preprocessor.py          ← 现有：transform_raw_log(raw_log)
    │ 读取: raw_log["client_ip"], raw_log["uri_path"], raw_log.get("query_params", {}),
    │       raw_log.get("status", 200), raw_log["timestamp"], raw_log.get("request_body", "")
    │ 输出: std_log = {client_ip, uri_path, query_keys, query_strings, status_code,
    │                  timestamp, method, trace_id, req_body_truncated}
    │ 注意: transform_raw_log 会 del std_log["request_body"]
    ▼
engine.py process_log()  ← 现有：调用速率限制 + 关键词检测
    │ 读取: std_log["trace_id"], std_log["client_ip"], std_log["uri_path"],
    │       std_log.get("timestamp"), std_log.get("status_code")
    ▼
acl_bootstrap.py         ← 现有：run_core_logic_batch_isolated()
    │ 直接索引: std_log["uri_path"]  ← KeyError 风险！
    │ 安全读取: std_log.get("query_keys", []), std_log.get("client_ip", "unknown")
    ▼
告警输出 / DLQ
```

### 2.2 字段兼容性矩阵

| AIWAF 字段 | 读取方式 | 类型要求 | Akto JSON 对应字段 | 转换需求 | 兼容性 |
|---|---|---|---|---|---|
| `client_ip` | `.get("client_ip", "unknown")` | str | `ip` | 直接映射 | ✅ |
| `uri_path` | `std_log["uri_path"]` **直接索引** | str | `path` | 需拆分 query string，默认 "/" | ⚠️ 必须非 None |
| `query_params` | `.get("query_params", {})` | dict | `path` 中的 query | `urllib.parse.parse_qs` 解析 | ✅ |
| `status` | `.get("status", 200)` | int | `statusCode` (String) | `int(statusCode)` | ⚠️ 需转 int |
| `timestamp` | `str(timestamp)` → 限频计算 | float/int | `time` (String) | `float(time)` | ⚠️ 需转 float |
| `method` | `.get("method", "GET")` | str | `method` | 直接映射 | ✅ |
| `request_body` | `.get("request_body", "")` | str/bytes | `requestPayload` | 直接映射 | ✅ |

### 2.3 关键兼容性发现

1. **`transform_raw_log` 读取 `query_params`（dict），不是 `query_keys`/`query_strings`** — 适配层必须输出 `query_params` dict，`transform_raw_log` 内部会拆分为 `query_keys` 和 `query_strings`

2. **`transform_raw_log` 读取 `status`（不是 `status_code`）** — `raw_log.get("status", 200)`，适配层输出键名必须是 `status`

3. **`run_core_logic_batch_isolated` 用 `std_log["uri_path"]` 直接索引** — 不是 `.get()`，如果 `uri_path` 缺失会 KeyError 崩溃。适配层必须始终提供此字段

4. **Akto 的 `statusCode` 和 `time` 是 String 类型** — 适配层必须转为 int/float，否则 `evaluate_rate_limit` 中 `now - t < window` 会 TypeError

5. **`request_body` 在 `transform_raw_log` 后会被 `del`** — 适配层提供初始值即可，不需要保留到后续

6. **`trace_id` 由 `generate_deterministic_trace_id` 生成** — 依赖 `client_ip` + `uri_path` + `timestamp` + `request_body`，适配层需全部提供

---

## 3. 改造方案

### 3.1 新增文件：akto_adapter.py

```python
# akto_adapter.py — 新增文件
import json
from urllib.parse import urlparse, parse_qs
from typing import Dict, Any

def parse_akto_json_message(raw_json: str) -> Dict[str, Any]:
    """将 akto.api.logs 的 JSON 消息转为 transform_raw_log 期望的格式"""
    msg = json.loads(raw_json) if isinstance(raw_json, (str, bytes)) else raw_json

    # path 含完整 URI（含 query string），需拆分
    raw_path = msg.get("path", "/") or "/"
    parsed = urlparse(raw_path if "://" in raw_path else f"http://dummy{raw_path}")

    # transform_raw_log 期望 query_params 是 dict（key → str 或 list）
    query_params = {}
    for k, v in parse_qs(parsed.query).items():
        query_params[k] = v[0] if len(v) == 1 else v

    # statusCode 和 time 在 akto.api.logs 中是 String 类型，需转 int/float
    status_code = msg.get("statusCode", "200")
    try:
        status_int = int(status_code)
    except (ValueError, TypeError):
        status_int = 200

    time_str = msg.get("time", "0")
    try:
        timestamp = float(time_str)
    except (ValueError, TypeError):
        timestamp = 0.0

    return {
        # transform_raw_log 直接读取的字段（键名必须匹配）
        "client_ip": msg.get("ip") or msg.get("client_ip") or "unknown",
        "timestamp": timestamp,
        "method": msg.get("method", "GET"),
        "uri_path": parsed.path or "/",
        "query_params": query_params,   # ← transform_raw_log 读取此字段
        "status": status_int,           # ← transform_raw_log 读取 raw_log.get("status", 200)
        "request_body": msg.get("requestPayload", "") or "",
        # akto 扩展字段（透传到告警）
        "akto_account_id": msg.get("akto_account_id", ""),
        "akto_vxlan_id": msg.get("akto_vxlan_id", ""),
        "source": msg.get("source", ""),
        "direction": msg.get("direction", ""),
        "dest_ip": msg.get("destIp", ""),
        "response_payload": msg.get("responsePayload", ""),
    }
```

### 3.2 改造 engine.py — 新增 Consumer

```python
# engine.py 改造 — 新增 Consumer

from aiokafka import AIOKafkaConsumer, AIOKafkaProducer

class AIWAFStreamEngine:
    def __init__(self, settings, state_mgr, model_path):
        # ... 现有代码 ...
        self.settings = settings

    async def start(self):
        # Producer（现有）
        self.producer = AIOKafkaProducer(
            bootstrap_servers=self.settings.kafka_brokers,
            value_serializer=lambda v: v,
            compression_type="lz4",
        )
        await self.producer.start()

        # Consumer（新增）
        self.consumer = AIOKafkaConsumer(
            self.settings.input_topic,            # "akto.api.logs"
            bootstrap_servers=self.settings.kafka_brokers,
            group_id=self.settings.consumer_group, # "aiwaf-consumer-group"
            value_deserializer=lambda v: v,        # 原始 bytes，交给 adapter
            key_deserializer=lambda v: v.decode('utf-8') if v else None,
            auto_offset_reset="earliest",
            enable_auto_commit=False,              # 手动提交
            max_poll_records=500,
        )
        await self.consumer.start()

        # 启动消费循环
        asyncio.create_task(self._consume_loop())

    async def _consume_loop(self):
        """Kafka 消费循环 — 替代外部调用 process_log()"""
        from akto_adapter import parse_akto_json_message

        async for batch in self.consumer:
            for msg in batch:
                try:
                    # JSON → raw_log dict
                    raw_log = parse_akto_json_message(msg.value.decode('utf-8'))
                    await self.process_log(raw_log)
                except Exception as e:
                    # 反序列化失败 → DLQ
                    dlq_payload = {
                        "trace_id": None,
                        "error": f"Processing failed: {e}",
                        "error_type": type(e).__name__,
                        "raw_log": msg.value.hex(),
                        "topic": msg.topic,
                        "partition": msg.partition,
                        "offset": msg.offset,
                    }
                    await self.producer.send_and_wait(
                        self.settings.dlq_topic,
                        orjson.dumps(dlq_payload)
                    )
                    METRIC_DLQ_OUT.inc()

            # 手动提交 offset
            await self.consumer.commit()
```

### 3.3 Settings 扩展

```python
class Settings:
    # Redis
    redis_cluster_url: str

    # Kafka
    kafka_brokers: str
    input_topic: str = "akto.api.logs"           # 新增
    alert_topic: str = "akto.aiwaf.alerts"        # 改默认值
    dlq_topic: str = "akto.aiwaf.dlq"             # 改默认值
    consumer_group: str = "aiwaf-consumer-group"  # 新增

    # 进程池
    core_process_pool_size: int
```

**环境变量对应新增：**

| 变量 | 默认值 | 说明 |
|---|---|---|
| `KAFKA_INPUT_TOPIC` | `akto.api.logs` | 消费 Topic |
| `KAFKA_ALERT_TOPIC` | `akto.aiwaf.alerts` | 告警 Topic |
| `KAFKA_DLQ_TOPIC` | `akto.aiwaf.dlq` | 死信 Topic |
| `KAFKA_CONSUMER_GROUP` | `aiwaf-consumer-group` | Consumer Group ID |

### 3.4 告警输出格式增强

```python
async def _emit_alert(self, std_log: dict, rule: str):
    alert = {
        # 现有字段
        "trace_id": std_log.get("trace_id"),
        "rule_id": rule,
        "alert_timestamp": std_log.get("timestamp"),
        "client_ip": std_log.get("client_ip"),

        # 新增：akto 上下文（便于 akto 侧关联分析）
        "akto_account_id": std_log.get("akto_account_id", ""),
        "akto_vxlan_id": std_log.get("akto_vxlan_id", ""),
        "source": std_log.get("source", ""),
        "direction": std_log.get("direction", ""),

        # 新增：请求上下文
        "method": std_log.get("method", "GET"),
        "uri_path": std_log.get("uri_path", "/"),
        "status_code": std_log.get("status_code", 200),

        # 新增：检测元数据
        "detected_at": time.time(),
        "severity": self._classify_severity(rule),
        "req_body_truncated": std_log.get("req_body_truncated", ""),
    }
    await self.producer.send_and_wait(
        self.settings.alert_topic,  # → "akto.aiwaf.alerts"
        orjson.dumps(alert)
    )
```

### 3.5 requirements.txt

无需新增依赖 — JSON 解析用 Python 内置 `json` 模块，`urllib.parse` 也是内置。无需 Protobuf。

---

## 4. 兼容性验证方案

### 4.1 单元测试（最小可行验证）

```python
# tests/test_akto_adapter.py
import json
from preprocessor import transform_raw_log
from akto_adapter import parse_akto_json_message

def test_field_mapping():
    """验证 Akto JSON → adapt → transform_raw_log 不崩溃，字段完整"""
    akto_msg = {
        "path": "/api/users/123?name=alice&age=30",
        "method": "GET",
        "requestHeaders": '{"host": "api.example.com"}',
        "responseHeaders": '{"content-type": "application/json"}',
        "requestPayload": "",
        "responsePayload": '{"id": 123}',
        "ip": "10.0.1.5",
        "destIp": "10.0.2.10",
        "time": "1719500000",
        "statusCode": "200",
        "status": "OK",
        "akto_account_id": "1000000",
        "akto_vxlan_id": "1",
        "source": "MIRRORING",
        "direction": "REQUEST_RESPONSE",
    }

    # 步骤 1: 适配层转换
    raw_log = parse_akto_json_message(json.dumps(akto_msg))

    # 验证适配层输出符合 transform_raw_log 的输入预期
    assert raw_log["client_ip"] == "10.0.1.5"
    assert raw_log["uri_path"] == "/api/users/123"
    assert raw_log["method"] == "GET"
    assert raw_log["status"] == 200              # 必须是 int
    assert raw_log["timestamp"] == 1719500000.0  # 必须是 float
    assert raw_log["query_params"] == {"name": "alice", "age": "30"}
    assert raw_log["request_body"] == ""

    # 步骤 2: transform_raw_log 转换
    std_log = transform_raw_log(raw_log)

    # 验证 std_log 字段完整性
    assert std_log["client_ip"] == "10.0.1.5"
    assert std_log["uri_path"] == "/api/users/123"
    assert std_log["method"] == "GET"
    assert std_log["status_code"] == 200
    assert std_log["timestamp"] == 1719500000.0
    assert std_log["trace_id"]                   # 非空
    assert len(std_log["trace_id"]) == 32        # MD5 截断
    assert std_log["query_keys"] == ["name", "age"]
    assert std_log["query_strings"] == ["name=alice", "age=30"]
    assert "request_body" not in std_log         # 已被 del
    assert std_log["req_body_truncated"] == ""

    # 步骤 3: 验证 core logic 不崩溃（最关键）
    from acl_bootstrap import run_core_logic_batch_isolated
    import orjson
    result = run_core_logic_batch_isolated(
        batch_logs_json=[orjson.dumps(std_log)],
        batch_timestamps=[[1719500000.0]],
        batch_event_times=[1719500000.0],
        dynamic_kws=[],
    )
    assert len(result) == 1
    # 不论是 SuccessResult 还是 ErrorResult，不崩溃即通过

def test_empty_path():
    """空 path 不崩溃"""
    akto_msg = {"path": "", "method": "GET", "ip": "1.2.3.4",
                "statusCode": "200", "time": "0"}
    raw_log = parse_akto_json_message(json.dumps(akto_msg))
    std_log = transform_raw_log(raw_log)
    assert std_log["uri_path"] == "/"

def test_no_query_string():
    """无 query string 的 path"""
    akto_msg = {"path": "/api/health", "method": "GET", "ip": "1.2.3.4",
                "statusCode": "200", "time": "1719500000"}
    raw_log = parse_akto_json_message(json.dumps(akto_msg))
    assert raw_log["query_params"] == {}
    std_log = transform_raw_log(raw_log)
    assert std_log["query_keys"] == []

def test_string_statuscode():
    """Akto 的 statusCode 是 String 类型，必须转 int"""
    akto_msg = {"path": "/", "method": "GET", "ip": "1.2.3.4",
                "statusCode": "404", "time": "0"}
    raw_log = parse_akto_json_message(json.dumps(akto_msg))
    assert raw_log["status"] == 404  # 必须是 int，不是 "404"

def test_string_time():
    """Akto 的 time 是 String 类型，必须转 float"""
    akto_msg = {"path": "/", "method": "GET", "ip": "1.2.3.4",
                "statusCode": "200", "time": "1719500000"}
    raw_log = parse_akto_json_message(json.dumps(akto_msg))
    assert isinstance(raw_log["timestamp"], float)
    assert raw_log["timestamp"] == 1719500000.0

def test_missing_fields():
    """缺少字段时不崩溃"""
    akto_msg = {}
    raw_log = parse_akto_json_message(json.dumps(akto_msg))
    assert raw_log["client_ip"] == "unknown"
    assert raw_log["uri_path"] == "/"
    assert raw_log["method"] == "GET"
    assert raw_log["status"] == 200
    assert raw_log["timestamp"] == 0.0
    assert raw_log["request_body"] == ""
    # transform_raw_log 也不崩溃
    std_log = transform_raw_log(raw_log)
    assert std_log["trace_id"]  # 仍能生成

def test_full_url_path():
    """path 字段含完整 URL"""
    akto_msg = {"path": "https://api.example.com/users?id=42",
                "method": "GET", "ip": "1.2.3.4",
                "statusCode": "200", "time": "0"}
    raw_log = parse_akto_json_message(json.dumps(akto_msg))
    assert raw_log["uri_path"] == "/users"
    assert raw_log["query_params"] == {"id": "42"}
```

### 4.2 核心字段验证矩阵

| 检查项 | 验证方法 | 期望结果 |
|---|---|---|
| `uri_path` 被 `std_log["uri_path"]` 直接索引 | 适配层确保始终输出非 None 值 | ✅ 默认 "/" |
| `query_params` 用 `.get("query_params", {})` | 空字典时不崩溃 | ✅ 默认 {} |
| `timestamp` 传入 `get_and_update_rate_limit` | 必须是 float/int | ✅ 适配层 `float(time)` |
| `client_ip` 用 `.get("client_ip", "unknown")` | None 时降级 | ✅ 默认 "unknown" |
| `trace_id` 由 `generate_deterministic_trace_id` 生成 | 需 `client_ip`/`uri_path`/`timestamp`/`request_body` | ✅ 全部提供 |
| `request_body` 被 `del` 删除 | transform_raw_log 后不存在 | ✅ 适配层提供初始值 |
| `status` 读取为 `raw_log.get("status", 200)` | 必须是 int | ✅ 适配层 `int(statusCode)` |

### 4.3 端到端 Kafka 消费验证

```python
# verify_akto_logs.py — 手动验证脚本
# 从真实 Kafka 消费 10 条消息，走完整个管道
import asyncio, json
from aiokafka import AIOKafkaConsumer
from akto_adapter import parse_akto_json_message
from preprocessor import transform_raw_log

async def verify():
    consumer = AIOKafkaConsumer(
        "akto.api.logs",
        bootstrap_servers="localhost:29092",
        group_id="aiwaf-verify",
        auto_offset_reset="latest",
    )
    await consumer.start()
    count = 0
    ok = 0
    fail = 0
    async for msg in consumer:
        try:
            raw_log = parse_akto_json_message(msg.value.decode('utf-8'))
            std_log = transform_raw_log(raw_log)
            print(f"[OK] trace_id={std_log['trace_id'][:8]} "
                  f"ip={std_log['client_ip']} path={std_log['uri_path']}")
            ok += 1
        except Exception as e:
            print(f"[FAIL] {e} | raw={msg.value[:200]}")
            fail += 1
        count += 1
        if count >= 10:
            break
    print(f"\nResult: {ok} ok, {fail} fail out of {count}")
    await consumer.stop()

asyncio.run(verify())
```

---

## 5. 改造清单

| # | 文件 | 改动 | 优先级 | 工作量 |
|---|---|---|---|---|
| 1 | 新增 `akto_adapter.py` | JSON 反序列化 + 字段映射 + 类型转换 | P0 | 1h |
| 2 | `engine.py` | 新增 AIOKafkaConsumer + `_consume_loop()` | P0 | 2h |
| 3 | `engine.py` | `_emit_alert()` 字段丰富 | P1 | 1h |
| 4 | Settings / 环境变量 | `input_topic`, `consumer_group` 等 | P0 | 30min |
| 5 | 新增 `tests/test_akto_adapter.py` | 适配层单测（7 个用例） | P0 | 1.5h |
| 6 | 新增 `tests/test_consume_loop.py` | 消费循环集成测试 | P1 | 1.5h |
| 7 | `verify_akto_logs.py` | 端到端验证脚本 | P0 | 30min |
| 8 | `requirements.txt` | 无需改动（JSON 用内置库） | — | 0 |
| **合计** | | | | **~8h** |

> 对比原方案（13h），删除了 Protobuf 编译（-2.5h）、proto stub 生成（-30min）、protobuf 依赖（-5min），减少了约 5h 工作量。

---

## 6. 风险与缓解

| 风险 | 影响 | 缓解措施 |
|---|---|---|
| Consumer Group 冲突 | 如果 aiwaf 和其他消费者用同一 group ID，会互相抢消息 | group ID 独立设置为 `aiwaf-consumer-group` |
| `path` 字段格式不确定 | 可能是纯路径 `/api/v1`，也可能含完整 URL `https://host/api/v1?foo=bar` | `urlparse` 兼容两种，单测覆盖 |
| 大 payload | `requestPayload` 可能很大（文件上传），JSON 解析可能 OOM | AIWAF 已有 `MAX_BODY_HASH_BYTES=10MB` 截断 |
| offset 管理 | 手动 commit 失败导致重复消费 | AIWAF 有 SETNX 幂等去重，可承受重复 |
| `statusCode` 非数字 | Akto 数据可能含 `"NaN"` 或空字符串 | 适配层 try/except 降级为 200 |
| `time` 缺失或非数字 | 限频窗口计算错误 | 适配层 try/except 降级为 0.0 |
| `uri_path` 为 None | `run_core_logic_batch_isolated` 直接索引 KeyError | 适配层默认 "/" |

---

## 7. 数据流总结

```
Akto data-ingestion-service
  │
  │ Kafka: akto.api.logs (JSON, 所有字段为 String)
  │
  ▼
AIWAF Consumer (新增)
  │
  ├── akto_adapter.parse_akto_json_message()
  │   ├── json.loads(raw_json)
  │   ├── urlparse(path) → 拆分 path + query
  │   ├── int(statusCode) → status
  │   ├── float(time) → timestamp
  │   └── 输出 raw_log dict (7 个核心字段 + 6 个扩展字段)
  │
  ├── preprocessor.transform_raw_log(raw_log)
  │   ├── generate_deterministic_trace_id(client_ip, uri_path, timestamp, request_body)
  │   ├── 拆分 query_params → query_keys + query_strings
  │   ├── 截断 request_body → req_body_truncated
  │   ├── del request_body
  │   └── 输出 std_log dict
  │
  ├── engine.process_log(std_log)
  │   ├── Redis 速率限制 (client_ip + uri_path)
  │   ├── 关键词策略检测 (uri_path + query_keys + method)
  │   └── 触发告警 / 放行
  │
  └── Kafka: akto.aiwaf.alerts (JSON)
      {
        "trace_id", "rule_id", "alert_timestamp", "client_ip",
        "akto_account_id", "akto_vxlan_id", "source", "direction",
        "method", "uri_path", "status_code",
        "detected_at", "severity", "req_body_truncated"
      }
```
