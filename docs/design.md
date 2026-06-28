# AIWAF-Stream 设计文档

> 版本: 2.0 | 最后更新: 2026-06-28

---

## 1. 项目概述

AIWAF-Stream 是一个**异步流式 Web 应用防火墙引擎**，从 Kafka 消费 Akto API 流量数据，经 16 项检测能力处理后输出告警。

核心特性：

- **Kafka 流式消费**：从 `akto.api.logs` Topic 消费 Akto 流量 JSON
- **16 项检测能力**：关键词 + 速率限制 + AI 异常检测 + 请求头验证 + UUID 篡改 + 地理围栏 + 蜜罐 + 路径清单 + Fail-Secure 降级 + 熔断器 + 双缓冲写回 + 子进程隔离 + 关键词自学习
- **79 项可配置**：YAML + 环境变量 + Redis 运行时覆盖（25 项可覆盖）
- **427 测试用例**：100% 通过率

---

## 2. 目录结构

```
aiwaf/
  core/               ← 检测策略库（22 模块，纯逻辑，可复用）
    ip_keyword.py        关键词策略 + 自学习
    malicious_context.py 恶意上下文判定（6 指标）
    path_manifest.py      路径清单（从流量自动构建）
    header_validation.py  请求头验证
    anomaly.py            AI 异常检测（IsolationForest）
    stream_trainer.py     批量训练器
    rate_limit.py         速率限制判定
    uuid_tamper.py        UUID 篡改检测
    honeypot.py           蜜罐时序检测
    method_validation.py  HTTP 方法验证
    geo_policy.py         地理围栏策略
    geoip.py              GeoIP 查询
    exemptions.py         路径豁免
    ...
  stream/              ← 流式运行时框架（8 模块）
    engine.py            主引擎：Kafka 消费 + 检测编排
    redis_facade.py      Redis 状态管理 + Fail-Secure 降级
    acl_bootstrap.py     子进程隔离层
    akto_adapter.py      Akto JSON 适配层
    preprocessor.py      预处理：trace_id + query + body 截断
    config.py            配置加载（YAML + 环境变量）
    config_override.py   Redis 运行时配置覆盖
    asyncbreaker.py      熔断器封装
scripts/
  verify_akto_logs.py   ← 端到端验证脚本
tests/                  ← 427 测试用例
docs/                   ← 文档
```

---

## 3. 架构总览

```
Kafka: akto.api.logs (JSON)
  │
  ├─ akto_adapter.parse_akto_json_message()
  │    JSON → raw_log dict (7 核心 + 8 扩展字段)
  │
  ├─ preprocessor.transform_raw_log()
  │    生成 trace_id + 拆分 query + 截断 body + 透传扩展字段
  │
  ├─ engine.process_log()
  │    ├── PathManifest.record()
  │    ├── 请求头验证 (evaluate_header_policy)
  │    ├── 路径豁免检查
  │    ├── UUID 篡改检测
  │    ├── 地理围栏 (GeoIP)
  │    ├── Redis 去重 (SETNX)
  │    ├── Redis 速率限制 (ZSET)
  │    └── → 微批处理 → ProcessPoolExecutor
  │         ├── 速率限制判定 (evaluate_rate_limit)
  │         ├── 关键词策略 (evaluate_keyword_policy)
  │         │   ├── 探测路径检测 (PROBE_PATH_PATTERNS)
  │         │   ├── 学习关键词匹配 (dynamic_keywords)
  │         │   └── 固有恶意模式 (INHERENTLY_MALICIOUS_PATTERNS)
  │         └── 关键词自学习 (is_malicious_context)
  │
  ├─ Fail-Secure 降级（Redis 不可用时）
  │    ├── 本地黑名单检查
  │    ├── 本地速率限制计数
  │    └── 双缓冲写回
  │
  └─ Kafka: akto.aiwaf.alerts (JSON, 14 字段)
      Kafka: akto.aiwaf.dlq (异常死信)
```

---

## 4. 数据流

### 4.1 请求处理生命周期

```
Kafka 消息 → akto_adapter → preprocessor → process_log
  │
  ├── 1. PathManifest.record(uri_path, method, status_code)
  ├── 2. 请求头验证 → 命中? → HeaderBlock 告警 + return
  ├── 3. 路径豁免检查 → 命中? → return（跳过所有检测）
  ├── 4. UUID 篡改检测 → 命中? → UUIDTamper 告警
  ├── 5. 地理围栏 → 命中? → GeoBlock 告警 + return
  ├── 6. Redis 去重 (SETNX, 24h TTL) → 重复? → return
  ├── 7. Redis 速率限制 (ZSET 滑动窗口)
  │      ├── Redis 不可用 (CircuitBreaker) → Fail-Secure 降级
  │      │   ├── 本地黑名单检查 → 命中? → Local_Blacklist_Block 告警
  │      │   └── 本地速率计数 > limit → Local_RateLimit_Block 告警
  │      └── Redis 正常 → 继续检测
  └── 8. batch_queue → _batch_dispatcher → ProcessPoolExecutor
       ├── evaluate_rate_limit → FLOOD_BLOCK? → RateLimitFlood 告警
       ├── evaluate_keyword_policy
       │   ├── PROBE_PATH_PATTERNS 匹配 → KeywordBlock 告警
       │   ├── dynamic_keywords 匹配 → KeywordBlock 告警
       │   └── INHERENTLY_MALICIOUS_PATTERNS → KeywordBlock 告警
       ├── is_malicious_context → learned_keywords → Redis 写入
       └── side_effects → batch_block_ips + batch_add_keywords
```

### 4.2 trace_id 生成算法

```
trace_id = SHA256( client_ip | uri_path | MD5(request_body_bytes) | timestamp )[:32]

截断策略:
- request_body ≥ max_body_hash_bytes (默认 10MB) → 截断后 MD5
- request_body 存储 → 截断前 max_body_store_bytes (默认 1KB)
- dict/list 类型 body → orjson.dumps() 序列化后 hash
```

### 4.3 双缓冲写回机制

```
Fail-Secure 拉黑 IP → _backup_buffer.append(ip)
                              │
background_sync_worker (每 background_sync_interval 秒, 默认 5s):
  _current_buffer ⇄ _backup_buffer  (原子交换)
  ips_to_sync = list(_backup_buffer)
  batch_block_ips(ips_to_sync) → Redis
  同步成功 → _backup_buffer.clear()
  同步失败 → 数据保留在 _backup_buffer，下次重试
  
溢出保护: len(_backup_buffer) ≥ max_pending_ips (默认 10000) → METRIC_PENDING_OVERFLOW++
```

---

## 5. 告警输出

### 5.1 告警 Topic (`akto.aiwaf.alerts`)

14 字段 JSON：

```json
{
  "trace_id": "a1b2c3d4...",
  "rule_id": "KeywordBlock:Keyword block: Inherently suspicious: probe path",
  "alert_timestamp": 1719500000.0,
  "client_ip": "10.0.1.5",
  "akto_account_id": "1000000",
  "akto_vxlan_id": "1",
  "source": "MIRRORING",
  "direction": "REQUEST",
  "method": "GET",
  "uri_path": "/.env",
  "status_code": 404,
  "detected_at": 1719500005.123,
  "severity": "HIGH",
  "req_body_truncated": ""
}
```

### 5.2 死信 Topic (`akto.aiwaf.dlq`)

```json
{
  "trace_id": "...",
  "error": "Processing failed: ...",
  "error_type": "ValueError",
  "raw_log": { ... }
}
```

---

## 6. 配置体系

### 三级优先级

```
环境变量 (最高) > YAML 配置文件 > 内置默认值 (最低)
```

### Redis 运行时覆盖（25 项检测参数）

```bash
redis-cli SET aiwaf:config:rate_limit_max_requests 200
redis-cli SET aiwaf:config:auto_block_enabled false
redis-cli DEL aiwaf:config:rate_limit_max_requests  # 恢复默认
```

10 秒本地缓存，Redis 不可用时降级到 YAML/默认值。

详见 `config.example.yaml`（79 项配置）。

---

## 7. 安全设计原则

1. **零信任指纹**：trace_id = SHA256(IP + URI + MD5(Body) + Timestamp)，客户端不可伪造
2. **SETNX 绝对幂等**：相同 trace_id 的请求只处理一次（`dedup_ttl` 默认 24h）
3. **Fail-Secure**：Redis 不可用时不丢检测能力，本地缓存 + 熔断器承担防线
4. **子进程隔离**：核心逻辑 crash 不影响主进程事件循环
5. **人工审核模式**：`auto_block_enabled=false` 时只告警不拉黑
6. **白名单机制**：合法关键词白名单防止误封正常流量

---

## 8. 可观测性

| Metric | 类型 | 含义 |
|--------|------|------|
| `aiwaf_engine_in_total` | Counter | 接收日志数 |
| `aiwaf_dlq_out_total` | Counter | DLQ 路由数 |
| `aiwaf_pool_fatal_total` | Counter | ProcessPool 重建次数 |
| `aiwaf_pending_overflow_total` | Counter | 双缓冲溢出次数 |

---

## 9. 相关文档

- [检测能力详解](detection_capabilities.md)
- [检测模式实现机制与配置方式](detection_implementation.md)
- [部署与配置](deployment.md)
- [使用手册](usage.md)
- [测试文档](testing.md)
- [排障指南](troubleshooting.md)
- [开发文档](development.md)
