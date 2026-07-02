# AIWAF-Stream 使用手册

> 版本: 2.0 | 最后更新: 2026-06-28

---

## 1. 快速开始

### 1.1 最小配置

```yaml
# config.yaml
redis_cluster_url: "redis://localhost:6379"
kafka_brokers: "localhost:9092"
```

### 1.2 启动引擎

```python
import asyncio
from aiwaf.stream.config import Settings
from aiwaf.stream.redis_facade import RedisClusterStateManager
from aiwaf.stream.engine import AIWAFStreamEngine

async def main():
    settings = Settings.from_env()
    state_mgr = RedisClusterStateManager(
        settings.redis_cluster_url,
        settings.dedup_ttl,
        settings.blacklist_ttl,
    )
    engine = AIWAFStreamEngine(settings, state_mgr, "/path/to/model.pkl")
    await engine.run()

asyncio.run(main())
```

---

## 2. 输入格式

### 2.1 Akto Kafka 消息（`akto.api.logs`）

```json
{
  "path": "/api/users/123?name=alice",
  "method": "GET",
  "requestHeaders": "{\"user-agent\":\"Mozilla/5.0\",\"accept\":\"text/html\"}",
  "responseHeaders": "{\"content-type\":\"application/json\"}",
  "requestPayload": "",
  "responsePayload": "{\"id\":123}",
  "ip": "10.0.1.5",
  "destIp": "10.0.2.10",
  "time": "1719500000",
  "statusCode": "200",
  "status": "OK",
  "akto_account_id": "1000000",
  "akto_vxlan_id": "1",
  "source": "MIRRORING",
  "direction": "REQUEST"
}
```

### 2.2 字段映射（`akto_adapter.py`）

| Akto 字段 | 内部字段 | 类型转换 |
|---|---|---|
| `path` | `uri_path` + `query_params` | urlparse 拆分 |
| `method` | `method` | 无 |
| `ip` | `client_ip` | 无 |
| `statusCode` | `status` | String → int |
| `time` | `timestamp` | String → float |
| `requestPayload` | `request_body` | 无 |
| `requestHeaders` | `request_headers` | 无（透传 JSON string） |
| `akto_account_id` | `akto_account_id` | 无 |
| `akto_vxlan_id` | `akto_vxlan_id` | 无 |
| `source` | `source` | 无 |
| `direction` | `direction` | 无 |
| `destIp` | `dest_ip` | 无 |
| `responsePayload` | `response_payload` | 无 |

---

## 3. 输出格式

### 3.1 告警（`akto.aiwaf.alerts`）

14 字段 JSON：

| 字段 | 类型 | 说明 |
|---|---|---|
| `trace_id` | str | SHA256 指纹（32 字符） |
| `rule_id` | str | 触发的规则名 |
| `alert_timestamp` | float | 原始请求时间戳 |
| `client_ip` | str | 请求来源 IP |
| `akto_account_id` | str | Akto 账户 ID |
| `akto_vxlan_id` | str | Akto VXLAN ID |
| `source` | str | 流量来源 |
| `direction` | str | 流量方向 |
| `method` | str | HTTP 方法 |
| `uri_path` | str | 请求路径 |
| `status_code` | int | HTTP 状态码 |
| `detected_at` | float | 检测时间戳 |
| `severity` | str | HIGH/MEDIUM/LOW |
| `req_body_truncated` | str | 请求体前 1KB |

### 3.2 死信（`akto.aiwaf.dlq`）

```json
{
  "trace_id": "...",
  "error": "Processing failed: ...",
  "error_type": "ValueError",
  "raw_log": { ... }
}
```

---

## 4. 检测规则

| Rule ID | Severity | 触发条件 |
|---|---|---|
| `Local_Blacklist_Block` | HIGH | Redis 不可用时 IP 在本地黑名单 |
| `Local_RateLimit_Block` | HIGH | Redis 不可用时本地速率超限 |
| `RateLimitFlood` | MEDIUM | Redis 速率限制检测到洪泛 |
| `KeywordBlock:...probe path` | HIGH | URL 匹配探测路径正则 |
| `KeywordBlock:...Learned keyword` | HIGH | URL 段匹配自学习关键词 |
| `KeywordBlock:...Inherently suspicious` | HIGH | URL 段匹配固有恶意模式 |
| `HeaderBlock:{reason}` | HIGH | 请求头异常 |
| `UUIDTamper:malformed_uuid` | HIGH | UUID 格式篡改 |
| `GeoBlock:{country}` | MEDIUM | 地理围栏拦截 |

---

## 5. 运行时管理

### 5.1 IP 黑名单

```bash
# 查看
redis-cli KEYS "aiwaf:blk:*"
redis-cli GET aiwaf:blk:10.0.1.5

# 解封
redis-cli DEL aiwaf:blk:10.0.1.5
```

### 5.2 关键词库

```bash
# 查看 Top 10
redis-cli ZREVRANGE aiwaf:keywords 0 9 WITHSCORES

# 删除误判关键词
redis-cli ZREM aiwaf:keywords shell
```

### 5.3 豁免路径

```bash
# 添加
redis-cli SADD aiwaf:exempt:paths "/api/health"

# 移除
redis-cli SREM aiwaf:exempt:paths "/api/health"

# 查看全部
redis-cli SMEMBERS aiwaf:exempt:paths
```

### 5.4 运行时配置覆盖

```bash
# 调整速率限制
redis-cli SET aiwaf:config:rate_limit_max_requests 200

# 切换人工审核模式
redis-cli SET aiwaf:config:auto_block_enabled false

# 豁免内网 IP
redis-cli SET aiwaf:config:header_skip_ips "192.168.0.0/16"

# 恢复默认
redis-cli DEL aiwaf:config:rate_limit_max_requests
```

### 5.5 查看告警

```bash
kafka-console-consumer --bootstrap-server localhost:9092 \
  --topic akto.aiwaf.alerts --from-beginning
```

---

## 6. 常用场景配置

### 6.1 内网 API 场景（跳过请求头检查）

```yaml
header_required: ""
header_skip_ips: "192.168.0.0/16,10.0.0.0/8"
```

### 6.2 人工审核模式（只告警不拉黑）

```yaml
auto_block_enabled: false
auto_learn_keywords: false
```

### 6.3 地理围栏（只允许中国访问）

```yaml
geoip_db_path: "/data/geoip2/GeoLite2-Country.mmdb"
geo_allow_countries: "CN"
```

### 6.4 高安全模式（严格速率限制）

```yaml
rate_limit_window: 30
rate_limit_max_requests: 50
rate_limit_flood_threshold: 80
fail_secure_local_limit: 20
```

---

## 7. 验证脚本

```bash
KAFKA_BROKERS=localhost:9092 python scripts/verify_akto_logs.py
```

从真实 Kafka 消费 10 条消息，走完整个管道，打印结果。

---

## 8. 相关文档

- [检测能力详解](detection_capabilities.md)
- [检测模式实现机制](detection_implementation.md)
- [部署与配置](deployment.md)
- [设计文档](design.md)
