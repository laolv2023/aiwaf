# AIWAF-Stream 部署与配置文档

> 版本: 2.0 | 最后更新: 2026-06-28

---

## 1. 环境依赖

### 1.1 运行时依赖

| 包名 | 版本要求 | 用途 |
|------|---------|------|
| Python | ≥3.12 | asyncio.timeout, match-case |
| orjson | ≥3.9 | 高性能 JSON 序列化 |
| redis | ≥5.0 | Redis 异步客户端 |
| aiokafka | ≥0.8 | Kafka 异步生产者/消费者 |
| cachetools | ≥5.0 | 本地 TTL 缓存 (Fail-Secure) |
| prometheus-client | ≥0.17 | 指标暴露 |
| joblib | ≥1.3 | ML 模型加载（子进程） |
| pyyaml | ≥6.0 | YAML 配置文件解析 |
| asyncbreaker | — | 异步熔断器 |

### 1.2 可选依赖（AI 异常检测）

| 包名 | 版本要求 | 用途 |
|------|---------|------|
| numpy | ≥1.24 | 数值计算 |
| pandas | ≥2.0 | 特征 DataFrame |
| scikit-learn | ≥1.3 | IsolationForest 训练/预测 |

### 1.3 外部服务

| 服务 | 要求 | 用途 |
|------|------|------|
| Redis | ≥6.0 | 去重、限流、黑名单、关键词、配置覆盖 |
| Kafka | ≥2.8 | 消费 Akto 流量 + 告警输出 + DLQ |
| MaxMind GeoIP2 DB | 可选 | 地理围栏（`geoip_db_path` 为空则禁用） |

---

## 2. 安装部署

### 2.1 安装

```bash
git clone https://github.com/laolv2023/aiwaf.git
cd aiwaf
python3.12 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2.2 配置

```bash
# 复制配置模板
cp config.example.yaml config.yaml

# 编辑配置
vim config.yaml
```

或通过环境变量配置：

```bash
export KAFKA_BROKERS=localhost:9092
export REDIS_CLUSTER_URL=redis://localhost:6379
export KAFKA_INPUT_TOPIC=akto.api.logs
export KAFKA_ALERT_TOPIC=akto.aiwaf.alerts
export KAFKA_DLQ_TOPIC=akto.aiwaf.dlq
```

### 2.3 启动

```python
import asyncio
from aiwaf.stream.config import Settings
from aiwaf.stream.redis_facade import RedisClusterStateManager
from aiwaf.stream.engine import AIWAFStreamEngine

async def main():
    settings = Settings.from_env()
    state_mgr = RedisClusterStateManager(
        settings.redis_cluster_url,
        dedup_ttl=settings.dedup_ttl,
        blacklist_ttl=settings.blacklist_ttl,
    )
    engine = AIWAFStreamEngine(settings, state_mgr, "/path/to/model.pkl")
    await engine.start()
    await asyncio.Event().wait()

asyncio.run(main())
```

### 2.4 Docker 部署

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
CMD ["python", "-c", "import asyncio; from aiwaf.stream.config import Settings; from aiwaf.stream.redis_facade import RedisClusterStateManager; from aiwaf.stream.engine import AIWAFStreamEngine; s=Settings.from_env(); m=RedisClusterStateManager(s.redis_cluster_url, s.dedup_ttl, s.blacklist_ttl); e=AIWAFStreamEngine(s,m,'/app/model.pkl'); asyncio.run(e.start())"]
```

---

## 3. 配置项详解（72 项）

### 3.1 Redis

| YAML 字段 | 环境变量 | 默认值 | 说明 |
|---|---|---|---|
| `redis_cluster_url` | `REDIS_CLUSTER_URL` | `redis://localhost:6379` | Redis 连接 URL |

### 3.2 Kafka 连接

| YAML 字段 | 环境变量 | 默认值 | 说明 |
|---|---|---|---|
| `kafka_brokers` | `KAFKA_BROKERS` | `localhost:9092` | Kafka broker 地址 |
| `input_topic` | `KAFKA_INPUT_TOPIC` | `akto.api.logs` | 消费 Topic |
| `alert_topic` | `KAFKA_ALERT_TOPIC` | `akto.aiwaf.alerts` | 告警 Topic |
| `dlq_topic` | `KAFKA_DLQ_TOPIC` | `akto.aiwaf.dlq` | 死信 Topic |
| `consumer_group` | `KAFKA_CONSUMER_GROUP` | `aiwaf-consumer-group` | Consumer Group ID |

### 3.3 Kafka Producer/Consumer 参数

| YAML 字段 | 环境变量 | 默认值 | 说明 |
|---|---|---|---|
| `kafka_enable_idempotence` | `KAFKA_ENABLE_IDEMPOTENCE` | `true` | 幂等生产者 |
| `kafka_acks` | `KAFKA_ACKS` | `all` | 确认级别 |
| `kafka_auto_offset_reset` | `KAFKA_AUTO_OFFSET_RESET` | `earliest` | 无偏移时行为 |
| `kafka_max_poll_records` | `KAFKA_MAX_POLL_RECORDS` | `500` | 单次拉取最大记录数 |

### 3.4 进程池

| YAML 字段 | 环境变量 | 默认值 | 说明 |
|---|---|---|---|
| `core_process_pool_size` | `CORE_PROCESS_POOL_SIZE` | `4` | 子进程池大小 |
| `max_tasks_per_child` | `MAX_TASKS_PER_CHILD` | `200` | 子进程最大任务数 |

### 3.5 速率限制

| YAML 字段 | 环境变量 | 默认值 | Redis 覆盖 | 说明 |
|---|---|---|---|---|
| `rate_limit_window` | `RATE_LIMIT_WINDOW` | `60` | ✅ | 窗口大小（秒） |
| `rate_limit_max_requests` | `RATE_LIMIT_MAX_REQUESTS` | `100` | ✅ | 窗口内最大请求数 |
| `rate_limit_flood_threshold` | `RATE_LIMIT_FLOOD_THRESHOLD` | `150` | ✅ | 洪泛检测阈值 |
| `fail_secure_local_limit` | `FAIL_SECURE_LOCAL_LIMIT` | `50` | ✅ | Redis 不可用时本地阈值 |

### 3.6 请求头验证

| YAML 字段 | 环境变量 | 默认值 | Redis 覆盖 | 说明 |
|---|---|---|---|---|
| `header_required` | `HEADER_REQUIRED` | `user-agent,accept` | ✅ | 必需头（空=不检查） |
| `header_skip_ips` | `HEADER_SKIP_IPS` | `` | ✅ | 豁免 IP/CIDR |
| `header_skip_paths` | `HEADER_SKIP_PATHS` | `` | ✅ | 豁免路径前缀 |
| `header_max_ua_length` | `HEADER_MAX_UA_LENGTH` | `500` | ✅ | UA 最大长度 |
| `header_max_accept_length` | `HEADER_MAX_ACCEPT_LENGTH` | `4096` | ✅ | Accept 最大长度 |
| `header_suspicious_ua` | `HEADER_SUSPICIOUS_UA` | `` | ✅ | 自定义可疑 UA |
| `header_legitimate_bots` | `HEADER_LEGITIMATE_BOTS` | `` | ✅ | 合法爬虫 UA |

### 3.7 地理围栏

| YAML 字段 | 环境变量 | 默认值 | Redis 覆盖 | 说明 |
|---|---|---|---|---|
| `geoip_db_path` | `GEOIP_DB_PATH` | `` | ❌ | MaxMind DB 路径（空=禁用） |
| `geo_block_countries` | `GEO_BLOCK_COUNTRIES` | `` | ✅ | 阻止国家 |
| `geo_allow_countries` | `GEO_ALLOW_COUNTRIES` | `` | ✅ | 允许国家 |

### 3.8 AI 异常检测

| YAML 字段 | 环境变量 | 默认值 | Redis 覆盖 | 说明 |
|---|---|---|---|---|
| `ai_min_logs` | `AI_MIN_LOGS` | `50` | ✅ | 最小训练样本数 |
| `ai_contamination` | `AI_CONTAMINATION` | `0.05` | ✅ | IsolationForest 污染率 |
| `ai_n_estimators` | `AI_N_ESTIMATORS` | `100` | ✅ | 树数 |
| `ai_max_samples` | `AI_MAX_SAMPLES` | `auto` | ❌ | 最大样本数 |

### 3.9 人工审核模式

| YAML 字段 | 环境变量 | 默认值 | Redis 覆盖 | 说明 |
|---|---|---|---|---|
| `auto_block_enabled` | `AUTO_BLOCK_ENABLED` | `true` | ✅ | 自动拉黑（false=只告警） |
| `auto_learn_keywords` | `AUTO_LEARN_KEYWORDS` | `true` | ✅ | 自动学习关键词 |

### 3.10 其他参数

| YAML 字段 | 环境变量 | 默认值 | 说明 |
|---|---|---|---|
| `batch_max_size` | `BATCH_MAX_SIZE` | `50` | 每批最大消息数 |
| `batch_timeout_ms` | `BATCH_TIMEOUT_MS` | `10` | 批处理超时（ms） |
| `batch_queue_maxsize` | `BATCH_QUEUE_MAXSIZE` | `10000` | 队列最大长度 |
| `keyword_refresh_interval` | `KEYWORD_REFRESH_INTERVAL` | `10` | 关键词刷新间隔（秒） |
| `keyword_top_n` | `KEYWORD_TOP_N` | `500` | Top N 关键词数 |
| `dedup_ttl` | `DEDUP_TTL` | `86400` | 去重 TTL（秒） |
| `blacklist_ttl` | `BLACKLIST_TTL` | `3600` | 黑名单 TTL（秒） |
| `local_blacklist_ttl` | `LOCAL_BLACKLIST_TTL` | `300` | 本地黑名单 TTL |
| `local_rate_limit_ttl` | `LOCAL_RATE_LIMIT_TTL` | `60` | 本地速率限制 TTL |
| `circuit_breaker_fail_max` | `CIRCUIT_BREAKER_FAIL_MAX` | `5` | 熔断器跳闸阈值 |
| `circuit_breaker_timeout` | `CIRCUIT_BREAKER_TIMEOUT` | `60` | 熔断器恢复间隔 |
| `max_pending_ips` | `MAX_PENDING_IPS` | `10000` | 缓冲最大长度 |
| `max_body_hash_bytes` | `MAX_BODY_HASH_BYTES` | `10485760` | Body 哈希截断 |
| `max_body_store_bytes` | `MAX_BODY_STORE_BYTES` | `1024` | Body 存储截断 |
| `honeypot_ttl` | `HONEYPOT_TTL` | `300` | 蜜罐 TTL |
| `keyword_min_segment_length` | `KEYWORD_MIN_SEGMENT_LENGTH` | `3` | 路径段最小长度 |
| `background_sync_interval` | `BACKGROUND_SYNC_INTERVAL` | `5` | 同步间隔 |
| `kafka_retry_interval` | `KAFKA_RETRY_INTERVAL` | `5` | Kafka 重试间隔 |

### 3.11 预定义特征追加

| YAML 字段 | 环境变量 | 默认值 | 说明 |
|---|---|---|---|
| `static_keywords_extra` | `STATIC_KEYWORDS_EXTRA` | `""` | 追加到 STATIC_KW |
| `legitimate_keywords_extra` | `LEGITIMATE_KEYWORDS_EXTRA` | `""` | 追加到合法白名单 |
| `inherently_malicious_extra` | `INHERENTLY_MALICIOUS_EXTRA` | `""` | 追加到固有恶意模式 |
| `very_strong_attacks_extra` | `VERY_STRONG_ATTACKS_EXTRA` | `""` | 追加到强力攻击模式 |
| `probe_path_patterns_extra` | `PROBE_PATH_PATTERNS_EXTRA` | `""` | 追加到探测路径正则 |
| `post_only_suffixes_extra` | `POST_ONLY_SUFFIXES_EXTRA` | `""` | 追加到 POST-only 后缀 |
| `login_paths_extra` | `LOGIN_PATHS_EXTRA` | `""` | 追加到登录路径前缀 |
| `header_max_bytes` | `HEADER_MAX_BYTES` | `32768` | Header 最大字节数 |
| `header_max_count` | `HEADER_MAX_COUNT` | `100` | Header 最大数量 |

### 3.12 UUID 篡改评分

| YAML 字段 | 环境变量 | 默认值 | 说明 |
|---|---|---|---|
| `uuid_block_threshold` | `UUID_BLOCK_THRESHOLD` | `5` | 拦截阈值 |
| `uuid_malformed_weight` | `UUID_MALFORMED_WEIGHT` | `5` | malformed 权重 |
| `uuid_not_found_weight` | `UUID_NOT_FOUND_WEIGHT` | `1` | 不存在权重 |
| `uuid_success_decay` | `UUID_SUCCESS_DECAY` | `2` | 成功衰减 |
| `uuid_window_seconds` | `UUID_WINDOW_SECONDS` | `60` | 评分窗口（秒） |

### 3.13 检测模式全局开关

| YAML 字段 | 环境变量 | 默认值 | 说明 |
|---|---|---|---|
| `detection_header_enabled` | `DETECTION_HEADER_ENABLED` | `true` | 请求头验证 |
| `detection_uuid_enabled` | `DETECTION_UUID_ENABLED` | `true` | UUID 篡改检测 |
| `detection_geo_enabled` | `DETECTION_GEO_ENABLED` | `true` | 地理围栏 |
| `detection_rate_limit_enabled` | `DETECTION_RATE_LIMIT_ENABLED` | `true` | 速率限制 |
| `detection_keyword_enabled` | `DETECTION_KEYWORD_ENABLED` | `true` | 关键词策略检测 |
| `detection_fail_secure_enabled` | `DETECTION_FAIL_SECURE_ENABLED` | `true` | Fail-Secure 降级 |
| `detection_method_enabled` | `DETECTION_METHOD_ENABLED` | `true` | HTTP 方法验证 |
| `path_rules` | `PATH_RULES` | `""` | 按路径禁用检测（JSON） |

---

## 4. Redis 运行时配置覆盖

25 项检测参数可通过 Redis 运行时覆盖：

```bash
# 临时调整速率限制
redis-cli SET aiwaf:config:rate_limit_max_requests 200

# 临时关闭自动拉黑
redis-cli SET aiwaf:config:auto_block_enabled false

# 临时豁免内网 IP
redis-cli SET aiwaf:config:header_skip_ips "192.168.0.0/16"

# 恢复默认值
redis-cli DEL aiwaf:config:rate_limit_max_requests
```

10 秒本地缓存，Redis 不可用时降级到 YAML/默认值。

---

## 5. 运行时管理

### 5.1 查看/管理黑名单

```bash
redis-cli KEYS "aiwaf:blk:*"           # 查看所有黑名单 IP
redis-cli GET aiwaf:blk:10.0.1.5       # 查看拉黑原因
redis-cli DEL aiwaf:blk:10.0.1.5       # 解封 IP
```

### 5.2 查看/管理关键词

```bash
redis-cli ZREVRANGE aiwaf:keywords 0 9 WITHSCORES   # Top 10 关键词
redis-cli ZREM aiwaf:keywords shell                  # 删除误判关键词
```

### 5.3 查看/管理豁免路径

```bash
redis-cli SADD aiwaf:exempt:paths "/api/health"     # 添加豁免
redis-cli SREM aiwaf:exempt:paths "/api/health"     # 移除豁免
redis-cli SMEMBERS aiwaf:exempt:paths                # 查看所有
```

### 5.4 查看告警

```bash
kafka-console-consumer --bootstrap-server localhost:9092 \
  --topic akto.aiwaf.alerts --from-beginning
```

### 5.5 验证脚本

```bash
KAFKA_BROKERS=localhost:9092 python scripts/verify_akto_logs.py
```

---

## 6. 相关文档

- [检测能力详解](detection_capabilities.md)
- [检测模式实现机制](detection_implementation.md)
- [设计文档](design.md)
- [使用手册](usage.md)
