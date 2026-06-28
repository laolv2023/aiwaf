# AIWAF-Stream 排障指南

> 版本: 2.0 | 最后更新: 2026-06-28

---

## 1. 常见问题

### 1.1 导入错误

| 错误 | 原因 | 解决 |
|------|------|------|
| `ModuleNotFoundError: No module named 'aiwaf.stream'` | 项目根目录不在 PYTHONPATH | `export PYTHONPATH=/path/to/aiwaf` |
| `ModuleNotFoundError: No module named 'aiokafka'` | aiokafka 未安装 | `pip install aiokafka` |
| `ModuleNotFoundError: No module named 'redis'` | redis 未安装 | `pip install redis` |
| `ModuleNotFoundError: No module named 'cachetools'` | cachetools 未安装 | `pip install cachetools` |
| `ModuleNotFoundError: No module named 'yaml'` | PyYAML 未安装 | `pip install pyyaml` |
| `ModuleNotFoundError: No module named 'sklearn'` | scikit-learn 未安装（AI 训练可选） | `pip install scikit-learn` |

### 1.2 Redis 相关

| 症状 | 可能原因 | 排查步骤 |
|------|---------|----------|
| `ConnectionRefusedError` | Redis 未启动 | `redis-cli ping` |
| `CircuitBreakerError` 频繁触发 | Redis 不稳定 | 调整 `circuit_breaker_fail_max` 和 `circuit_breaker_timeout` |
| 本地黑名单快速增长 | Redis 长时间不可用 | 检查 Redis 连接，查看 `aiwaf_pending_overflow_total` 指标 |
| 双缓冲同步失败 | Redis 写入异常 | 检查 `background_sync_worker` 日志 |

### 1.3 Kafka 相关

| 症状 | 可能原因 | 排查步骤 |
|------|---------|----------|
| `KafkaTimeoutError` | Broker 不可达 | `kafka-broker-api-versions --bootstrap-server <broker>` |
| 告警未到达 Topic | Producer 未 start | 确认 `await engine.start()` 已调用 |
| 消费循环停止 | Consumer 异常退出 | 检查 `kafka_retry_interval` 配置，查看日志 |
| DLQ 消息积压 | 下游消费慢 | 检查 DLQ consumer group lag |

### 1.4 ProcessPool 相关

| 症状 | 可能原因 | 排查步骤 |
|------|---------|----------|
| `BrokenProcessPool` 频繁 | 子进程 OOM/crash | 减小 `max_tasks_per_child`，检查 ML 模型内存 |
| `aiwaf_pool_fatal_total` 增长 | ProcessPool 反复重建 | 查看子进程 stderr 日志 |
| 处理延迟增大 | 子进程饱和 | 增大 `core_process_pool_size` |
| `init_worker` 失败 | model_path 不存在或损坏 | 检查模型文件路径和完整性 |

### 1.5 请求头验证相关

| 症状 | 可能原因 | 排查步骤 |
|------|---------|----------|
| 内网 API 全部被 HeaderBlock | 内网客户端无 Accept/UA | 配置 `header_skip_ips: "192.168.0.0/16"` 或 `header_required: ""` |
| 合法爬虫被拦截 | UA 匹配可疑模式 | 配置 `header_legitimate_bots: "googlebot,bingbot"` |
| 误报率过高 | 必需头过严 | 配置 `header_required: ""` 禁用必需头检查 |

### 1.6 UUID 篡改相关

| 症状 | 可能原因 | 排查步骤 |
|------|---------|----------|
| UUID 误报 | 路径段恰好 36 字符含 4 个 dash | 检查是否为合法 UUID 格式 |
| 无 UUID 的路径误报 | `is_malformed_uuid` 对非 UUID 返回 True | 已修复：仅检查 36 字符 + 4 dash 的段 |

### 1.7 地理围栏相关

| 症状 | 可能原因 | 排查步骤 |
|------|---------|----------|
| 所有请求被 GeoBlock | `geo_allow_countries` 配置过严 | 检查配置，空=全部允许 |
| GeoIP 不生效 | `geoip_db_path` 为空或文件不存在 | 检查路径和文件 |
| 国家代码不匹配 | 大小写问题 | `evaluate_geo_policy` 内部自动转大写 |

### 1.8 AI 异常检测相关

| 症状 | 可能原因 | 排查步骤 |
|------|---------|----------|
| AI 训练跳过 | 数据量不足 | 检查 `ai_min_logs`（默认 50），增加训练数据 |
| 所有请求预测为异常 | 训练数据太少或 contamination 过高 | 增加训练数据，降低 `ai_contamination`（如 0.01） |
| sklearn 未安装 | AI 功能需要可选依赖 | `pip install scikit-learn numpy pandas` |

---

## 2. 诊断命令

### 2.1 Redis 状态检查

```bash
# 黑名单
redis-cli KEYS "aiwaf:blk:*" | wc -l
redis-cli GET aiwaf:blk:10.0.1.5

# 关键词库
redis-cli ZCARD aiwaf:keywords
redis-cli ZREVRANGE aiwaf:keywords 0 9 WITHSCORES

# 速率限制
redis-cli ZCARD aiwaf:rl:10.0.1.5
redis-cli ZRANGE aiwaf:rl:10.0.1.5 0 -1 WITHSCORES

# 去重记录
redis-cli DBSIZE  # 包含 aiwaf:idem:* keys

# 配置覆盖
redis-cli KEYS "aiwaf:config:*"

# 豁免路径
redis-cli SMEMBERS aiwaf:exempt:paths
```

### 2.2 Kafka 状态检查

```bash
# Consumer Group lag
kafka-consumer-groups --bootstrap-server localhost:9092 \
  --describe --group aiwaf-consumer-group

# 告警 Topic 消息
kafka-console-consumer --bootstrap-server localhost:9092 \
  --topic akto.aiwaf.alerts --max-messages 5

# DLQ Topic 消息
kafka-console-consumer --bootstrap-server localhost:9092 \
  --topic akto.aiwaf.dlq --max-messages 5
```

### 2.3 验证脚本

```bash
KAFKA_BROKERS=localhost:9092 python scripts/verify_akto_logs.py
```

### 2.4 Prometheus 指标

| 指标 | 含义 | 异常阈值 |
|---|---|---|
| `aiwaf_engine_in_total` | 入口计数 | 停止增长 = 消费循环停止 |
| `aiwaf_dlq_out_total` | DLQ 计数 | 快速增长 = 处理异常 |
| `aiwaf_pool_fatal_total` | 进程池崩溃 | >0 = 子进程问题 |
| `aiwaf_pending_overflow_total` | 缓冲溢出 | >0 = Redis 长时间不可用 |

---

## 3. Fail-Secure 降级排查

### 3.1 判断是否进入降级模式

```bash
# 检查本地黑名单是否有数据（降级模式下会增长）
redis-cli KEYS "aiwaf:blk:*" | wc -l

# 检查 Prometheus 指标
# aiwaf_pending_overflow_total > 0 → 缓冲溢出
```

### 3.2 Redis 恢复后的操作

Redis 恢复后，`background_sync_worker` 会自动将缓冲中的 IP 同步回 Redis。无需手动操作。

如果需要手动同步：

```bash
# 查看缓冲中的 IP（需要从进程内存获取，无直接命令）
# 重启引擎即可触发同步
```

---

## 4. 相关文档

- [检测能力详解](detection_capabilities.md)
- [检测模式实现机制](detection_implementation.md)
- [设计文档](design.md)
- [部署与配置](deployment.md)
