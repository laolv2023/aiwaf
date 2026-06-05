# AIWAF-Stream 排障指南

> 版本: 1.0 | 最后更新: 2026-06-05

---

## 1. 常见问题

### 1.1 导入错误

| 错误 | 原因 | 解决 |
|------|------|------|
| `ModuleNotFoundError: No module named 'asyncbreaker'` | 生产环境需要真实熔断器 | 安装 `asyncbreaker` 包或替换为生产实现 |
| `ModuleNotFoundError: No module named 'redis'` | redis 包未安装 | `pip install redis` |
| `ModuleNotFoundError: No module named 'aiokafka'` | aiokafka 未安装 | `pip install aiokafka` |
| `ModuleNotFoundError: No module named 'cachetools'` | cachetools 未安装 | `pip install cachetools` |
| `ModuleNotFoundError: No module named 'aiwaf.core'` | aiwaf mock 模块路径问题 | 确保项目根目录在 `PYTHONPATH` |

### 1.2 Redis 相关

| 症状 | 可能原因 | 排查步骤 |
|------|---------|----------|
| `ConnectionRefusedError` | Redis 未启动或地址错误 | 1. `redis-cli -h <host> -p <port> ping`<br>2. 检查 `redis_cluster_url` 配置 |
| `ResponseError: MOVED` | Redis Cluster 重定向 | 确保 `redis.from_url()` 后客户端自动处理 MOVED |
| `CircuitBreakerError` 频繁触发 | Redis 不稳定 | 1. 检查 Redis 负载和延迟<br>2. 增大 `fail_max` 到 10<br>3. 延长 `timeout_duration` 到 120s |
| 本地黑名单快速增长 | Redis 长时间不可用 | 1. 检查 Redis 连接<br>2. 查看 `METRIC_PENDING_OVERFLOW` |

### 1.3 Kafka 相关

| 症状 | 可能原因 | 排查步骤 |
|------|---------|----------|
| `KafkaTimeoutError` | Kafka Broker 不可达 | 1. `kafka-broker-api-versions --bootstrap-server <broker>`<br>2. 检查网络策略/防火墙 |
| `MessageSizeTooLargeError` | 消息超过 `max.message.bytes` | 减小 `MAX_BODY_STORE_BYTES` 或增大 Kafka 配置 |
| 告警未到达 | Producer 未 start | 确认 `await engine.producer.start()` 已调用 |
| DLQ 消息积压 | 消费者未启动或消费太慢 | 检查 DLQ consumer group lag |

### 1.4 ProcessPool 相关

| 症状 | 可能原因 | 排查步骤 |
|------|---------|----------|
| `BrokenProcessPool` 频繁触发 | 子进程 OOM 或 crash | 1. 检查子进程内存<br>2. 减小 `max_tasks_per_child`<br>3. 检查 ML 模型是否有内存泄漏 |
| `METRIC_POOL_FATAL` 增长 | ProcessPool 反复重建 | 查看子进程 stderr 日志定位崩溃原因 |
| 处理延迟增大 | 子进程饱和 | 增大 `core_process_pool_size` |
| `RuntimeError: Missing batch result` | 批处理结果数量不匹配 | 检查 `run_core_logic_batch_isolated` 的输出 |

### 1.5 预处理相关

| 症状 | 可能原因 | 排查步骤 |
|------|---------|----------|
| trace_id 碰撞 | 相同内容 + 相同时间戳 | 正常行为，确定性指纹 |
| `TypeError` in `hashlib.update()` | Body 为非 bytes/str 类型 | 已修复：自动 `orjson.dumps()` 处理 dict/list |
| 内存飙升 | 大 Body 未截断 | 检查 `MAX_BODY_HASH_BYTES` 和 `MAX_BODY_STORE_BYTES` |
| Query 参数丢失 | `query_params` 为空或格式不对 | 确认上游传入格式：`{"key": "value"}` 或 `{"key": ["v1","v2"]}` |

---

## 2. 诊断命令

### 2.1 快速健康检查

```bash
# 测试 Redis 连接
python -c "
import asyncio
from redis_facade import RedisClusterStateManager
async def test():
    mgr = RedisClusterStateManager('redis://localhost:6379')
    result = await mgr.is_duplicate_and_add('health-check')
    print(f'Redis OK: is_duplicate={result}')
asyncio.run(test())
"

# 测试预处理
python -c "
from preprocessor import transform_raw_log
log = transform_raw_log({'client_ip':'1.2.3.4','timestamp':1000,'uri_path':'/'})
print(f'Preprocessor OK: trace_id={log[\"trace_id\"]}')
"

# 运行冒烟测试
python -m pytest tests/ -x --tb=short
```

### 2.2 性能诊断

```bash
# Profile 预处理性能
python -m cProfile -s cumulative -m pytest tests/test_preprocessor.py -k "transform" -q

# 检查内存使用
python -c "
from redis_facade import local_blacklist, local_rate_limit
print(f'local_blacklist: {len(local_blacklist)} entries')
print(f'local_rate_limit: {len(local_rate_limit)} entries')
"
```

### 2.3 数据完整性检查

```bash
# 验证 trace_id 一致性
python -c "
from preprocessor import generate_deterministic_trace_id, transform_raw_log
raw = {'client_ip':'1.2.3.4','timestamp':1000.0,'uri_path':'/api','request_body':'test'}
log1 = transform_raw_log(dict(raw))
log2 = transform_raw_log(dict(raw))
assert log1['trace_id'] == log2['trace_id'], 'trace_id NOT deterministic!'
print('trace_id consistency: OK')
"
```

---

## 3. 常见配置错误

### 3.1 `redis_cluster_url` 格式

```python
# ✅ 正确
"redis://localhost:6379"
"rediss://user:pass@redis-cluster:6379/0"
"redis://host1:6379,host2:6379,host3:6379"

# ❌ 错误
"localhost:6379"              # 缺少协议前缀
"redis://localhost"            # 缺少端口
```

### 3.2 `kafka_brokers` 格式

```python
# ✅ 正确
"localhost:9092"
"broker1:9092,broker2:9092,broker3:9092"

# ❌ 错误
"localhost"                   # 缺少端口
"kafka://localhost:9092"      # 不需要协议前缀
```

### 3.3 ProcessPool 配置

```python
# ✅ 正确
core_process_pool_size = os.cpu_count() // 2  # 预留资源给主进程

# ❌ 可能导致问题
core_process_pool_size = os.cpu_count() * 2   # 过度订阅
max_tasks_per_child = None                     # 可能内存泄漏
```

---

## 4. 故障恢复流程

### 4.1 Redis 完全不可用

```
1. CircuitBreaker 自动触发 → 所有 Redis 操作走 Fail-Secure
2. local_blacklist / local_rate_limit 接管防线
3. 阻断的 IP 写入 _backup_buffer
4. background_sync_worker 持续尝试同步
5. Redis 恢复后自动写回积压数据
```

**手动干预**（如果同步失败）：
```python
# 手动导出备份缓冲
print(f"Pending IPs in buffer: {len(_current_buffer) + len(_backup_buffer)}")
```

### 4.2 ProcessPool 崩溃

```
1. BrokenProcessPool → _batch_dispatcher 捕获
2. METRIC_POOL_FATAL++
3. 自动重建 ProcessPoolExecutor
4. 当前批次的 futures 收到 RuntimeError
5. 各 future → _route_to_dlq (消息不丢)
```

### 4.3 Kafka Producer 断开

```
1. aiokafka 内置重连机制
2. 告警发送失败 → 异常被 _emit_alert 吞掉
3. DLQ 写入失败 → 异常被 _route_to_dlq 吞掉
4. 消息在 process_log 的 batch_queue 中等待
```

---

## 5. 性能调优

### 5.1 低延迟 (< 5ms P99)

```python
batch_size = 20          # 减小批量，更快分派
batch_timeout = 0.005    # 更短的聚合等待
core_process_pool_size = cpu_count()  # 更多子进程
```

### 5.2 高吞吐 (> 50K QPS)

```python
batch_size = 100         # 更大批量
batch_timeout = 0.02     # 更长聚合，提高批效率
batch_queue.maxsize = 20000
core_process_pool_size = cpu_count() * 0.75
```

### 5.3 内存受限 (< 512MB)

```python
MAX_BODY_HASH_BYTES = 1 * 1024 * 1024   # 1MB (从 10MB 降低)
MAX_BODY_STORE_BYTES = 256              # 256B (从 1KB 降低)
local_blacklist.maxsize = 2000          # 从 10000 降低
local_rate_limit.maxsize = 2000
batch_queue.maxsize = 2000
MAX_PENDING_IPS = 2000
```

---

## 6. 告警排查决策树

```
DLQ_OUT > 0 ?
├─ YES → 检查 error_type
│   ├─ "BrokenProcessPool" → 检查子进程内存/ML 模型
│   ├─ "ItemErrorResult"    → 检查 run_core_logic_batch_isolated 日志
│   ├─ "RuntimeError"       → 检查批处理结果数量
│   └─ 其他                 → 检查原始日志格式
└─ NO  → OK

POOL_FATAL > 0 ?
├─ YES → 子进程频繁崩溃
│   ├─ 检查 model.joblib 是否正确加载
│   ├─ 检查 joblib 版本兼容性
│   └─ 减少 max_tasks_per_child
└─ NO  → OK

PENDING_OVERFLOW > 0 ?
├─ YES → Redis 写回速度跟不上
│   ├─ 检查 Redis 延迟
│   ├─ 减少 sync 间隔
│   └─ 增加 MAX_PENDING_IPS
└─ NO  → OK
```
