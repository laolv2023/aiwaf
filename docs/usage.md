# AIWAF-Stream 使用手册

> 版本: 1.0 | 最后更新: 2026-06-05

---

## 1. 快速开始

### 1.1 最小可用示例

```python
import asyncio
from engine import AIWAFStreamEngine
from redis_facade import RedisClusterStateManager
from preprocessor import transform_raw_log

class SimpleSettings:
    redis_cluster_url = "redis://localhost:6379"
    kafka_brokers = "localhost:9092"
    alert_topic = "aiwaf.alerts"
    dlq_topic = "aiwaf.dlq"
    core_process_pool_size = 4

async def main():
    # 1. 初始化
    state_mgr = RedisClusterStateManager(SimpleSettings.redis_cluster_url)
    engine = AIWAFStreamEngine(SimpleSettings(), state_mgr, "model.joblib")
    await engine.start()

    # 2. 处理请求
    raw_log = {
        "client_ip": "192.168.1.100",
        "timestamp": 1717623456.789,
        "method": "POST",
        "uri_path": "/api/login",
        "query_params": {"user": "admin", "pass": "123456"},
        "request_body": '{"user":"admin"}',
    }
    
    std_log = transform_raw_log(raw_log)
    await engine.process_log(std_log)

    # 3. 保持运行
    await asyncio.Event().wait()

asyncio.run(main())
```

### 1.2 输入格式

#### Raw Log (上游输入)
```json
{
    "client_ip": "1.2.3.4",
    "remote_addr": "1.2.3.4",
    "timestamp": 1717623456.789,
    "method": "POST",
    "uri_path": "/api/v1/users",
    "query_params": {
        "search": "SELECT * FROM users",
        "limit": ["10"]
    },
    "request_body": "{\"payload\":\"...\"}",
    "status": 200
}
```

#### Std Log (预处理后)
```json
{
    "client_ip": "1.2.3.4",
    "timestamp": 1717623456.789,
    "method": "POST",
    "uri_path": "/api/v1/users",
    "query_keys": ["search", "limit"],
    "query_strings": ["search=SELECT * FROM users", "limit=10"],
    "status_code": 200,
    "trace_id": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
    "req_body_truncated": "{\"payload\":\"...\"}"
}
```

---

## 2. API 参考

### 2.1 Preprocessor

```python
from preprocessor import generate_deterministic_trace_id, transform_raw_log

# 生成确定性 trace_id
trace_id = generate_deterministic_trace_id(std_log)

# 标准化原始日志
std_log = transform_raw_log(raw_log)
```

### 2.2 RedisClusterStateManager

```python
from redis_facade import RedisClusterStateManager

mgr = RedisClusterStateManager("redis://localhost:6379")

# 请求去重（返回 True 表示重复）
is_dup = await mgr.is_duplicate_and_add("trace-abc")

# 带重试次数去重
is_dup = await mgr.is_duplicate_and_add("trace-abc", is_retry=True, retry_count=1)

# 滑动窗口限流
timestamps = await mgr.get_and_update_rate_limit("1.2.3.4", time.time(), window=60, max_req=100)

# 批量封禁 IP
await mgr.batch_block_ips([("1.2.3.4", "SQLi"), ("5.6.7.8", "Flood")])

# 获取 Top 关键词
top_kws = await mgr.get_top_keywords(500)

# 批量添加关键词
await mgr.batch_add_keywords(["sqli", "xss", "rce"])
```

### 2.3 AIWAFStreamEngine

```python
from engine import AIWAFStreamEngine

engine = AIWAFStreamEngine(settings, state_mgr, "model.joblib")

# 启动引擎（自动启动 dispatcher/sync/refresh workers）
await engine.start()

# 处理单条标准日志
await engine.process_log(std_log)

# 处理重试消息
await engine.process_log(std_log, is_retry=True, retry_count=2)
```

### 2.4 Train Pipeline

```python
from train_pipeline import _process_row_purifier

# 行级清洗：评估关键词，返回是否保留该行
keep = _process_row_purifier((
    {"uri_path": "/api/data", "query_strings": ["q=DROP TABLE"]},
    ["DROP", "UNION", "SELECT"]
))
# keep == False (被关键词匹配，过滤掉)
```

---

## 3. 典型场景

### 3.1 与 Kafka 集成

```python
from aiokafka import AIOKafkaConsumer

async def consume_loop(engine):
    consumer = AIOKafkaConsumer(
        'input-topic',
        bootstrap_servers='localhost:9092',
        value_deserializer=lambda m: orjson.loads(m)
    )
    await consumer.start()
    try:
        async for msg in consumer:
            raw_log = msg.value
            std_log = transform_raw_log(raw_log)
            asyncio.create_task(engine.process_log(std_log))
    finally:
        await consumer.stop()
```

### 3.2 自定义告警处理

```python
class CustomEngine(AIWAFStreamEngine):
    async def _emit_alert(self, std_log, rule):
        # 发送到多个目标
        alert = {"trace_id": std_log["trace_id"], "rule_id": rule, ...}
        
        # Kafka
        await self.producer.send_and_wait(self.settings.alert_topic, orjson.dumps(alert))
        
        # Webhook
        await self._send_webhook(alert)
        
        # Slack
        if rule.startswith("KeywordBlock"):
            await self._send_slack(alert)

    async def _send_webhook(self, alert):
        import aiohttp
        async with aiohttp.ClientSession() as session:
            await session.post("https://hooks.example.com/alert", json=alert)
```

### 3.3 自定义限流策略

```python
# 在 redis_facade.py 中
class RedisClusterStateManager:
    async def get_and_update_rate_limit_custom(
        self, ip: str, event_time: float, 
        window: int, max_req: int, burst_window: int = 10, burst_max: int = 20
    ) -> list:
        """双层限流：长窗口 + 短窗口突发控制"""
        # 短窗口检查
        burst_key = f"aiwaf:rl:{ip}:burst"
        pipe = self.redis.pipeline(transaction=False)
        pipe.zremrangebyscore(burst_key, 0, (event_time - burst_window) * 1000)
        pipe.zcard(burst_key)
        burst_count = (await pipe.execute())[1]
        
        if burst_count >= burst_max:
            return []  # 空列表触发 flood_block
        
        # 正常窗口
        return await self.get_and_update_rate_limit(ip, event_time, window, max_req)
```

---

## 4. 日志格式

引擎输出告警格式：
```json
{
    "trace_id": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
    "rule_id": "KeywordBlock:path_match:sqli",
    "alert_timestamp": 1717623456.789,
    "client_ip": "1.2.3.4"
}
```

DLQ 消息格式：
```json
{
    "trace_id": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
    "error": "ItemErrorResult: dataclass construction failed",
    "error_type": "ItemErrorResult",
    "raw_log": {
        "client_ip": "1.2.3.4",
        "uri_path": "/api/data",
        "req_body_truncated": "..."
    }
}
```
