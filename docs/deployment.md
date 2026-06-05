# AIWAF-Stream 部署与配置文档

> 版本: 1.0 | 最后更新: 2026-06-05

---

## 1. 环境依赖

### 1.1 运行时依赖

| 包名 | 版本要求 | 用途 |
|------|---------|------|
| Python | ≥3.10 | 异步特性 (asyncio.timeout, match-case) |
| orjson | ≥3.9 | 高性能 JSON 序列化 |
| redis | ≥5.0 | Redis 异步客户端 (redis.asyncio) |
| aiokafka | ≥0.8 | Kafka 异步生产者 |
| cachetools | ≥5.0 | 本地 TTL 缓存 (Fail-Secure) |
| prometheus-client | ≥0.17 | 指标暴露 |
| joblib | ≥1.3 | ML 模型加载（子进程） |

### 1.2 外部服务

| 服务 | 要求 | 用途 |
|------|------|------|
| Redis Cluster | ≥6.0 | 去重、限流、黑名单、关键词排行 |
| Kafka Cluster | ≥2.8 | 告警 Topic + DLQ Topic |
| ML Model | joblib 格式 | 子进程加载的安全模型 |

### 1.3 测试依赖

| 包名 | 用途 |
|------|------|
| pytest ≥7.0 | 测试框架 |
| pytest-asyncio | 异步测试支持 |

---

## 2. 安装部署

### 2.1 手动安装

```bash
# 克隆仓库
git clone https://github.com/laolv2023/aiwaf.git
cd aiwaf

# 创建虚拟环境
python3.12 -m venv venv
source venv/bin/activate

# 安装依赖
pip install -r requirements.txt

# 安装项目（开发模式）
pip install -e .
```

### 2.2 Docker 部署

```dockerfile
FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["python", "-m", "aiwaf_stream.launcher"]
```

```bash
# 构建镜像
docker build -t aiwaf-stream:latest .

# 运行
docker run -d \
  --name aiwaf-stream \
  -e REDIS_URL="redis://redis-cluster:6379" \
  -e KAFKA_BROKERS="kafka:9092" \
  -e MODEL_PATH="/models/waf_model.joblib" \
  aiwaf-stream:latest
```

### 2.3 Kubernetes 部署

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: aiwaf-stream
spec:
  replicas: 3
  selector:
    matchLabels:
      app: aiwaf-stream
  template:
    metadata:
      labels:
        app: aiwaf-stream
    spec:
      containers:
      - name: aiwaf
        image: aiwaf-stream:latest
        env:
        - name: REDIS_URL
          valueFrom:
            secretKeyRef:
              name: aiwaf-secrets
              key: redis_url
        - name: KAFKA_BROKERS
          value: "kafka-broker-0:9092,kafka-broker-1:9092,kafka-broker-2:9092"
        resources:
          requests:
            memory: "512Mi"
            cpu: "1"
          limits:
            memory: "2Gi"
            cpu: "4"
```

---

## 3. 配置说明

### 3.1 Settings 对象

引擎通过 `settings` 对象获取配置，需实现以下属性：

```python
class Settings:
    # Redis
    redis_cluster_url: str      # Redis 集群连接串
    
    # Kafka
    kafka_brokers: str          # Kafka Broker 列表，逗号分隔
    alert_topic: str            # 告警 Topic 名称
    dlq_topic: str              # 死信队列 Topic 名称
    
    # 进程池
    core_process_pool_size: int # 子进程池大小（建议 CPU 核数 * 0.75）
```

### 3.2 环境变量（推荐）

| 变量 | 必需 | 默认值 | 说明 |
|------|------|--------|------|
| `REDIS_URL` | ✅ | — | Redis 集群连接 URL |
| `KAFKA_BROKERS` | ✅ | — | Kafka Broker 地址 |
| `KAFKA_ALERT_TOPIC` | ❌ | `aiwaf.alerts` | 告警 Topic |
| `KAFKA_DLQ_TOPIC` | ❌ | `aiwaf.dlq` | DLQ Topic |
| `CORE_POOL_SIZE` | ❌ | `os.cpu_count()` | 子进程池大小 |
| `MODEL_PATH` | ✅ | — | ML 模型文件路径 |

### 3.3 调优参数

| 参数 | 位置 | 默认值 | 调优建议 |
|------|------|--------|----------|
| `core_process_pool_size` | engine.py:31 | CPU 核数 | = CPU 核数 * 0.5~0.75 |
| `max_tasks_per_child` | engine.py:32 | 200 | 高负载场景减少到 100 |
| `batch_queue.maxsize` | engine.py:36 | 10000 | 按内存调整，1 item ≈ 2KB |
| `batch_size` | engine.py:72 | 50 | 低延迟场景减到 20，高吞吐增到 100 |
| `batch_timeout` | engine.py:71 | 0.01s | 低延迟场景减到 0.005 |
| `MAX_BODY_HASH_BYTES` | preprocessor.py:8 | 10MB | 按最大文件上传大小调整 |
| `MAX_BODY_STORE_BYTES` | preprocessor.py:9 | 1KB | 按 DLQ 存储需求调整 |
| `local_blacklist TTL` | redis_facade.py:63 | 300s | 黑名单有效期 |
| `local_rate_limit TTL` | redis_facade.py:64 | 60s | 限流窗口 |
| `local_rate_limit threshold` | engine.py:136 | 50 | 触发黑名单的请求数 |
| `redis_breaker fail_max` | redis_facade.py:61 | 5 | 熔断失败数阈值 |
| `redis_breaker timeout` | redis_facade.py:61 | 60s | 熔断恢复超时 |

---

## 4. 启动与停止

### 4.1 启动

```python
import asyncio
from engine import AIWAFStreamEngine
from redis_facade import RedisClusterStateManager

async def main():
    settings = load_settings()  # 用户实现
    state_mgr = RedisClusterStateManager(settings.redis_cluster_url)
    engine = AIWAFStreamEngine(settings, state_mgr, settings.model_path)
    
    await engine.start()
    
    # 消费 Kafka 消息，传入 engine.process_log()
    # ...

asyncio.run(main())
```

### 4.2 优雅停止

```python
async def shutdown(engine):
    # 1. 停止接收新消息
    # 2. 等待 batch_queue 排空
    while not engine.batch_queue.empty():
        await asyncio.sleep(0.1)
    # 3. 关闭 ProcessPool
    engine.core_executor.shutdown(wait=True)
    # 4. 停止 Kafka producer
    await engine.producer.stop()
```

### 4.3 健康检查

```python
async def health_check(engine) -> dict:
    return {
        "batch_queue_size": engine.batch_queue.qsize(),
        "pool_workers": engine.core_executor._max_workers,
        "keywords_cached": len(engine.dynamic_keywords_cache),
        "local_blacklist_size": len(local_blacklist),
        "local_rate_limit_size": len(local_rate_limit),
    }
```

---

## 5. 监控指标

### 5.1 Prometheus Metrics

```promql
# 吞吐量
rate(aiwaf_engine_in_total[1m])

# DLQ 率
rate(aiwaf_dlq_out_total[1m]) / rate(aiwaf_engine_in_total[1m])

# ProcessPool 健康
rate(aiwaf_pool_fatal_total[5m])

# 双缓冲压力
aiwaf_pending_overflow_total
```

### 5.2 告警规则

```yaml
groups:
  - name: aiwaf
    rules:
      - alert: HighDLQRate
        expr: rate(aiwaf_dlq_out_total[5m]) / rate(aiwaf_engine_in_total[5m]) > 0.01
        for: 5m
        annotations:
          summary: "DLQ rate exceeds 1%"

      - alert: ProcessPoolBroken
        expr: rate(aiwaf_pool_fatal_total[5m]) > 0
        annotations:
          summary: "ProcessPool was rebuilt"

      - alert: BufferOverflow
        expr: rate(aiwaf_pending_overflow_total[5m]) > 0
        annotations:
          summary: "Double buffer overflow"
```

---

## 6. 容量规划

| QPS | CPU 核数 | 内存 | Redis 内存/天 |
|-----|---------|------|---------------|
| 1K | 2 | 512MB | ~50MB |
| 5K | 4 | 1GB | ~250MB |
| 10K | 8 | 2GB | ~500MB |
| 50K | 32 | 8GB | ~2.5GB |

> Redis 内存估算基于：每次请求 1 个 SETNX key (100B) + 1 个 ZSET member (50B) × 86400s 内的请求。
