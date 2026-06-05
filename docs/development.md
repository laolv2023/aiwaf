# AIWAF-Stream 开发文档

> 版本: 1.0 | 最后更新: 2026-06-05

---

## 1. 项目结构

```
aiwaf_stream/
├── __init__.py
├── preprocessor.py          # 预处理引擎：trace_id 生成 + 日志标准化
├── acl_bootstrap.py         # 运行时防腐层：子进程批量执行 + 副作用收集
├── redis_facade.py          # Redis 状态管理：去重/限流/黑名单 + Fail-Secure
├── engine.py                # 异步流式检测引擎：主入口 + 微批调度
├── train_pipeline.py        # 离线训练管道：Airflow DAG 行级清洗
├── asyncbreaker.py          # 异步熔断器 stub（测试用，生产替换）
├── aiwaf/
│   ├── __init__.py
│   └── core/
│       ├── __init__.py
│       ├── rate_limit.py    # 限流决策模型
│       └── ip_keyword.py    # 关键词策略模型
├── tests/
│   ├── __init__.py
│   ├── test_preprocessor.py   # 99 tests
│   ├── test_acl_bootstrap.py  # 100 tests
│   ├── test_redis_facade.py   # 103 tests
│   ├── test_engine.py         # 118 tests
│   └── test_train_pipeline.py # 80 tests
└── docs/
    ├── design.md
    ├── development.md
    ├── testing.md
    ├── deployment.md
    ├── usage.md
    └── troubleshooting.md
```

---

## 2. 模块开发指南

### 2.1 Preprocessor 模块

**核心函数**：

```python
def generate_deterministic_trace_id(std_log: dict) -> str:
    """基于 IP + URI + MD5(Body) + Timestamp 生成唯一 trace_id"""
    
def transform_raw_log(raw_log: dict) -> dict:
    """将上游原始日志转为 AIWAF 标准格式"""
```

**扩展示例** — 添加新的 Body 哈希算法：

```python
# 在 generate_deterministic_trace_id() 中替换 MD5 为 SHA256
body_hasher = hashlib.sha256()          # 改为 SHA256
body_hasher.update(raw_body_bytes)
body_hash = body_hasher.hexdigest()[:32]  # 截断 128-bit
```

**注意事项**：
- `request_body` 可能是 `str`、`bytes`、`dict`、`list`，必须处理所有类型
- 超过 `MAX_BODY_HASH_BYTES`(10MB) 的 Body 会被截断后 hash
- `transform_raw_log` 会 `del std_log["request_body"]` 释放主进程内存

### 2.2 ACL Bootstrap 模块

**核心类/函数**：

```python
class ProcessLocalCollector:
    """替代原生 WAF 的 Redis/CSV 写入，内存收集副作用"""
    def block_ip(self, ip, reason, extended_request_info=None): ...
    def add_keyword(self, kw, count=1): ...
    def extract_and_clear(self) -> dict: ...

def run_core_logic_batch_isolated(
    batch_logs_json, batch_timestamps, batch_event_times, dynamic_kws
) -> List[ItemSuccessResult | ItemErrorResult]: ...

def init_worker(model_path: str): ...
```

**添加新副作用类型的步骤**：

1. 在 `ProcessLocalCollector` 添加收集方法：
```python
def add_custom_metric(self, name: str, value: float):
    if not hasattr(self, '_custom_metrics'):
        self._custom_metrics = {}
    self._custom_metrics[name] = self._custom_metrics.get(name, 0) + value
```

2. 在 `extract_and_clear()` 中提取并清空：
```python
effects = {
    ...
    'custom_metrics': dict(getattr(self, '_custom_metrics', {}))
}
if hasattr(self, '_custom_metrics'):
    self._custom_metrics.clear()
```

3. 在 `run_core_logic_batch_isolated()` 中调用新方法

### 2.3 Redis Facade 模块

**核心类**：

```python
class RedisClusterStateManager:
    """直接操作 Redis，不做容错"""
    async def is_duplicate_and_add(trace_id, is_retry, retry_count) -> bool: ...
    async def get_and_update_rate_limit(ip, event_time, window, max_req) -> list: ...
    async def batch_block_ips(ips_reasons) -> None: ...
    async def get_top_keywords(n) -> List[str]: ...
    async def batch_add_keywords(kws) -> None: ...

class RedisStateFacade:
    """CircuitBreaker 装饰器，自动熔断"""
```

**添加新的 Redis 操作**：

1. 在 `RedisClusterStateManager` 添加方法：
```python
async def get_ip_reputation(self, ip: str) -> int:
    return int(await self.redis.get(f"aiwaf:rep:{ip}") or 0)
```

2. 在 `RedisStateFacade` 添加门面方法：
```python
async def get_ip_reputation(self, ip: str) -> int:
    async with redis_breaker.context():
        return await self.mgr.get_ip_reputation(ip)
```

### 2.4 Engine 模块

**核心类**：

```python
class AIWAFStreamEngine:
    async def start(self): ...
    async def process_log(self, std_log, is_retry, retry_count): ...
```

**添加新的 Worker 协程**：

```python
async def _metrics_report_worker(self):
    """每 30 秒上报 Prometheus 指标"""
    while True:
        await asyncio.sleep(30)
        # push metrics to pushgateway
```

然后在 `start()` 中注册：
```python
async def start(self):
    ...
    asyncio.create_task(self._metrics_report_worker())
```

---

## 3. 编码规范

### 3.1 类型注解
所有公共函数必须有完整的类型注解：
```python
def transform_raw_log(raw_log: dict) -> dict: ...
async def process_log(self, std_log: dict, is_retry: bool = False, retry_count: int = 0) -> None: ...
```

### 3.2 异常处理
- **子进程**：所有异常包装为 `ItemErrorResult`，不传播到主进程
- **主进程**：Redis 操作异常由 `CircuitBreaker` 捕获 → 降级到 Fail-Secure
- **告警/DLQ**：告警失败不阻塞主流程 (`except Exception: pass`)

### 3.3 docstring 格式
```python
def function_name(param: type) -> return_type:
    """一行概要描述。

    详细说明（可选）。
    """
```

### 3.4 import 规范
- 标准库第一组
- 第三方库第二组
- 项目内部第三组
- 延迟导入：`redis.asyncio` 和 `joblib` 采用函数内 `import`（避免子进程加载开销）

---

## 4. 开发环境搭建

```bash
# 1. 创建虚拟环境
python -m venv venv
source venv/bin/activate

# 2. 安装依赖
pip install orjson cachetools aiokafka redis prometheus-client pytest pytest-asyncio

# 3. 安装 mock 核心模块（测试用）
pip install -e .

# 4. 运行测试验证
python -m pytest tests/ -v
```

---

## 5. 关键设计决策记录 (ADR)

| # | 决策 | 理由 |
|---|------|------|
| 1 | trace_id 用 SHA256(MD5(body))[:32] | 128-bit 有效位，防碰撞；双 hash 防长度扩展攻击 |
| 2 | `max_tasks_per_child=200` | 防止 Python GIL 和 C 扩展内存碎片在子进程中累积 |
| 3 | 微批大小 50 + 超时 0.01s | 在吞吐和延迟间平衡；小于 1ms 延迟增加 < 0.5ms |
| 4 | `local_rate_limit` 阈值 50 | 1 分钟内单 IP 50+ 请求触发 Fail-Secure 阻断 |
| 5 | 双缓冲 5s 同步周期 | Redis 不可用期间阻断 5s 内批量写回 |
