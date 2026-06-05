# AIWAF-Stream 设计文档

> 版本: 1.0 | 最后更新: 2026-06-05

---

## 1. 项目概述

AIWAF-Stream 是一个**异步流式 Web 应用防火墙引擎**，面向高吞吐场景（>10K QPS），核心特性包括：

- **零信任指纹**：基于完整请求 Body 的确定性 trace_id，实现端到端可追溯
- **进程池隔离**：核心安全逻辑在 `ProcessPoolExecutor` 子进程中执行，主进程异步非阻塞
- **异步熔断 + Fail-Secure 本地防线**：Redis 不可用时自动降级到本地 TTL 缓存
- **双缓冲写回**：Fail-Secure 阻断的 IP 通过双缓冲机制异步同步回 Redis
- **微批调度**：自适应批量聚合，单批最多 50 条，兼顾吞吐与延迟

---

## 2. 架构总览

```
                          ┌─────────────────────────────────────┐
                          │          Kafka (Input Topic)          │
                          └──────────────┬──────────────────────┘
                                         │ raw_log
                                         ▼
┌────────────────────────────────────────────────────────────────────┐
│                        AIWAFStreamEngine (主进程 asyncio)           │
│                                                                    │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────────────┐   │
│  │  preprocessor │──▶│  process_log │──▶│  _batch_dispatcher   │   │
│  │  trace_id     │   │  dedup+RL    │   │  (微批调度器)         │   │
│  │  transform    │   │  fail-secure │   │                      │   │
│  └──────────────┘   └──────┬───────┘   └──────────┬───────────┘   │
│                            │                       │               │
│              ┌─────────────┼───────────────────────┼──────┐        │
│              │  RedisStateFacade │ background_sync │  KW   │        │
│              │  (CircuitBreaker) │    _worker      │refresh│        │
│              └─────────┬─────────┴────────┬────────┴───────┘        │
│                        │                  │                         │
│              ┌─────────▼─────────┐  ┌─────▼──────────┐             │
│              │ local_blacklist   │  │ double_buffer   │             │
│              │ local_rate_limit  │  │ (deque A ⇄ B)   │             │
│              │ (TTLCache)        │  │                 │             │
│              └───────────────────┘  └─────────────────┘             │
└────────────────────────────────────────────────────────────────────┘
          │                                              │
          │ ProcessPoolExecutor                          │ Kafka
          ▼                                              ▼
┌──────────────────────┐              ┌──────────────────────────────┐
│  子进程 (isolated)    │              │   Alert Topic / DLQ Topic     │
│                      │              └──────────────────────────────┘
│  run_core_logic_     │
│  batch_isolated()    │
│  ├─ evaluate_rate    │
│  ├─ evaluate_keyword │
│  └─ ProcessLocal     │
│     Collector        │
└──────────────────────┘
```

---

## 3. 数据流

### 3.1 请求处理生命周期

```
Raw Log → [preprocessor] → Std Log (with trace_id)
  → [process_log] 
      ├─ SETNX 去重 (Redis, 24h TTL)
      ├─ 滑动窗口限流 (Redis ZSET)
      ├─ [CircuitBreaker 触发]
      │    └→ Fail-Secure 本地防线
      │         ├─ local_blacklist 检查
      │         ├─ local_rate_limit 计数 → >50 → blacklist + backup_buffer
      │         └─ bypass → 放行
      └─ [正常路径]
           └→ batch_queue → _batch_dispatcher → ProcessPool
                ├─ evaluate_rate_limit (AIWAF core)
                ├─ evaluate_keyword_policy (AIWAF core)
                └→ 结果处理
                     ├─ flood_block → _emit_alert
                     ├─ keyword_block → _emit_alert
                     ├─ side_effects.blocked_ips → batch_block_ips (Redis)
                     └─ side_effects.keywords → batch_add_keywords (Redis)
```

### 3.2 trace_id 生成算法

```
trace_id = SHA256( client_ip | uri_path | MD5(request_body_bytes) | timestamp )[:32]

截断策略:
- request_body ≥ 10MB → 截断前 10MB 后 MD5 (防 OOM)
- request_body 存储 → 截断前 1KB (仅 DLQ/存储用，不影响指纹)
- dict/list 类型 body → orjson.dumps() 序列化后 hash
- bytes 类型 body → 直接 hash
```

### 3.3 双缓冲写回机制

```
_insert → _backup_buffer.append(ip)
                              │
background_sync_worker (每 5s):
  _current_buffer ⇄ _backup_buffer  (原子交换)
  for ip in _current_buffer:
      batch_block_ips(ip, "Local_FailSecure")  → Redis
      _current_buffer.popleft()
  
溢出保护: len(_current_buffer) ≥ 10000 → METRIC_PENDING_OVERFLOW++
```

---

## 4. 模块设计

### 4.1 `preprocessor.py` — 预处理引擎

| 函数 | 职责 | 输入 | 输出 |
|------|------|------|------|
| `generate_deterministic_trace_id()` | 零信任流式指纹 | `std_log: dict` | `str` (32-char hex) |
| `transform_raw_log()` | 原始日志标准化 | `raw_log: dict` | `std_log: dict` |

**设计要点**：
- 非字符串 body 自动序列化为 JSON（防 `hashlib.update()` 崩溃）
- Query 参数展开为 `key=value` 字符串列表，保留 HTTP 语义
- `client_ip` 优先用 `client_ip`，回退到 `remote_addr`

### 4.2 `acl_bootstrap.py` — 运行时防腐层 (ACL)

| 组件 | 类型 | 职责 |
|------|------|------|
| `ProcessLocalCollector` | class | 子进程内存收集器，替代 Redis/CSV 写操作 |
| `run_core_logic_batch_isolated()` | function | 批量执行入口，逐条容错 |
| `init_worker()` | function | ProcessPool initializer，加载 ML 模型 |
| `ItemSuccessResult` | dataclass | 成功结果包装 |
| `ItemErrorResult` | dataclass | 失败结果包装（100% 可序列化） |

**设计要点**：
- `ProcessLocalCollector.extract_and_clear()` 原子提取+清空，防止跨请求污染
- 子进程异常不传播到主进程，包装为 `ItemErrorResult`
- 每条消息独立容错，不因单条失败丢弃整批

### 4.3 `redis_facade.py` — Redis 状态管理

| 组件 | 类型 | 职责 |
|------|------|------|
| `RedisClusterStateManager` | class | 核心 Redis 操作（SETNX/ZSET/Pipeline） |
| `RedisStateFacade` | class | 熔断器装饰门面 |
| `local_blacklist` | TTLCache(10000, 300s) | 本地黑名单 |
| `local_rate_limit` | TTLCache(10000, 60s) | 本地限流计数器 |
| `background_sync_worker()` | coroutine | 双缓冲异步写回 |

**Redis 数据结构**：
| Key Pattern | 类型 | TTL | 用途 |
|-------------|------|-----|------|
| `aiwaf:idem:{trace_id}` | String (SETNX) | 86400s | 请求去重 |
| `aiwaf:rl:{ip}` | ZSET | `window*2` | 滑动窗口限流 |
| `aiwaf:blk:{ip}` | String | 3600s | IP 黑名单 |
| `aiwaf:keywords` | ZSET | 持久 | 动态关键词排行 |

### 4.4 `engine.py` — 异步流式检测引擎

| 组件 | 类型 | 职责 |
|------|------|------|
| `AIWAFStreamEngine` | class | 主引擎，编排全链路 |
| `_batch_dispatcher()` | coroutine | 自适应微批调度器 |
| `_keyword_refresh_worker()` | coroutine | 10s 间隔刷新关键词缓存 |
| `_emit_alert()` | coroutine | Kafka 告警发送 |
| `_route_to_dlq()` | coroutine | DLQ 路由 |

**关键参数**：
| 参数 | 默认值 | 说明 |
|------|--------|------|
| `core_process_pool_size` | settings 配置 | 子进程池大小 |
| `max_tasks_per_child` | 200 | 每个子进程最大任务数（防内存泄漏） |
| `batch_queue.maxsize` | 10000 | 批队列容量（背压） |
| `batch_size` | 50 | 单批最大条数 |
| `batch_timeout` | 0.01s | 微批等待超时 |

### 4.5 `train_pipeline.py` — 离线训练管道

| 函数 | 职责 |
|------|------|
| `_process_row_purifier()` | 行级清洗：评估关键词策略，返回是否保留该行 |

### 4.6 `asyncbreaker.py` — 异步熔断器

| 类 | 职责 |
|------|------|
| `CircuitBreakerError` | 熔断器打开时抛出的异常 |
| `CircuitBreaker` | 异步熔断器，提供 `context()` async context manager |

---

## 5. 容错设计

### 5.1 熔断降级路径

```
Redis 操作
  ├─ 正常 → 返回结果
  └─ CircuitBreakerError
       └→ Fail-Secure 本地防线
            ├─ IP in local_blacklist → 阻断 + Alert
            ├─ IP in double_buffer → 阻断 + Alert
            ├─ local_rate_limit[ip] > 50 → blacklist + buffer → 阻断
            └─ local_rate_limit[ip] ≤ 50 → 放行
```

### 5.2 ProcessPool 容错

- `BrokenProcessPool` → 重建 Executor + `METRIC_POOL_FATAL` 指标
- `max_tasks_per_child=200` → 定期回收子进程，防内存泄漏
- `cancel_futures=True` → BrokenPool 时取消所有未完成任务

### 5.3 可观测性

| Metric | 类型 | 含义 |
|--------|------|------|
| `aiwaf_engine_in_total` | Counter | 接收日志数 |
| `aiwaf_dlq_out_total` | Counter | DLQ 路由数 |
| `aiwaf_pool_fatal_total` | Counter | ProcessPool 重建次数 |
| `aiwaf_pending_overflow_total` | Counter | 双缓冲溢出次数 |

---

## 6. 安全设计原则

1. **零信任指纹**：trace_id 由请求内容决定，客户端不可伪造
2. **SETNX 绝对幂等**：相同 trace_id 的请求只处理一次（24h 窗口）
3. **防乱序**：限流 ZSET 使用 `event_time*1000 + random` 作为 score，防止同毫秒覆盖
4. **Fail-Secure**：Redis 不可用时不丢检测能力，本地缓存承担防线
5. **子进程隔离**：核心逻辑 crash 不影响主进程事件循环
