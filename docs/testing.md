# AIWAF-Stream 测试文档

> 版本: 2.0 | 测试用例总数: 427 | 最后更新: 2026-06-28

---

## 1. 测试策略

### 1.1 分层测试架构

```
┌─────────────────────────────────────────┐
│          Integration Tests (集成)         │  ~15%
│  端到端流程：preprocess → ACL → engine    │
├─────────────────────────────────────────┤
│         Surface Tests (浅层)              │  ~35%
│  单函数/单类 正常路径 + 边界条件            │
├─────────────────────────────────────────┤
│          Deep Tests (深度)                │  ~40%
│  多参数组合、并发、异常恢复、压力场景        │
├─────────────────────────────────────────┤
│          Edge Cases (边缘)                │  ~10%
│  None/空字符串、超大数据、特殊字符、Unicode  │
└─────────────────────────────────────────┘
```

### 1.2 Mock 策略

| 外部依赖 | Mock 方式 | 文件 |
|----------|-----------|------|
| Redis | `unittest.mock.patch('redis.asyncio.from_url')` → `MockRedis` | test_redis_facade.py, test_engine.py |
| Kafka | `unittest.mock.AsyncMock` | test_engine.py |
| File I/O | 不 mock，使用真实沙箱文件 | test_engine.py |
| AIWAF Core | `aiwaf/core/` 下的 mock 实现 | aiwaf/core/*.py |

---

## 2. 测试文件明细

### 2.1 `test_preprocessor.py` — 99 tests

| 测试类 | 数量 | 覆盖范围 |
|--------|------|----------|
| `TestDeterministicTraceId` | ~20 | trace_id 确定性、唯一性、碰撞测试 |
| `TestTransformRawLog` | ~20 | 日志标准化、字段映射、Query 参数展开 |
| `TestEdgeCases` | ~15 | None/空值、超长 Body、二进制 Body、特殊字符 |
| `TestSupplementaryPreprocessor` | ~10 | 补充边界条件 |
| `TestDeepFingerprint` | ~10 | 指纹碰撞深度测试、多类型 Body |
| `TestDeepTransform` | ~12 | 深度转换测试 |
| `TestIntegrationPreprocessor` | ~12 | 全链路集成 |

**关键用例示例**：
```python
def test_same_input_same_trace_id(self):
    """相同输入产生相同 trace_id"""
    raw = {"client_ip":"1.2.3.4","timestamp":1234567890.0,"uri_path":"/api","request_body":"test"}
    id1 = generate_deterministic_trace_id(transform_raw_log(raw))
    id2 = generate_deterministic_trace_id(transform_raw_log(raw))
    assert id1 == id2

def test_different_body_different_trace_id(self):
    """不同 Body 产生不同 trace_id（防碰撞）"""
    ...

def test_body_over_10mb_truncated(self):
    """超 10MB Body 截断后 hash，不 OOM"""
    ...
```

### 2.2 `test_acl_bootstrap.py` — 100 tests

| 测试类 | 数量 | 覆盖范围 |
|--------|------|----------|
| `TestProcessLocalCollector` | ~15 | Collector 原子操作、extract_and_clear 清空 |
| `TestResultDataclasses` | ~6 | ItemSuccessResult / ItemErrorResult 构造与序列化 |
| `TestRunCoreLogicBatchIsolated` | ~18 | 批量执行、逐条容错、side_effects 聚合 |
| `TestSideEffectPreservation` | ~7 | 副作用正确传递 |
| `TestDeepCollector` | ~10 | Collector 深度测试 |
| `TestDeepBatchProcessing` | ~15 | 大批量、混合成功/失败、乱序处理 |
| `TestDeepSideEffects` | ~25 | 副作用隔离、多次 extract 一致性 |
| `TestDeepBatchExtra` | ~16 | 额外批处理场景 |
| `TestFinalAcl` | ~18 | 端到端 ACL 流程 |

### 2.3 `test_redis_facade.py` — 103 tests

| 测试类 | 数量 | 覆盖范围 |
|--------|------|----------|
| `TestRedisClusterStateManager` | ~14 | SETNX 去重、Pipeline 限流、batch 操作 |
| `TestLocalDefense` | ~14 | local_blacklist/rate_limit、TTL 行为 |
| `TestDoubleBufferSync` | ~6 | 双缓冲 swap、sync 流程 |
| `TestDeepSETNX` | ~6 | 幂等性深度测试 |
| `TestDeepPipeline` | ~14 | Pipeline 结果索引、乱序、唯一性 |
| `TestDeepLocalDefense` | ~9 | 本地防线压力测试 |
| `TestDeepDoubleBuffer` | ~17 | 双缓冲溢出、多次 swap、数据完整性 |
| `TestExtraSETNX` | ~7 | 特殊 trace_id 格式 |
| `TestExtraPipeline` | ~5 | 不同窗口/限流参数 |
| `TestExtraLocalDefense` | ~7 | 1000 IP 并发限流 |
| `TestExtraDoubleBuffer` | ~9 | 缓冲处理中的追加/弹出 |
| `TestFinalRedis` | ~14 | 全量 Redis 操作集成 |
| `TestFinalRedis2` | ~8 | 最终回归验证 |

### 2.4 `test_engine.py` — 118 tests

| 测试类 | 数量 | 覆盖范围 |
|--------|------|----------|
| `TestEngineNormalPath` | ~20 | process_log、emit_alert、route_to_dlq |
| `TestFailSecure` | ~22 | CircuitBreaker 降级、本地防线 |
| `TestBatchAndDLQ` | ~35 | 批队列、背压、DLQ 格式 |
| `TestSupplementaryEngine` | ~25 | 补充引擎测试 |
| `TestDeepFailSecure` | ~16 | Fail-Secure 深度覆盖 |
| `TestDeepDLQ` | ~10 | DLQ 深度测试 |
| `TestDeepConcurrency` | ~10 | 并发处理 |
| `TestDeepKeywordAndAlert` | ~15 | 关键词刷新、告警链路 |
| `TestDeepEngineExtra` | ~30 | 引擎集成深度 |
| `TestFinalEngine` | ~20 | 全链路端到端 |

### 2.5 `test_train_pipeline.py` — 80 tests

| 测试类 | 数量 | 覆盖范围 |
|--------|------|----------|
| `TestProcessRowPurifier` | ~16 | 行级清洗、关键词匹配 |
| `TestPipelineOrchestration` | ~16 | ProcessPool 编排 |
| `TestPipelineEdgeCases` | ~7 | 空数据、特殊字符 |
| `TestDeepPurifier` | ~14 | Purifier 深度测试 |
| `TestDeepPipelineIntegration` | ~12 | 管道集成测试 |
| `TestDeepEdgeCases` | ~9 | 边缘场景深度覆盖 |
| `TestDeepPipelineExtra` | ~6 | 额外管道测试 |

---

## 3. 运行测试

### 3.1 全量运行

```bash
# 运行所有 427 个测试
python -m pytest tests/ -v

# 并行运行（加速）
python -m pytest tests/ -v -n auto
```

### 3.2 按模块运行

```bash
python -m pytest tests/test_preprocessor.py -v
python -m pytest tests/test_acl_bootstrap.py -v
python -m pytest tests/test_redis_facade.py -v
python -m pytest tests/test_engine.py -v
python -m pytest tests/test_train_pipeline.py -v
```

### 3.3 按标记/名称筛选

```bash
# 运行特定测试类
python -m pytest tests/test_engine.py::TestFailSecure -v

# 运行特定测试方法
python -m pytest tests/test_engine.py::TestFailSecure::test_circuit_breaker_error_triggers_fail_secure -v

# 按名称模式筛选
python -m pytest tests/ -k "duplicate" -v
```

### 3.4 CI 模式

```bash
# JUnit XML 报告
python -m pytest tests/ --junitxml=report.xml

# 覆盖率
python -m pytest tests/ --cov=. --cov-report=html --cov-report=term
```

---

## 4. 测试编写规范

### 4.1 命名约定
- **测试类**：`Test<ModuleName>` / `TestDeep<Area>` / `TestFinal<Module>`
- **测试方法**：`test_<what>_<condition>_<expected>`
- 示例：`test_trace_id_different_body_produces_different_hash`

### 4.2 测试结构 (AAA 模式)
```python
def test_example(self):
    # Arrange
    raw = {"client_ip": "1.2.3.4", ...}
    
    # Act
    result = transform_raw_log(raw)
    
    # Assert
    assert result["trace_id"] is not None
    assert len(result["trace_id"]) == 32
```

### 4.3 Mock 使用
```python
from unittest.mock import patch, AsyncMock, MagicMock

# Mock Redis
with patch('redis.asyncio.from_url', return_value=MockRedis()):
    mgr = RedisClusterStateManager("redis://localhost")
    result = await mgr.is_duplicate_and_add("trace-123")

# Mock Kafka（在 engine 测试中）
engine.producer = AsyncMock()
```

### 4.4 添加新测试

1. 确定测试类型（浅层/深度/边界/集成）
2. 在对应文件的合适位置添加测试类或方法
3. 确保每个断言覆盖一个明确的行为
4. 运行全量测试保证无回归

---

## 5. 当前测试状态

| 模块 | 测试数 | 状态 |
|------|--------|------|
| preprocessor | 99 | ✅ 100% pass |
| acl_bootstrap | 100 | ✅ 100% pass |
| akto_adapter | 14 | ✅ 100% pass |
| akto_integration | 114 | ✅ 100% pass |
| full_integration | 100 | ✅ 100% pass |
| **合计** | **427** | **0 fail / 0 error / 0 skip** |

---

## 6. 回归检查清单

每次代码变更后，必须验证：
- [ ] `python -m pytest tests/ -v` 全部通过
- [ ] 新增函数有对应的单元测试
- [ ] 修改的函数对应的测试仍通过或已更新
- [ ] 异常路径有显式测试覆盖
- [ ] 无新增 pytest warning
