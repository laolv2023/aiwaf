# AIWAF-Stream 开发文档

> 版本: 2.0 | 最后更新: 2026-06-28

---

## 1. 项目结构

```
aiwaf/
  core/               ← 检测策略库（22 模块，纯逻辑，可复用）
    ip_keyword.py        关键词策略
    malicious_context.py 恶意上下文判定
    path_manifest.py      路径清单
    header_validation.py  请求头验证
    anomaly.py            AI 异常检测
    stream_trainer.py     批量训练器
    rate_limit.py         速率限制
    uuid_tamper.py        UUID 篡改
    honeypot.py           蜜罐检测
    method_validation.py  方法验证
    geo_policy.py         地理围栏
    geoip.py              GeoIP
    exemptions.py         路径豁免
    constants.py          常量
    block_responses.py    响应格式
    training.py           训练辅助
    training_features.py  特征提取
    rust_backend.py       Rust 后端适配
    model_artifacts.py    模型元数据
    model_security.py     模型安全
    model_serialization.py 模型序列化
  stream/              ← 流式运行时框架（8 模块）
    engine.py            主引擎
    redis_facade.py      Redis 状态管理 + Fail-Secure
    acl_bootstrap.py     子进程隔离
    akto_adapter.py      Akto 适配
    preprocessor.py      预处理
    config.py            配置加载
    config_override.py   Redis 配置覆盖
    asyncbreaker.py      熔断器
scripts/
  verify_akto_logs.py   验证脚本
tests/                  ← 427 测试用例
  test_akto_adapter.py     14 用例
  test_akto_integration.py 114 用例
  test_preprocessor.py     99 用例
  test_acl_bootstrap.py   100 用例
  test_full_integration.py 100 用例
  test_engine.py          118 用例（已有，含旧结构测试）
  test_redis_facade.py    103 用例（已有）
  test_integration.py     1381 行（已有）
  test_cross_comparison.py 894 行（已有，需更新路径）
docs/                   ← 文档
```

---

## 2. 模块开发指南

### 2.1 添加新的检测模块

1. 在 `aiwaf/core/` 下创建新模块（纯逻辑，无 I/O 依赖）
2. 在 `aiwaf/stream/engine.py` 的 `process_log()` 中集成调用
3. 在 `aiwaf/stream/config.py` 中添加配置项
4. 在 `config.example.yaml` 中添加配置模板
5. 在 `tests/test_full_integration.py` 中添加测试用例

### 2.2 修改检测逻辑

检测逻辑在 `aiwaf/core/` 中，不依赖 Kafka/Redis。修改后运行：

```bash
python -m pytest tests/test_full_integration.py tests/test_preprocessor.py tests/test_acl_bootstrap.py -q
```

### 2.3 修改流式运行时

运行时逻辑在 `aiwaf/stream/` 中。修改后运行：

```bash
python -m pytest tests/test_akto_integration.py tests/test_full_integration.py -q
```

---

## 3. 代码规范

### 3.1 层次依赖

```
aiwaf.stream → aiwaf.core （单向依赖，core 不反向 import stream）
```

### 3.2 错误处理

- 所有 `_emit_alert` 调用必须 `try/except`
- 所有 Redis 操作通过 `CircuitBreaker` 上下文管理器
- 子进程异常包装为 `ItemErrorResult`，不传播到主进程
- `process_log` 中的检测异常不中断消费循环

### 3.3 配置

- 新配置项添加到 `config.py` 的 `Settings` dataclass
- 同步添加到 `from_env()` 的 `env_map`
- 同步添加到 `config.example.yaml`
- 可覆盖的项添加到 `config_override.py` 的 `_OVERRIDABLE_KEYS`
- 测试中更新 `MockSettings`

---

## 4. 测试

```bash
# 全量测试
python -m pytest tests/ -q

# 核心测试（不含旧结构测试）
python -m pytest tests/test_full_integration.py tests/test_akto_integration.py \
  tests/test_preprocessor.py tests/test_acl_bootstrap.py tests/test_akto_adapter.py -q
# 427 passed
```

### 测试覆盖

| 文件 | 用例数 | 覆盖 |
|---|---|---|
| test_akto_adapter.py | 14 | 字段映射/类型转换/边界条件 |
| test_akto_integration.py | 114 | 消费循环/DLQ/告警/severity |
| test_preprocessor.py | 99 | trace_id/query/body 截断 |
| test_acl_bootstrap.py | 100 | 子进程批量执行/容错 |
| test_full_integration.py | 100 | 端到端/config_override/path_manifest/stream_trainer |

---

## 5. 调试

### 5.1 验证脚本

```bash
KAFKA_BROKERS=localhost:9092 python scripts/verify_akto_logs.py
```

### 5.2 单元调试

```python
from aiwaf.stream.akto_adapter import parse_akto_json_message
from aiwaf.stream.preprocessor import transform_raw_log
import orjson

msg = {"path": "/api/test", "method": "GET", "ip": "1.2.3.4", "statusCode": "200", "time": "1000"}
raw_log = parse_akto_json_message(orjson.dumps(msg).decode())
std_log = transform_raw_log(raw_log)
print(std_log)
```

---

## 6. 相关文档

- [检测能力详解](detection_capabilities.md)
- [检测模式实现机制](detection_implementation.md)
- [设计文档](design.md)
- [部署与配置](deployment.md)
- [测试文档](testing.md)
- [排障指南](troubleshooting.md)
