# AIWAF-Stream

> 异步流式 Web 应用防火墙引擎 | Kafka 消费 · 零信任指纹 · Fail-Secure · AI 异常检测

[![Tests](https://img.shields.io/badge/tests-427%20passed-brightgreen)](tests/)
[![Python](https://img.shields.io/badge/python-3.12-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

---

## 核心特性

- **Kafka 流式消费**：从 `akto.api.logs` 消费 Akto 流量数据
- **16 项检测能力**：关键词 + 速率限制 + AI 异常检测 + 请求头验证 + UUID 篡改 + 地理围栏 + 蜜罐 + 路径清单
- **关键词自学习**：运行时自动学习恶意关键词，写入 Redis 形成闭环
- **AI 异常检测**：IsolationForest 训练 + 预测，检测未知攻击
- **Fail-Secure 降级**：Redis 不可用时自动切到本地内存防线 + 熔断器
- **路径清单**：从 Kafka 流量自动构建 URL 模板，替代框架路由
- **79 项可配置**：YAML + 环境变量 + Redis 运行时覆盖 + 7 个检测模式全局开关
- **427 测试用例**：100% 通过率，覆盖正常路径 + 边缘 + 异常 + 集成

---

## 架构

```
aiwaf/
  core/               ← 检测策略库（22 模块，纯逻辑，可复用）
    ip_keyword.py        关键词策略 + 自学习
    malicious_context.py 恶意上下文判定（6 指标）
    path_manifest.py      路径清单（从流量自动构建）
    header_validation.py  请求头验证
    anomaly.py            AI 异常检测（IsolationForest）
    stream_trainer.py     批量训练器
    ...                   蜜罐/UUID/GeoIP/方法验证/...
  stream/              ← 流式运行时框架（8 模块）
    engine.py             主引擎（Kafka 消费 + 检测编排 + 告警输出）
    redis_facade.py       Redis 状态管理 + Fail-Secure 降级
    acl_bootstrap.py      子进程隔离层（ProcessPoolExecutor）
    akto_adapter.py       Akto JSON 适配层
    preprocessor.py       预处理（trace_id + query 拆分 + body 截断）
    config.py             配置加载（YAML + 环境变量）
    config_override.py    Redis 运行时配置覆盖
    asyncbreaker.py       熔断器封装
```

---

## 数据流

```
Kafka: akto.api.logs (JSON)
  │
  ├─ akto_adapter.parse_akto_json_message()
  ├─ preprocessor.transform_raw_log()
  ├─ engine.process_log()
  │   ├─ Path Manifest 记录
  │   ├─ 请求头验证
  │   ├─ UUID 篡改检测
  │   ├─ 地理围栏 (GeoIP)
  │   ├─ Redis 速率限制
  │   ├─ 关键词策略检测 (子进程)
  │   └─ AI 异常检测 (IsolationForest)
  │
  └─ Kafka: akto.aiwaf.alerts (14 字段 JSON)
      Kafka: akto.aiwaf.dlq (死信)
```

---

## 快速开始

```bash
# 1. 安装依赖
pip install -r requirements.txt

# 2. 配置
cp config.example.yaml config.yaml
vim config.yaml

# 3. 启动
python -c "
from aiwaf.stream.config import Settings
from aiwaf.stream.redis_facade import RedisClusterStateManager, RedisStateFacade
from aiwaf.stream.engine import AIWAFStreamEngine
import asyncio

settings = Settings.from_env()
state_mgr = RedisClusterStateManager(settings.redis_cluster_url)
engine = AIWAFStreamEngine(settings, state_mgr, '/path/to/model.pkl')

asyncio.run(engine.run())
"
```

---

## 配置

支持三种方式，优先级：环境变量 > YAML > 默认值

```yaml
# config.yaml
redis_cluster_url: "redis://localhost:6379"
kafka_brokers: "localhost:9092"
rate_limit_max_requests: 100
auto_block_enabled: true
```

运行时通过 Redis 覆盖（25 项可覆盖）：

```bash
redis-cli SET aiwaf:config:rate_limit_max_requests 200
redis-cli SET aiwaf:config:auto_block_enabled false
```

---

## 检测规则

| Rule | Severity | 触发条件 |
|---|---|---|
| `Local_Blacklist_Block` | HIGH | Redis 不可用时，IP 在本地黑名单 |
| `Local_RateLimit_Block` | HIGH | Redis 不可用时，本地速率超限 |
| `RateLimitFlood` | MEDIUM | Redis 速率限制检测到洪泛 |
| `KeywordBlock:*` | HIGH | 关键词策略匹配（探测路径/学习关键词/固有恶意） |
| `HeaderBlock:*` | HIGH | 请求头异常（爬虫UA/缺失必需头） |
| `UUIDTamper:*` | HIGH | UUID 格式篡改 |
| `GeoBlock:*` | MEDIUM | 地理围栏拦截 |

---

## 测试

```bash
python -m pytest tests/ -q
# 427 passed
```
