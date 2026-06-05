# AIWAF-Stream

> 异步流式 Web 应用防火墙引擎 | 高吞吐 · 零信任指纹 · Fail-Secure

[![Tests](https://img.shields.io/badge/tests-500%20passed-brightgreen)](tests/)
[![Python](https://img.shields.io/badge/python-3.12-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

---

## 核心特性

- **零信任指纹**: SHA256(MD5(Body)) 确定性 trace_id，端到端可追溯
- **进程池隔离**: 核心安全逻辑运行在子进程，主进程异步非阻塞
- **异步熔断 + Fail-Secure**: Redis 不可用时自动降级到本地 TTL 缓存
- **双缓冲写回**: Fail-Secure 阻断 IP 通过双缓冲异步同步回 Redis
- **微批调度**: 自适应批量聚合 (≤50 条/批)，兼顾吞吐与延迟
- **500 测试用例**: 100% 通过率，覆盖正常路径 + 边缘 + 异常 + 集成

---

## 架构

```
Kafka Input → preprocessor → AIWAFStreamEngine
                                ├─ RedisStateFacade (CircuitBreaker)
                                ├─ ProcessPool (ACL batch)
                                ├─ Local Fail-Secure (TTLCache)
                                └─ Kafka Output (Alert / DLQ)
```

详细架构请参阅 [设计文档](docs/design.md)。

---

## 快速开始

```bash
# 安装
pip install -r requirements.txt

# 运行测试
python -m pytest tests/ -v

# 结果：500 passed
```

```python
from engine import AIWAFStreamEngine
from redis_facade import RedisClusterStateManager
from preprocessor import transform_raw_log

async def main():
    state_mgr = RedisClusterStateManager("redis://localhost:6379")
    engine = AIWAFStreamEngine(settings, state_mgr, "model.joblib")
    await engine.start()

    raw = {"client_ip": "1.2.3.4", "timestamp": 1717623456.789, "uri_path": "/api/data"}
    await engine.process_log(transform_raw_log(raw))
```

---

## 文档

| 文档 | 内容 |
|------|------|
| [design.md](docs/design.md) | 架构设计、数据流、模块设计 |
| [development.md](docs/development.md) | 开发规范、模块详解、编码指南 |
| [testing.md](docs/testing.md) | 测试策略、500 用例覆盖详情 |
| [deployment.md](docs/deployment.md) | 环境依赖、部署配置、容量规划 |
| [usage.md](docs/usage.md) | API 参考、典型场景、集成示例 |
| [troubleshooting.md](docs/troubleshooting.md) | 常见问题、诊断命令、故障恢复 |

---

## 项目结构

```
aiwaf_stream/
├── preprocessor.py          # 预处理引擎
├── acl_bootstrap.py         # 运行时防腐层 (ACL)
├── redis_facade.py          # Redis 状态管理 + Fail-Secure
├── engine.py                # 异步流式检测引擎
├── train_pipeline.py        # 离线训练管道
├── asyncbreaker.py          # 异步熔断器
├── aiwaf/core/              # WAF 核心 mock 模块
├── tests/                   # 500 测试用例
└── docs/                    # 完整文档
```

---

## 测试覆盖

| 模块 | 测试数 |
|------|--------|
| preprocessor | 99 |
| acl_bootstrap | 100 |
| redis_facade | 103 |
| engine | 118 |
| train_pipeline | 80 |
| **合计** | **500** ✅ |

---

## 依赖

- Python ≥ 3.10
- Redis ≥ 6.0 (Cluster 模式)
- Kafka ≥ 2.8
- orjson, aiokafka, cachetools, prometheus-client, joblib

---

## 许可证

MIT
