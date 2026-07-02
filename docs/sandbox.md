# AIWAF-Stream 基准测试沙箱使用指南

> 版本: 1.0 | 最后更新: 2026-06-28
> 脚本: `scripts/sandbox.py`

---

## 1. 概述

AIWAF-Stream 基准测试沙箱用于验证 AIWAF 流式引擎的检测能力和误报控制能力。

**工作原理**：将 12 种攻击模式 + 1 种正常流量模式转换为 Akto Kafka 消息格式，注入 `akto.api.logs` Topic，然后从 `akto.aiwaf.alerts` Topic 收集告警，统计检测率和误报率。

```
                    scripts/sandbox.py
                         │
          ┌──────────────┼──────────────┐
          ▼              ▼              ▼
    攻击消息生成     正常消息生成    告警收集
    (12 种模式)     (浏览器流量)    (akto.aiwaf.alerts)
          │              │              ▲
          ▼              ▼              │
    ┌─────────────────────────┐    ┌────┴────┐
    │  Kafka: akto.api.logs   │    │ AIWAF   │
    │  (注入流量消息)          │───▶│ Engine  │
    └─────────────────────────┘    └─────────┘
                                          │
                                   ┌──────┴──────┐
                                   │ Kafka:      │
                                   │ akto.aiwaf. │
                                   │ alerts      │
                                   └─────────────┘
```

与官方仓库 Sandbox 的关键区别：

| 维度 | 官方 Sandbox | 流式版 Sandbox |
|---|---|---|
| 测试方式 | HTTP 请求 → AIWAF 代理 → 403/200 响应 | Kafka 消息 → AIWAF 消费 → 告警 JSON |
| 靶机依赖 | 需要启动 OWASP Juice Shop 容器 | 无需靶机（直接构造 Akto 消息） |
| 统计指标 | HTTP 403/429 = 拦截率 | 告警 JSON 数量 = 检测率 |
| 框架对比 | Django vs Flask vs FastAPI 三套 | 无框架（流式版本无框架依赖） |

---

## 2. 环境准备

### 2.1 依赖

```bash
pip install aiokafka orjson
```

### 2.2 外部服务

需要运行中的 Kafka 和 Redis，以及正在运行的 AIWAF 引擎。

**快速启动（Docker）**：

```bash
# 启动 Kafka + Redis
docker run -d --name kafka -p 9092:9092 \
  -e KAFKA_NODE_ID=1 \
  -e KAFKA_PROCESS_ROLES=broker,controller \
  -e KAFKA_LISTENERS=PLAINTEXT://:9092 \
  -e KAFKA_ADVERTISED_LISTENERS=PLAINTEXT://localhost:9092 \
  -e KAFKA_CONTROLLER_QUORUM_VOTERS=1@localhost:9092 \
  -e KAFKA_CONTROLLER_LISTENER_NAMES=CONTROLLER \
  -e KAFKA_INTER_BROKER_LISTENER_NAME=PLAINTEXT \
  -e KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR=1 \
  -e CLUSTER_ID=MkU3OEVBNTcwNTJENDM2Qk \
  apache/kafka:latest

docker run -d --name redis -p 6379:6379 redis:7

# 创建 Topic
docker exec kafka /opt/kafka/bin/kafka-topics.sh \
  --bootstrap-server localhost:9092 --create \
  --topic akto.api.logs --partitions 1 --replication-factor 1
docker exec kafka /opt/kafka/bin/kafka-topics.sh \
  --bootstrap-server localhost:9092 --create \
  --topic akto.aiwaf.alerts --partitions 1 --replication-factor 1
```

### 2.3 启动 AIWAF 引擎

```bash
# 配置（最小配置）
cat > config.yaml << 'EOF'
redis_cluster_url: "redis://localhost:6379"
kafka_brokers: "localhost:9092"
EOF

# 启动引擎
python -c "
import asyncio
from aiwaf.stream.config import Settings
from aiwaf.stream.redis_facade import RedisClusterStateManager
from aiwaf.stream.engine import AIWAFStreamEngine

async def main():
    settings = Settings.from_env()
    state_mgr = RedisClusterStateManager(settings.redis_cluster_url)
    engine = AIWAFStreamEngine(settings, state_mgr, '')
    await engine.run()

asyncio.run(main())
" &
```

### 2.4 环境变量

| 变量 | 默认值 | 说明 |
|---|---|---|
| `KAFKA_BROKERS` | `localhost:9092` | Kafka broker 地址 |
| `KAFKA_INPUT_TOPIC` | `akto.api.logs` | 输入 Topic（注入流量） |
| `KAFKA_ALERT_TOPIC` | `akto.aiwaf.alerts` | 告警 Topic（收集结果） |

---

## 3. 运行测试

### 3.1 全量测试（推荐）

```bash
python scripts/sandbox.py --mode all
```

执行正常流量 + 全部 12 种攻击，输出检测率和误报率。

### 3.2 仅攻击测试

```bash
python scripts/sandbox.py --mode attacks
```

只执行 12 种攻击模式，统计检测率。

### 3.3 仅正常流量测试

```bash
python scripts/sandbox.py --mode normal
```

只执行正常流量，验证不误杀。

---

## 4. 12 种攻击模式详解

### 4.1 暴力破解 (brute_force)

| 属性 | 值 |
|---|---|
| **消息数** | 50 |
| **源 IP** | `203.0.113.1` |
| **路径** | `/rest/user/login` (POST) |
| **状态码** | 401 |
| **内容** | 50 个不同邮箱 `admin0~49@example.com` + 固定密码 |
| **预期检测** | HeaderBlock（缺 Accept 头）+ RateLimitFlood（速率超限） |

### 4.2 凭证填充 (credential_stuffing)

| 属性 | 值 |
|---|---|
| **消息数** | 40 |
| **源 IP** | `203.0.113.2` |
| **路径** | `/rest/user/login` (POST) |
| **状态码** | 401 |
| **内容** | 4 组凭证 × 10 次重复（`admin@juice-sh.op`/`test@juice-sh.op` 等） |
| **预期检测** | HeaderBlock + RateLimitFlood |

### 4.3 路径探测 (path_probe)

| 属性 | 值 |
|---|---|
| **消息数** | 12 |
| **源 IP** | `203.0.113.3` |
| **路径** | `/admin.php`、`/.env`、`/.git/config`、`/../etc/passwd`、`/wp-login.php`、`/phpmyadmin`、`/config.php`、`/server-status`、`/actuator/env`、`/api/internal`、`/backup.zip`、`/.well-known/security.txt` |
| **状态码** | 404 |
| **预期检测** | KeywordBlock: Inherently suspicious: probe path（匹配 `PROBE_PATH_PATTERNS` 正则） |

### 4.4 可疑 Header (header_probe)

| 属性 | 值 |
|---|---|
| **消息数** | 1 |
| **源 IP** | `203.0.113.4` |
| **User-Agent** | `sqlmap/1.0` |
| **Accept** | （空） |
| **预期检测** | HeaderBlock: Suspicious user agent: Pattern: sqlmap |

### 4.5 Header 变体 (header_variations)

| 属性 | 值 |
|---|---|
| **消息数** | 5 |
| **源 IP** | `203.0.113.5` |
| **User-Agents** | `sqlmap/1.8`、`nikto/2.5.0`、`masscan/1.3`、`curl/7.88.1`、`python-requests/2.31.0` |
| **Accept** | （空） |
| **预期检测** | HeaderBlock: Suspicious user agent（匹配 `SUSPICIOUS_USER_AGENTS` 列表） |

### 4.6 突发流量 (burst)

| 属性 | 值 |
|---|---|
| **消息数** | 30 |
| **源 IP** | `203.0.113.6` |
| **路径** | `/` (GET) |
| **状态码** | 200 |
| **预期检测** | RateLimitFlood（同一 IP 在窗口内超过 `rate_limit_max_requests`） |

### 4.7 混合突发 (burst_mixed)

| 属性 | 值 |
|---|---|
| **消息数** | 40 |
| **源 IP** | `203.0.113.7` |
| **内容** | 交替：登录 POST（401）/ 产品 GET（200）/ 首页 GET（200） |
| **预期检测** | RateLimitFlood + HeaderBlock（POST 请求缺 Accept） |

### 4.8 方法探测 (method_probe)

| 属性 | 值 |
|---|---|
| **消息数** | 3 |
| **源 IP** | `203.0.113.8` |
| **方法** | PUT / DELETE / PATCH |
| **路径** | `/api/` |
| **状态码** | 405 |
| **预期检测** | 可能不触发（流式版本 MethodBlock 仅检查 GET→POST-only，不检查 PUT/DELETE/PATCH） |

### 4.9 查询注入 (query_injection)

| 属性 | 值 |
|---|---|
| **消息数** | 3 |
| **源 IP** | `203.0.113.9` |
| **路径** | `/rest/products/search?q=' OR 1=1--`、`<script>alert(1)</script>`、`';WAITFOR DELAY '0:0:3'--` |
| **状态码** | 200 |
| **预期检测** | KeywordBlock（`is_malicious_context` 检测到 SQLi/XSS 模式） |

### 4.10 OWASP Top 10 (owasp_top10)

| 属性 | 值 |
|---|---|
| **消息数** | 8 |
| **源 IP** | `203.0.113.10` |
| **内容** | SQL 注入、XSS、`.env` 探测、`.git` 探测、`/admin` 访问、目录遍历、凭证填充、SQL 注入登录 |
| **预期检测** | KeywordBlock + HeaderBlock（多种检测联合） |

### 4.11 超长路径 (long_path)

| 属性 | 值 |
|---|---|
| **消息数** | 1 |
| **源 IP** | `203.0.113.11` |
| **路径** | `/` + `a` × 2047（2048 字符路径） |
| **状态码** | 404 |
| **预期检测** | 可能不触发（流式版本无路径长度检测，但 `is_malicious_context` 可能因 404 + 异常路径触发） |

### 4.12 正常流量 (normal_traffic)

| 属性 | 值 |
|---|---|
| **消息数** | 40 |
| **源 IP** | `198.51.100.1` |
| **User-Agent** | `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120 Safari/537.36` |
| **Accept** | `text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8` |
| **路径** | `/`、`/rest/products`、`/rest/products/search?q=apple`、`/api/Products/1`（各 10 次） |
| **状态码** | 200 |
| **预期检测** | 0 告警（正常浏览器流量不应被检测） |

---

## 5. 输出格式

### 5.1 控制台输出

```
======================================================================
  AIWAF-Stream Sandbox — 基准测试
  Kafka: localhost:9092
  Input: akto.api.logs
  Alert: akto.aiwaf.alerts
  Mode:  all
======================================================================

[1/2] 正常流量测试（验证不误杀）...
  发送: 40, 告警: 0, 误报率: 0.0%

[2/2] 攻击流量测试（验证检测率）...
  brute_force                    发送:  50, 告警:  50, 检测率: 100.0%
  credential_stuffing             发送:  40, 告警:  40, 检测率: 100.0%
  path_probe                     发送:  12, 告警:  12, 检测率: 100.0%
  header_probe                   发送:   1, 告警:   1, 检测率: 100.0%
  header_variations              发送:   5, 告警:   5, 检测率: 100.0%
  burst                          发送:  30, 告警:   1, 检测率:   3.3%
  burst_mixed                    发送:  40, 告警:  14, 检测率:  35.0%
  method_probe                   发送:   3, 告警:   0, 检测率:   0.0%
  query_injection                发送:   3, 告警:   3, 检测率: 100.0%
  owasp_top10                    发送:   8, 告警:   8, 检测率: 100.0%
  long_path                      发送:   1, 告警:   0, 检测率:   0.0%

======================================================================
  汇总
======================================================================
  攻击检测率:   134/193 = 69.4%
  正常误报率:   0/40 = 0.0%

  结果已保存: sandbox_results_20260628_160000.json
```

### 5.2 JSON 报告文件

文件名：`sandbox_results_YYYYMMDD_HHMMSS.json`

```json
{
  "timestamp": "2026-06-28T16:00:00+00:00",
  "kafka_brokers": "localhost:9092",
  "input_topic": "akto.api.logs",
  "alert_topic": "akto.aiwaf.alerts",
  "results": [
    {"name": "normal_traffic", "sent": 40, "alerts": 0},
    {"name": "brute_force", "sent": 50, "alerts": 50},
    {"name": "credential_stuffing", "sent": 40, "alerts": 40},
    {"name": "path_probe", "sent": 12, "alerts": 12},
    {"name": "header_probe", "sent": 1, "alerts": 1},
    {"name": "header_variations", "sent": 5, "alerts": 5},
    {"name": "burst", "sent": 30, "alerts": 1},
    {"name": "burst_mixed", "sent": 40, "alerts": 14},
    {"name": "method_probe", "sent": 3, "alerts": 0},
    {"name": "query_injection", "sent": 3, "alerts": 3},
    {"name": "owasp_top10", "sent": 8, "alerts": 8},
    {"name": "long_path", "sent": 1, "alerts": 0}
  ],
  "summary": {
    "attack_detection_rate": "134/193 (69.4%)",
    "normal_false_positive_rate": "0/40 (0.0%)"
  }
}
```

---

## 6. 结果解读

### 6.1 检测率参考

| 攻击类型 | 预期检测率 | 说明 |
|---|---|---|
| 暴力破解 | 100% | 缺 Accept 头 → HeaderBlock（每条触发） |
| 凭证填充 | 100% | 同上 |
| 路径探测 | 100% | `.env`/`.git`/`.php` 等匹配 PROBE_PATH_PATTERNS |
| 可疑 Header | 100% | `sqlmap` 匹配 SUSPICIOUS_USER_AGENTS |
| Header 变体 | 100% | `curl`/`nikto`/`masscan` 等匹配 |
| 突发流量 | 低（~3%） | 仅 RateLimitFlood 触发（需超过 `rate_limit_max_requests`，默认 100） |
| 混合突发 | 中（~35%） | 部分 POST 请求缺 Accept 头 |
| 方法探测 | 0% | 流式版本不检测 PUT/DELETE/PATCH |
| 查询注入 | 100% | `is_malicious_context` 检测到 SQLi/XSS 模式 |
| OWASP Top10 | 100% | 多种检测联合触发 |
| 超长路径 | 0% | 无路径长度检测（可通过 `is_malicious_context` 间接检测） |

### 6.2 误报率参考

| 流量类型 | 预期误报率 | 说明 |
|---|---|---|
| 正常浏览器流量 | 0% | 有完整 UA + Accept + 状态码 200 |

### 6.3 常见问题

**检测率低于预期**：
- 确认 AIWAF 引擎已启动并正在消费 `akto.api.logs`
- 检查 Redis 是否可用（`redis-cli ping`）
- 确认 `akto.aiwaf.alerts` Topic 已创建

**误报率高于预期**：
- 检查 `header_required` 配置（内网场景设为空）
- 检查 `header_skip_ips` 配置（豁免内网 IP）
- 检查正常流量的 User-Agent 和 Accept 是否完整

**burst 检测率为 0**：
- 30 条消息可能未超过 `rate_limit_max_requests`（默认 100）
- 可通过 `redis-cli SET aiwaf:config:rate_limit_max_requests 10` 降低阈值

---

## 7. 自定义攻击模式

在 `scripts/sandbox.py` 中添加自定义攻击：

```python
def gen_custom_attack(ip: str = "203.0.113.99") -> List[Dict[str, Any]]:
    """自定义攻击"""
    return [
        make_akto_msg("/api/admin/delete-all", "POST", ip, "200",
                       request_body='{"confirm": true}',
                       user_agent="python-requests/2.31.0",
                       accept=""),
    ]

# 添加到 ATTACK_SUITE 列表
ATTACK_SUITE = [
    ...
    ("custom_attack", gen_custom_attack),
]
```

---

## 8. 与验证脚本的区别

| 维度 | `scripts/verify_akto_logs.py` | `scripts/sandbox.py` |
|---|---|---|
| **用途** | 连接真实 Kafka 验证管道 | 注入攻击流量测试检测能力 |
| **消息来源** | 真实 Akto 流量（被动消费） | 模拟攻击消息（主动注入） |
| **统计** | 打印每条消息处理结果 | 统计检测率 + 误报率 |
| **攻击覆盖** | 无（依赖真实流量） | 12 种攻击 + 正常流量 |
| **使用场景** | 部署后验证 | 开发/调优/基准测试 |

---

## 9. 相关文档

- [检测能力详解](detection_capabilities.md)
- [检测模式实现机制](detection_implementation.md)
- [部署与配置](deployment.md)
- [排障指南](troubleshooting.md)
