# AIWAF-Stream 检测能力详解

> 版本: 2.0 | 最后更新: 2026-06-28
> 来源: 全部内容基于代码实际逻辑，无推测。

---

## 检测流程总览

每条 Kafka 消息进入 `AIWAFStreamEngine.process_log()` 后，按以下顺序执行 16 项检测能力。任一检测命中即输出告警并终止后续检测（部分检测除外）。

```
process_log(std_log)
  │
  ├── 1. 路径清单记录 (PathManifest.record)
  ├── 2. 请求头验证 (evaluate_header_policy)
  ├── 3. 路径豁免检查 (header_skip_paths 前缀匹配)
  ├── 4. UUID 篡改检测 (is_malformed_uuid + record_uuid_signal)
  ├── 5. 地理围栏 (lookup_country_name + evaluate_geo_policy)
  │
  ├── Redis 操作 (is_duplicate_and_add + get_and_update_rate_limit)
  │   ├── Redis 可用 → 进入正常检测路径
  │   │   ├── 6. 请求去重 (SETNX)
  │   │   ├── 7. 速率限制 (Redis Sorted Set)
  │   │   └── → 微批处理 → ProcessPoolExecutor
  │   │       ├── 8. 速率限制判定 (evaluate_rate_limit)
  │   │       ├── 9. 关键词策略检测 (evaluate_keyword_policy)
  │   │       │   ├── 9a. 探测路径检测 (PROBE_PATH_PATTERNS)
  │   │       │   ├── 9b. 学习关键词匹配 (dynamic_keywords)
  │   │       │   └── 9c. 固有恶意模式匹配 (INHERENTLY_MALICIOUS_PATTERNS)
  │   │       └── 10. 关键词自学习 (is_malicious_context → learned_keywords)
  │   │
  │   └── Redis 不可用 (CircuitBreakerError) → Fail-Secure 降级
  │       ├── 11. 本地黑名单检测 (local_blacklist + _current_buffer + _backup_buffer)
  │       └── 12. 本地速率限制 (local_rate_limit 内存计数)
  │
  ├── 13. AI 异常检测 (IsolationForest — 批量训练时)
  ├── 14. HTTP 方法验证 (evaluate_method_policy — honeypot.py)
  ├── 15. 熔断器 (asyncbreaker.CircuitBreaker)
  └── 16. Fail-Secure 双缓冲写回 (background_sync_worker)
```

---

## 1. 路径清单 (Path Manifest)

**源码**: `aiwaf/core/path_manifest.py` → `PathManifest` 类

**触发位置**: `engine.py` `process_log()` 开头，每条消息都执行

**工作原理**:

每条流量到达后，调用 `PathManifest.record(path, method, status_code)` 记录。URL 先通过 `templify_path()` 转换为模板，再更新统计信息。

**模板化规则**（`templify_path` 函数，按优先级）:

| 优先级 | 匹配规则 | 正则 | 替换为 | 示例 |
|---|---|---|---|---|
| 1 | UUID | `^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$` | `{uuid}` | `550e8400-e29b-41d4-...` → `{uuid}` |
| 2 | JWT | `^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$` | `{jwt}` | `eyJhbGciOi...` → `{jwt}` |
| 3 | 纯整数 | `^\d+$` | `{id}` | `123` → `{id}` |
| 4 | 长十六进制 (≥16字符) | `^[0-9a-f]{16,}$` | `{hex}` | `a1b2c3d4e5f67890` → `{hex}` |
| 5 | Base64 (≥20字符) | `^[A-Za-z0-9+/]{20,}={0,2}$` | `{b64}` | `c3RhciB0cmF2ZWw...` → `{b64}` |
| 6 | 长随机串 (≥32字符) | `^(?=[A-Za-z0-9]{32,}$)(?=.*[a-z])(?=.*[A-Z])(?=.*\d).+$` | `{token}` | `aB3dE7fG9hI1jK3lM5nO7pQ9rS1tU3vW5xY7zA9` → `{token}` |
| 7 | 以上都不匹配 | — | 保持原值 | `users` → `users` |

**PathStats 数据结构**:

```python
@dataclass
class PathStats:
    template: str           # 模板路径
    total_count: int = 0    # 总访问次数
    ok_count: int = 0       # 2xx 响应数
    error_count: int = 0    # 4xx/5xx 响应数
    methods: Set[str]       # 观察到的 HTTP 方法集合
    last_seen: float = 0.0  # 最后访问时间戳

    @property
    def ok_ratio(self) -> float:
        return self.ok_count / max(self.total_count, 1)

    @property
    def is_known(self) -> bool:
        """路径是否被视为已知：至少 3 次访问且 2xx 比例 > 50%"""
        return self.total_count >= 3 and self.ok_ratio > 0.5
```

**path_exists 判定**: `templify_path(path)` → 查 `self._paths` → 返回 `stats.is_known`

**线程安全**: 所有方法使用 `threading.Lock` 保护（`process_log` 和 `_batch_dispatcher` 并发访问）

**配置项**: 无（内部逻辑）

**告警规则**: 无（路径清单不直接产生告警，供其他检测使用）

---

## 2. 请求头验证 (Header Validation)

**源码**: `aiwaf/core/header_validation.py` → `evaluate_header_policy()` 函数

**触发位置**: `engine.py` `process_log()` 中，Path Manifest 记录之后

**调用方式**:
```python
header_dec = evaluate_header_policy(
    environ,                    # WSGI 格式请求头
    method=std_log.get("method", "GET"),
    config_required_headers=required,    # 从 header_required 配置构建
    max_user_agent_length=self.settings.header_max_ua_length,
    max_accept_length=self.settings.header_max_accept_length,
    suspicious_user_agents=suspicious_ua,   # 自定义或默认
    legitimate_bots=legit_bots,             # 自定义或默认
)
```

**返回值**: `str`（拦截原因）或 `None`（放行）

**检测规则**（按执行顺序）:

| # | 规则 | 触发条件 | 返回值示例 |
|---|---|---|---|
| 1 | 头字节数超限 | `total_bytes > max_header_bytes` (默认 32768) | `"Header bytes exceed 32768"` |
| 2 | 头数量超限 | `header_count > max_header_count` (默认 100) | `"Header count exceeds 100"` |
| 3 | UA 过长 | `len(user_agent) > max_user_agent_length` (默认 500) | `"User-Agent longer than 500 chars"` |
| 4 | Accept 过长 | `len(accept_header) > max_accept_length` (默认 4096) | `"Accept header longer than 4096 chars"` |
| 5 | 必需头缺失 | 配置的 `header_required` 中任一缺失 | `"Missing required headers: accept"` |
| 6 | 可疑 User-Agent | 匹配 `SUSPICIOUS_USER_AGENTS` 列表 | `"Suspicious user agent: Pattern: okhttp"` |
| 7 | 可疑头组合 | 匹配 `SUSPICIOUS_COMBINATIONS` 列表 | `"Suspicious headers: Missing all browser-standard headers"` |
| 8 | 头质量分过低 | `_calculate_header_quality() < 3` | `"Low header quality score: 2"` |

**默认必需头**: `HTTP_USER_AGENT`, `HTTP_ACCEPT`

**默认可疑 UA 模式** (20 个):
```
bot, crawler, spider, scraper, curl, wget, python, java, node,
go-http, axios, okhttp, libwww, lwp-trivial, mechanize, requests, urllib,
httpie, postman, insomnia, ^$, mozilla/4.0$
```

**默认合法爬虫 UA** (16 个):
```
googlebot, bingbot, slurp, duckduckbot, baiduspider, yandexbot,
facebookexternalhit, twitterbot, linkedinbot, whatsapp, telegrambot,
applebot, pingdom, uptimerobot, statuscake, site24x7
```

**可疑头组合** (5 条):

| # | 条件 | 原因 |
|---|---|---|
| 1 | HTTP/2 + `mozilla/4.0` UA | HTTP/2 with old browser user agent |
| 2 | 有 UA 但无 Accept | User-Agent present but no Accept header |
| 3 | Accept=`*/*` 且无 Accept-Language/Accept-Encoding | Generic Accept header without language/encoding |
| 4 | 有 UA 但无 Accept-Language/Accept-Encoding/Connection | Missing all browser-standard headers |
| 5 | HTTP/1.0 + Chrome UA | Modern browser with HTTP/1.0 |

**头质量评分** (`_calculate_header_quality`):

| 因素 | 分值 |
|---|---|
| 有 User-Agent | +2 |
| 有 Accept | +2 |
| 有 Accept-Language | +1 |
| 有 Accept-Encoding | +1 |
| 有 Connection | +1 |
| 有 Cache-Control | +1 |
| 同时有 Accept-Language + Accept-Encoding | +1 |
| Connection = keep-alive | +1 |
| Accept 含 text/html + application/xml | +1 |
| **满分** | **10** |

低于 3 分判定为低质量。

**告警规则**: `HeaderBlock:{reason}`，severity = HIGH

**配置项**:

| 配置项 | 默认值 | 说明 |
|---|---|---|
| `header_required` | `"user-agent,accept"` | 必需头（逗号分隔，空=不检查） |
| `header_skip_ips` | `""` | 豁免 IP/CIDR |
| `header_skip_paths` | `""` | 豁免路径前缀 |
| `header_max_ua_length` | `500` | UA 最大长度 |
| `header_max_accept_length` | `4096` | Accept 最大长度 |
| `header_suspicious_ua` | `""` | 自定义可疑 UA（空=用默认 20 个） |
| `header_legitimate_bots` | `""` | 合法爬虫（空=用默认 16 个） |

---

## 3. 路径豁免 (Path Exemption)

**源码**: `engine.py` `process_log()` 中的 `header_skip_paths` 前缀匹配

**触发位置**: 请求头验证之后、UUID 检测之前

**工作原理**:

```python
skip_paths = [s.strip() for s in self.settings.header_skip_paths.split(",") if s.strip()]
for prefix in skip_paths:
    if uri_path.startswith(prefix):
        return  # 豁免路径跳过所有后续检测
```

配置 `header_skip_paths: "/api/health,/api/metrics"` 后，以这两个前缀开头的路径跳过所有检测。

**运行时动态管理**（`redis_facade.py` 中 `RedisStateFacade`）:

| 方法 | Redis 操作 | 说明 |
|---|---|---|
| `add_exempt_path(path)` | `SADD aiwaf:exempt:paths {path}` | 添加豁免路径 |
| `remove_exempt_path(path)` | `SREM aiwaf:exempt:paths {path}` | 移除豁免路径 |
| `get_exempt_paths()` | `SMEMBERS aiwaf:exempt:paths` | 获取所有豁免路径 |

**告警规则**: 无（豁免即放行）

**配置项**: `header_skip_paths`

---

## 4. UUID 篡改检测 (UUID Tamper)

**源码**: `aiwaf/core/uuid_tamper.py` → `is_malformed_uuid()` + `record_uuid_signal()`

**触发位置**: `engine.py` `process_log()` 中，路径豁免之后

**检测逻辑**:

```python
for seg in path_segments:
    # 只检查 36 字符且含至少 4 个 dash 的段（UUID 格式特征）
    if len(seg) == 36 and seg.count('-') >= 4 and is_malformed_uuid(seg):
        record_uuid_signal(ip, "malformed_uuid")
        await self._emit_alert(std_log, "UUIDTamper:malformed_uuid")
        break
```

**`is_malformed_uuid(value)` 逻辑**:
1. `is_valid_uuid(value)` 检查：
   - 非空
   - 匹配 `^[a-f0-9\-]{36}$`
   - `uuid.UUID(text)` 解析成功
2. `is_malformed_uuid = not is_valid_uuid`

**前置过滤**: 仅当路径段长度 = 36 且含 ≥4 个 dash 时才检查，避免对普通路径段误报。

**`record_uuid_signal(subject, signal)` 评分系统**:

```python
# 默认配置
{
    "enabled": True,
    "window_seconds": 60,       # 评分窗口
    "block_threshold": 5,       # 拉黑阈值
    "malformed_weight": 5,      # 篡改信号权重
    "not_found_weight": 1,      # 404 信号权重
    "success_decay": 2,         # 成功请求衰减
}
```

| 信号 | 权重 | 说明 |
|---|---|---|
| `malformed` | +5 | UUID 格式错误 |
| `not_found` | +1 | 合法 UUID 但 404 |
| `success` | -2 | 合法 UUID 且 <400 |

窗口内累计分数 ≥5 → `blocked: True`

**告警规则**: `UUIDTamper:malformed_uuid`，severity = HIGH

**配置项**: `honeypot_ttl`（UUID 评分窗口 TTL，默认 300 秒）

---

## 5. 地理围栏 (GeoIP)

**源码**: `aiwaf/core/geoip.py` → `lookup_country_name()` + `aiwaf/core/geo_policy.py` → `evaluate_geo_policy()`

**触发位置**: `engine.py` `process_log()` 中，UUID 检测之后

**前置条件**: `self.settings.geoip_db_path` 非空且 `GEOIP_AVAILABLE` 为 True

**`lookup_country_name(ip, db_path)` 逻辑**:
1. 加载 MaxMind GeoIP2 数据库
2. `reader.city(ip)` → 获取国家名
3. 结果缓存（cache_prefix + cache_seconds 参数）
4. 失败时返回 None

**`evaluate_geo_policy(country, allow_countries, block_countries, dynamic_blocked)` 逻辑**:

```python
# 国家代码统一大写
normalized_country = country.strip().upper()

if allow_countries:  # 白名单模式
    blocked = normalized_country not in allow
else:  # 黑名单模式
    blocked = normalized_country in block_countries or normalized_country in dynamic_blocked
```

- 白名单模式：只允许列表中的国家，其余全部拦截
- 黑名单模式：只拦截列表中的国家，其余全部放行

**告警规则**: `GeoBlock:{country}`，severity = MEDIUM

**配置项**:

| 配置项 | 默认值 | 说明 |
|---|---|---|
| `geoip_db_path` | `""` | MaxMind GeoIP2 DB 路径（空=禁用） |
| `geo_block_countries` | `""` | 阻止国家（逗号分隔，如 `CN,RU,KP`） |
| `geo_allow_countries` | `""` | 允许国家（逗号分隔，空=全部允许） |

---

## 6. 请求去重 (Deduplication)

**源码**: `aiwaf/stream/redis_facade.py` → `RedisClusterStateManager.is_duplicate_and_add()`

**触发位置**: `engine.py` `process_log()` 中，Redis 操作阶段

**工作原理**:

```python
async def is_duplicate_and_add(self, trace_id, is_retry=False, retry_count=0):
    idem_key = f"aiwaf:idem:{trace_id}:retry_{retry_count}" if is_retry else f"aiwaf:idem:{trace_id}"
    result = await self.redis.set(idem_key, "1", nx=True, ex=self.dedup_ttl)
    return result is None  # None = 已存在（重复）
```

- Redis `SET NX EX`：原子操作，键不存在则设置并返回 OK，已存在返回 None
- `dedup_ttl` 默认 86400 秒（24 小时）
- 命中重复 → 直接 `return`（不产生告警，静默丢弃）

**告警规则**: 无（重复请求静默丢弃）

**配置项**: `dedup_ttl`（默认 86400 秒）

---

## 7. 速率限制 (Redis)

**源码**: `aiwaf/stream/redis_facade.py` → `RedisClusterStateManager.get_and_update_rate_limit()`

**触发位置**: `engine.py` `process_log()` 中，去重之后

**Redis 数据结构**: Sorted Set (`aiwaf:rl:{ip}`)

```python
key = f"aiwaf:rl:{ip}"
score = event_time * 1000 + random.randint(0, 999)  # 毫秒时间戳 + 随机偏移
member = f"{score}-{random.getrandbits(32)}"

pipe = self.redis.pipeline(transaction=False)
pipe.zremrangebyscore(key, 0, (event_time - window) * 1000)  # 删除窗口外的旧记录
pipe.zremrangebyrank(key, 0, -(max_req * 2 + 1))              # 防止 Sorted Set 无限增长
pipe.zadd(key, {member: score})                                # 添加当前请求
pipe.expire(key, window * 2)                                   # 设置过期时间
pipe.zrange(key, 0, -1, withscores=True)                       # 获取窗口内所有时间戳
```

**告警规则**: 无（速率限制数据供 `evaluate_rate_limit` 判定）

**配置项**:

| 配置项 | 默认值 | 说明 |
|---|---|---|
| `rate_limit_window` | `60` | 窗口大小（秒） |
| `rate_limit_max_requests` | `100` | 窗口内最大请求数 |

---

## 8. 速率限制判定 (Rate Limit Evaluation)

**源码**: `aiwaf/core/rate_limit.py` → `evaluate_rate_limit()`

**触发位置**: `aiwaf/stream/acl_bootstrap.py` → `run_core_logic_batch_isolated()` 中（子进程内）

**判定逻辑**:

```python
def evaluate_rate_limit(timestamps, now, window_seconds, max_requests, flood_threshold):
    window = max(float(window_seconds), 1.0)
    trimmed = [t for t in list(timestamps or []) if now - t < window]
    trimmed.append(now)
    count = len(trimmed)

    action = ALLOW
    if count > int(flood_threshold):       # 默认 150
        action = FLOOD_BLOCK               # → 403 + 黑名单
    elif count > int(max_requests):        # 默认 100
        action = THROTTLE                  # → 429

    return RateLimitDecision(action=action, count=count, timestamps=trimmed)
```

| 条件 | action | 后果 |
|---|---|---|
| `count ≤ max_requests` (100) | `allow` | 放行 |
| `max_requests < count ≤ flood_threshold` | `throttle` | 限流（429） |
| `count > flood_threshold` (150) | `flood_block` | 告警 + IP 拉黑 |

**告警规则**: `RateLimitFlood`（仅 `flood_block` 时），severity = MEDIUM

**配置项**:

| 配置项 | 默认值 | 说明 |
|---|---|---|
| `rate_limit_window` | `60` | 窗口大小（秒） |
| `rate_limit_max_requests` | `100` | 软限制（throttle 阈值） |
| `rate_limit_flood_threshold` | `150` | 硬限制（flood_block 阈值） |

---

## 9. 关键词策略检测 (Keyword Policy)

**源码**: `aiwaf/core/ip_keyword.py` → `evaluate_keyword_policy()`

**触发位置**: `aiwaf/stream/acl_bootstrap.py` → `run_core_logic_batch_isolated()` 中（子进程内）

**输入参数**:

| 参数 | 来源 | 说明 |
|---|---|---|
| `path` | `std_log["uri_path"]` | 请求路径 |
| `query_keys` | `std_log["query_keys"]` | query 参数名列表 |
| `path_exists` | `PathManifest.path_exists()` | 路径是否已知合法 |
| `static_keywords` | `STATIC_KW` (9 个) | 静态恶意关键词 |
| `dynamic_keywords` | Redis `get_top_keywords(500)` | 自学习关键词 |
| `legitimate_keywords` | `DEFAULT_LEGITIMATE_KEYWORDS` (~170 个) | 合法关键词白名单 |
| `is_malicious_context` | 闭包函数 | 恶意上下文判定 |

**检测流程**:

### 9a. 探测路径检测 (PROBE_PATH_PATTERNS)

仅在 `path_exists = False` 时检查。

```python
PROBE_PATH_PATTERNS = (
    r"(^|/)\.(env|git|htaccess|htpasswd)(/|$)",   # 敏感文件
    r"\.(php|asp|aspx|jsp|cgi|bak|sql)(/|$)",       # 脚本文件扩展名
    r"xmlrpc\.php",                                   # WordPress xmlrpc
)
```

命中 → 返回 `"Keyword block: Inherently suspicious: probe path"`

### 9b. 学习关键词匹配

将 `static_keywords` 和 `dynamic_keywords` 合并，过滤掉 `exempt_keywords` 和 `legitimate_keywords`（当 `path_exists=True` 且 `is_malicious_context(kw)=False` 时）。

遍历路径段，如果段在可疑关键词集合中 → 返回 `"Keyword block: Learned keyword: {seg}"`

### 9c. 固有恶意模式匹配 (INHERENTLY_MALICIOUS_PATTERNS)

仅在 `path_exists = False` 时检查。

```python
INHERENTLY_MALICIOUS_PATTERNS = (
    "hack", "exploit", "attack", "malicious",
    "evil", "backdoor", "inject", "xss",
)
```

如果路径段不在 `legitimate_keywords` 中，且 `is_malicious_context(seg)=True` 或段包含 `INHERENTLY_MALICIOUS_PATTERNS` 中的模式 → 返回 `"Keyword block: Inherently suspicious: {seg}"`

### 已知路径增强检测 (VERY_STRONG_ATTACK_PATTERNS)

当 `path_exists = True` 时，需要额外满足以下条件之一才拦截：

```python
VERY_STRONG_ATTACK_PATTERNS = (
    "union+select", "drop+table", "<script", "javascript:",
    "onload=", "onerror=", "${", "{{", "eval(",
)
```

条件 1（满足 ≥2 项）：
- `"../" in raw_path`
- `"..\\" in raw_path`
- `query_keys 含 "cmd"/"exec"/"system"`
- `raw_path.count("%") > 5`
- `segments 中 >2 个在 malicious_keywords 中`

条件 2：路径包含 `VERY_STRONG_ATTACK_PATTERNS` 中的任一模式

**告警规则**: `KeywordBlock:{block_reason}`，severity = HIGH

**配置项**:

| 配置项 | 默认值 | 说明 |
|---|---|---|
| `keyword_refresh_interval` | `10` | 关键词缓存刷新间隔（秒） |
| `keyword_top_n` | `500` | 从 Redis 获取 Top N 关键词 |
| `keyword_min_segment_length` | `3` | 路径段最小长度（短于此不参与检测） |

---

## 10. 关键词自学习 (Keyword Self-Learning)

**源码**: `aiwaf/core/malicious_context.py` → `is_malicious_context()` + `aiwaf/core/ip_keyword.py` → `learned_keywords`

**触发位置**: `aiwaf/stream/acl_bootstrap.py` → `run_core_logic_batch_isolated()` 中（子进程内）

**学习流程**:

```python
# ip_keyword.py evaluate_keyword_policy 中
if keyword_learning_enabled and not path_exists:
    for seg in segments:
        if (
            seg not in legitimate_keywords
            and seg not in exempt_keywords
            and is_malicious_context(seg)
        ):
            learned_keywords.append(seg)
```

**`is_malicious_context(path, keyword, status, static_keywords)` 判定（6 个指标）**:

| # | 指标 | 判定条件 |
|---|---|---|
| 1 | 多静态关键词 | `len([seg for seg in segments if seg in static_keywords]) > 1` |
| 2 | 常见攻击模式 | 路径含 `../`、`..\\`、`.env`、`wp-admin`、`phpmyadmin`、`config`、`backup`、`database`、`mysql`、`passwd`、`shadow`、`xmlrpc`、`shell`、`cmd`、`exec`、`eval`、`system` 中任一 |
| 3 | SQL注入/XSS/模板注入 | 路径含 `union+select`、`drop+table`、`<script`、`javascript:`、`${`、`{{`、`onload=`、`onerror=`、`file://`、`http://` 中任一 |
| 4 | 多次目录遍历 | `path.count("../") > 1` 或 `path.count("..\\") > 1` |
| 5 | 编码攻击 | 路径含 `%2e%2e`、`%252e`、`%c0%ae`、`%3c%73%63%72%69%70%74` 中任一 |
| 6 | 404+异常路径 | `status == "404"` 且（路径长度 > 50 或 `/` 数量 > 10 或含 `<>{}` 等特殊字符） |

任一指标为 True → 返回 True

**学习闭环**:

```
请求到达 → is_malicious_context(seg) = True → learned_keywords.append(seg)
    ↓
ProcessLocalCollector.extract_and_clear() → side_effects['learned_keywords']
    ↓
engine.py: self.facade.batch_add_keywords(kws) → Redis ZINCRBY aiwaf:keywords
    ↓
下次 keyword_refresh_worker: get_top_keywords(500) → 读取到新关键词
    ↓
新请求匹配 → KeywordBlock: Learned keyword: {seg}
```

**告警规则**: 无（学习本身不产生告警，学习到的关键词参与 9b 检测）

**配置项**:

| 配置项 | 默认值 | 说明 |
|---|---|---|
| `auto_learn_keywords` | `True` | 是否自动学习关键词（False=只告警不学习） |
| `keyword_refresh_interval` | `10` | 缓存刷新间隔 |
| `keyword_top_n` | `500` | Top N 关键词数 |

---

## 11. 本地黑名单检测 (Fail-Secure Local Blacklist)

**源码**: `aiwaf/stream/redis_facade.py` → `local_blacklist` + `_current_buffer` + `_backup_buffer`

**触发位置**: `engine.py` `process_log()` 中，`CircuitBreakerError` 异常处理分支

**触发条件**: Redis 不可用（`asyncbreaker.CircuitBreakerError`）

**检测逻辑**:

```python
if ip in local_blacklist or ip in _current_buffer or ip in _backup_buffer:
    await self._emit_alert(std_log, "Local_Blacklist_Block")
    return
```

**数据结构**:

| 变量 | 类型 | 说明 |
|---|---|---|
| `local_blacklist` | `cachetools.TTLCache` (maxsize=10000, ttl=300) | 本地黑名单 IP → True |
| `_current_buffer` | `collections.deque` (maxlen=10000) | 当前缓冲（待同步 IP） |
| `_backup_buffer` | `collections.deque` (maxlen=10000) | 备份缓冲（同步失败积累的 IP） |

**告警规则**: `Local_Blacklist_Block`，severity = HIGH

**配置项**:

| 配置项 | 默认值 | 说明 |
|---|---|---|
| `local_blacklist_ttl` | `300` | 本地黑名单 TTL（秒） |
| `max_pending_ips` | `10000` | 缓冲队列最大长度 |
| `auto_block_enabled` | `True` | 是否自动拉黑（False=只告警不拉黑） |

---

## 12. 本地速率限制 (Fail-Secure Local Rate Limit)

**源码**: `aiwaf/stream/redis_facade.py` → `local_rate_limit`

**触发位置**: `engine.py` `process_log()` 中，本地黑名单检测之后

**触发条件**: Redis 不可用 且 IP 不在本地黑名单中

**检测逻辑**:

```python
local_rate_limit[ip] = local_rate_limit.get(ip, 0) + 1
if local_rate_limit[ip] > self.settings.fail_secure_local_limit:
    if auto_block_enabled:
        local_blacklist[ip] = True
        _backup_buffer.append(ip)
    await self._emit_alert(std_log, "Local_RateLimit_Block")
    return
```

**数据结构**: `local_rate_limit` = `cachetools.TTLCache` (maxsize=10000, ttl=60)

**告警规则**: `Local_RateLimit_Block`，severity = HIGH

**配置项**:

| 配置项 | 默认值 | 说明 |
|---|---|---|
| `fail_secure_local_limit` | `50` | 本地速率限制阈值 |
| `local_rate_limit_ttl` | `60` | 本地速率限制 TTL（秒） |
| `auto_block_enabled` | `True` | 是否自动拉黑 |

---

## 13. AI 异常检测 (IsolationForest)

**源码**: `aiwaf/core/stream_trainer.py` → `train_from_records()` + `predict_with_model()` + `aiwaf/core/anomaly.py`

**触发位置**: 批量训练时（非实时检测管道）

**训练流程** (`train_from_records`):

1. 构建 `train_records`（含 ip, path_len, path_lower, resp_time, status, timestamp, status_idx, kw_check, total_404）
2. 关键词学习：对 4xx/5xx 状态的请求提取路径段，通过 `is_malicious_context` 判定后加入 `tokens` Counter
3. 过滤关键词：出现 ≥2 次 + 长度 ≥4 + 不在白名单 + 在恶意上下文中 → `keyword_store.add_keyword(kw, cnt)`
4. IsolationForest 训练（需 `parsed_count >= min_ai_logs`，默认 50）

**特征向量** (`build_feature_vector` in `anomaly.py`):

| 特征 | 说明 |
|---|---|
| `path_len` | 路径长度 |
| `kw_hits` | 恶意关键词命中数 |
| `resp_time` | 响应时间 |
| `status_idx` | 状态码索引（200→0, 403→1, 404→2, 500→3, 其他→-1） |
| `burst` | 10 秒内同 IP 请求次数 |
| `total_404` | 同 IP 历史 404 次数 |

**IsolationForest 参数**:

| 参数 | 默认值 | 配置项 |
|---|---|---|
| `n_estimators` | `100` | `ai_n_estimators` |
| `max_samples` | `"auto"` | `ai_max_samples` |
| `contamination` | `0.05` | `ai_contamination` |
| `min_ai_logs` | `50` | `ai_min_logs` |

**异常 IP 检测**:

训练数据中 `IsolationForest.predict(features) == -1` 的 IP → 加入 `blocked_ips` 列表 → `BlacklistManager.block(ip, "AI anomaly detection")`

**告警规则**: 无直接告警（异常 IP 写入 Redis 黑名单，后续请求触发 `Local_Blacklist_Block` 或 Redis 黑名单检测）

**配置项**:

| 配置项 | 默认值 | 说明 |
|---|---|---|
| `ai_min_logs` | `50` | 最小训练样本数 |
| `ai_contamination` | `0.05` | 污染率（异常比例） |
| `ai_n_estimators` | `100` | 树数 |
| `ai_max_samples` | `"auto"` | 最大样本数 |

---

## 14. HTTP 方法验证 (Method Validation)

**源码**: `aiwaf/core/method_validation.py` → `evaluate_method_policy()` + `aiwaf/core/honeypot.py` → `should_block_get_to_post_only_endpoint()`

**说明**: 模块已移植到 `aiwaf/core/`，但在 `engine.py` 的 `process_log()` 中**未直接调用**。`honeypot.py` 的 `should_block_get_to_post_only_endpoint` 被 `method_validation.py` 调用。

**检测逻辑**:

```python
def evaluate_method_policy(*, method, path, accepts_get=False, accepts_post=False, accepts_method=False):
    method_u = method.upper()
    if method_u == "GET":
        if should_block_get_to_post_only_endpoint(path, accepts_get=False):
            return MethodDecision(action="block", reason=f"GET to obvious POST-only endpoint: {path}")
        return MethodDecision(action="allow")
    if method_u == "POST":
        return MethodDecision(action="allow")
    if method_u in {"HEAD", "OPTIONS"}:
        return MethodDecision(action="allow")
    if not accepts_method:
        return MethodDecision(action="block", reason=f"{method_u} to view that doesn't support it: {path}")
    return MethodDecision(action="allow")
```

**POST-only 端点后缀** (`OBVIOUS_POST_ONLY_SUFFIXES`):

```python
("/create/", "/submit/", "/upload/", "/delete/", "/process/")
```

GET 请求到以上后缀的路径 → 拦截

**集成状态**: 模块就绪，`engine.py` 中未调用（可在未来集成）

**告警规则**: `MethodBlock:{reason}`（未集成，预留）

---

## 15. 熔断器 (Circuit Breaker)

**源码**: `aiwaf/stream/asyncbreaker.py` → `CircuitBreaker` 类

**触发位置**: `aiwaf/stream/redis_facade.py` 中所有 Redis 操作的 `async with redis_breaker.context()` 包装

**工作原理**:

```python
redis_breaker = asyncbreaker.CircuitBreaker(
    fail_max=settings.circuit_breaker_fail_max,       # 默认 5
    timeout_duration=datetime.timedelta(seconds=settings.circuit_breaker_timeout)  # 默认 60
)
```

| 状态 | 条件 | 行为 |
|---|---|---|
| Closed（正常） | Redis 操作成功 | 请求正常通过 |
| Open（跳闸） | 连续失败 ≥ `fail_max` (5) 次 | 抛出 `CircuitBreakerError` → 进入 Fail-Secure |
| Half-Open（探测） | Open 状态持续 `timeout_duration` (60s) 后 | 尝试一次 Redis 操作，成功→Closed，失败→Open |

**影响**: `CircuitBreakerError` 被捕获后，`process_log` 进入 Fail-Secure 分支（检测 #11 + #12）

**告警规则**: 无（熔断器不直接产生告警，触发 Fail-Secure 检测）

**配置项**:

| 配置项 | 默认值 | 说明 |
|---|---|---|
| `circuit_breaker_fail_max` | `5` | 连续失败多少次跳闸 |
| `circuit_breaker_timeout` | `60` | 恢复探测间隔（秒） |

---

## 16. Fail-Secure 双缓冲写回 (Background Sync Worker)

**源码**: `aiwaf/stream/redis_facade.py` → `background_sync_worker()`

**触发位置**: `engine.py` `start()` 中作为后台 Task 启动

**工作原理**:

```python
async def background_sync_worker(state_mgr, cancel_event, sync_interval=5):
    global _current_buffer, _backup_buffer
    while not (cancel_event and cancel_event.is_set()):
        await asyncio.sleep(sync_interval)  # 默认 5 秒
        if not _current_buffer:
            continue

        # 交换 buffer
        _current_buffer, _backup_buffer = _backup_buffer, _current_buffer
        ips_to_sync = list(_backup_buffer)  # 取待同步数据

        try:
            await state_mgr.batch_block_ips([(ip, "Local_FailSecure") for ip in ips_to_sync])
            _backup_buffer.clear()  # 同步成功，清空
        except Exception:
            # 同步失败，数据保留在 _backup_buffer，合并 _current_buffer
            while _current_buffer:
                _backup_buffer.append(_current_buffer.popleft())
            if len(_backup_buffer) >= MAX_PENDING_IPS:
                METRIC_PENDING_OVERFLOW.inc()
```

**双缓冲机制**:

| 缓冲 | 用途 |
|---|---|
| `_current_buffer` | 接收新的 Fail-Secure 拉黑 IP（`process_log` 写入） |
| `_backup_buffer` | 待同步到 Redis 的 IP（Worker 读取） |

交换后 Worker 从 `_backup_buffer` 同步到 Redis，新 IP 继续写入 `_current_buffer`，无锁并发。

**告警规则**: 无（后台同步，不产生告警）

**配置项**:

| 配置项 | 默认值 | 说明 |
|---|---|---|
| `background_sync_interval` | `5` | 同步间隔（秒） |
| `max_pending_ips` | `10000` | 缓冲队列最大长度 |

---

## 告警规则汇总

| Rule ID | Severity | 检测能力 # | 触发条件 |
|---|---|---|---|
| `Local_Blacklist_Block` | HIGH | 11 | Redis 不可用时，IP 在本地黑名单/缓冲区 |
| `Local_RateLimit_Block` | HIGH | 12 | Redis 不可用时，本地速率超限 |
| `RateLimitFlood` | MEDIUM | 8 | Redis 速率限制检测到洪泛（>flood_threshold） |
| `KeywordBlock:Keyword block: Inherently suspicious: probe path` | HIGH | 9a | URL 匹配探测路径正则 |
| `KeywordBlock:Keyword block: Learned keyword: {seg}` | HIGH | 9b | URL 段匹配自学习关键词 |
| `KeywordBlock:Keyword block: Inherently suspicious: {seg}` | HIGH | 9c | URL 段匹配固有恶意模式 |
| `HeaderBlock:{reason}` | HIGH | 2 | 请求头异常 |
| `UUIDTamper:malformed_uuid` | HIGH | 4 | UUID 格式篡改 |
| `GeoBlock:{country}` | MEDIUM | 5 | 地理围栏拦截 |

**severity 判定逻辑** (`_classify_severity`):

```python
rule_lower = (rule or "").lower()
if "flood" in rule_lower or "ratelimit" in rule_lower: return "MEDIUM"
if "keyword" in rule_lower: return "HIGH"
if "blacklist" in rule_lower: return "HIGH"
if "header" in rule_lower: return "HIGH"
if "uuid" in rule_lower: return "HIGH"
if "geo" in rule_lower: return "MEDIUM"
return "LOW"
```

---

## 配置项汇总

全部 72 项配置项，支持 YAML 文件 + 环境变量 + Redis 运行时覆盖（25 项可覆盖）。

详见 `config.example.yaml`。
