# AIWAF-Stream 检测模式实现机制与配置方式

> 版本: 2.0 | 最后更新: 2026-06-28
> 来源: 全部内容基于代码实际逻辑，无推测。

---

## 1. 请求头验证 (HeaderBlock)

### 源码位置

- **模块**: `aiwaf/core/header_validation.py` — 函数 `evaluate_header_policy()`
- **调用点**: `aiwaf/stream/engine.py` `process_log()` L200-231

### 实现机制

`evaluate_header_policy()` 接收 WSGI 格式的 environ dict，按以下顺序执行 6 层检查，任一层命中即返回字符串（block reason），全部通过返回 `None`（允许）。

**第 1 层：Header 字节总量检查**

```python
total_bytes = 0
for key, value in environ.items():
    if not (key.startswith('HTTP_') or key in {'CONTENT_TYPE', 'CONTENT_LENGTH'}):
        continue
    total_bytes += len(key) + len(value_str)
    if total_bytes > max_header_bytes:  # 默认 32768 (32KB)
        return f"Header bytes exceed {max_header_bytes}"
```

**第 2 层：Header 数量检查**

```python
if header_count > max_header_count:  # 默认 100
    return f"Header count exceeds {max_header_count}"
```

**第 3 层：必需头缺失检查**

```python
required_headers = resolve_required_headers(config_required_headers, method)
# 默认: ['HTTP_USER_AGENT', 'HTTP_ACCEPT']
missing = [h for h in required_headers if not environ.get(h)]
if missing:
    return f"Missing required headers: {', '.join(missing)}"
```

**第 4 层：User-Agent 可疑模式检查** (`_check_user_agent()`)

按优先级检查：
1. UA 长度超过 `max_user_agent_length`（默认 500）
2. UA 匹配合法爬虫列表（`LEGITIMATE_BOTS`）→ 跳过
3. UA 匹配可疑模式列表（`SUSPICIOUS_USER_AGENTS`）→ 拦截
4. UA 长度 < 10 → 拦截

**内置可疑 UA 模式**（21 个正则）:
```
bot, crawler, spider, scraper, curl, wget, python, java, node,
go-http, axios, okhttp, libwww, lwp-trivial, mechanize, requests, urllib,
httpie, postman, insomnia, ^$ (空UA), mozilla/4.0$
```

**内置合法爬虫**（16 个正则）:
```
googlebot, bingbot, slurp, duckduckbot, baiduspider, yandexbot,
facebookexternalhit, twitterbot, linkedinbot, whatsapp, telegrambot,
applebot, pingdom, uptimerobot, statuscake, site24x7
```

**第 5 层：可疑头组合检查** (`_check_header_combinations()`)

5 个组合规则：

| # | 条件 | reason |
|---|---|---|
| 1 | HTTP/2 + `mozilla/4.0` UA | `HTTP/2 with old browser user agent` |
| 2 | 有 UA 但无 Accept | `User-Agent present but no Accept header` |
| 3 | Accept=`*/*` 但无 Accept-Language/Accept-Encoding | `Generic Accept header without language/encoding` |
| 4 | 有 UA 但无 Accept-Language/Accept-Encoding/Connection | `Missing all browser-standard headers` |
| 5 | HTTP/1.0 + Chrome UA | `Modern browser with HTTP/1.0` |

**第 6 层：Header 质量评分** (`_calculate_header_quality()`)

评分规则（满分 9，阈值 3）：

| 头存在 | 分数 |
|---|---|
| `HTTP_USER_AGENT` | +2 |
| `HTTP_ACCEPT` | +2 |
| 每个 `BROWSER_HEADERS` 头 | +1（最多 +4） |
| Accept-Language + Accept-Encoding 同时存在 | +1 |
| Connection = keep-alive | +1 |
| Accept 含 text/html + application/xml | +1 |

```python
if required_headers and quality_score < actual_min_score:  # 默认 3
    return f"Low header quality score: {quality_score}"
```

### 配置方式

| 配置项 | YAML 字段 | 环境变量 | 默认值 | Redis 覆盖 |
|---|---|---|---|---|
| 必需头列表 | `header_required` | `HEADER_REQUIRED` | `"user-agent,accept"` | ✅ `aiwaf:config:header_required` |
| 豁免 IP/CIDR | `header_skip_ips` | `HEADER_SKIP_IPS` | `""` | ✅ |
| 豁免路径前缀 | `header_skip_paths` | `HEADER_SKIP_PATHS` | `""` | ✅ |
| UA 最大长度 | `header_max_ua_length` | `HEADER_MAX_UA_LENGTH` | `500` | ✅ |
| Accept 最大长度 | `header_max_accept_length` | `HEADER_MAX_ACCEPT_LENGTH` | `4096` | ✅ |
| 自定义可疑 UA | `header_suspicious_ua` | `HEADER_SUSPICIOUS_UA` | `""` (用内置) | ✅ |
| 自定义合法爬虫 | `header_legitimate_bots` | `HEADER_LEGITIMATE_BOTS` | `""` (用内置) | ✅ |

**YAML 示例**:
```yaml
header_required: "user-agent,accept"
header_skip_ips: "192.168.0.0/16,10.0.0.0/8"
header_skip_paths: "/api/health,/api/metrics"
header_suspicious_ua: "okhttp,retrofit,feign"
```

**Redis 运行时覆盖**:
```bash
redis-cli SET aiwaf:config:header_required ""           # 禁用必需头检查
redis-cli SET aiwaf:config:header_skip_ips "192.168.0.0/16"
redis-cli DEL aiwaf:config:header_skip_ips               # 恢复默认
```

**豁免逻辑** (`_should_check_header()` in engine.py):
- IP 匹配 CIDR（`ipaddress.ip_network(cidr, strict=False)`）→ 跳过
- 路径前缀匹配 → 跳过

---

## 2. 路径清单 (PathManifest)

### 源码位置

- **模块**: `aiwaf/core/path_manifest.py` — 类 `PathManifest` + 函数 `templify_path()`
- **调用点**: `engine.py` `process_log()` L178 (record) + `_batch_dispatcher` L151 (get_all_templates)

### 实现机制

**URL 模板化** (`templify_path()`)

将 URL 路径分段，按优先级替换动态段为占位符：

| 优先级 | 正则 | 匹配示例 | 替换为 |
|---|---|---|---|
| 1 | `^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$` | `550e8400-e29b-41d4-a716-446655440000` | `{uuid}` |
| 2 | `^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$` | `eyJhbGciOi...` | `{jwt}` |
| 3 | `^\d+$` | `123` | `{id}` |
| 4 | `^[0-9a-f]{16,}$` | `a1b2c3d4e5f67890` | `{hex}` |
| 5 | `^[A-Za-z0-9+/]{20,}={0,2}$` | `c2VjcmV0VG9rZW4=` | `{b64}` |
| 6 | `^(?=[A-Za-z0-9]{32,}$)(?=.*[a-z])(?=.*[A-Z])(?=.*\d).+$` | `AbCd1234...` (32+字符) | `{token}` |

**记录与判定** (`PathManifest` 类，线程安全 `threading.Lock`)

```python
@dataclass
class PathStats:
    template: str
    total_count: int = 0
    ok_count: int = 0       # 2xx
    error_count: int = 0     # 4xx/5xx
    methods: Set[str] = field(default_factory=set)
    last_seen: float = 0.0

    @property
    def is_known(self) -> bool:
        return self.total_count >= 3 and self.ok_ratio > 0.5
```

- `record(path, method, status_code)`: 模板化 → 累加计数 → 记录 2xx/4xx
- `path_exists(path)`: 模板化 → 查 `_paths` → 返回 `stats.is_known`
- `get_all_templates()`: 返回所有模板列表（传给子进程用于 `path_exists` 判定）

### 配置方式

路径清单本身无配置项。其行为完全由流量数据驱动。

**Redis 持久化**（`RedisPathManifestStore`）:

| Redis Key | 类型 | 内容 |
|---|---|---|
| `aiwaf:paths:{template}` | Hash | `total`, `ok`, `error`, `last_seen` |
| `aiwaf:paths:{template}:methods` | Set | 允许的 HTTP 方法 |
| TTL | — | 7 天 (604800 秒) |

---

## 3. UUID 篡改检测 (UUIDTamper)

### 源码位置

- **模块**: `aiwaf/core/uuid_tamper.py` — 函数 `is_malformed_uuid()` + `record_uuid_signal()`
- **调用点**: `engine.py` `process_log()` L246-262

### 实现机制

**格式检查**:

```python
UUID_RE = re.compile(r"^[a-f0-9\-]{36}$")

def is_valid_uuid(value):
    if UUID_RE.match(text.lower()) is None:
        return False
    try:
        uuid.UUID(text)  # 严格解析
        return True
    except (ValueError, TypeError, AttributeError):
        return False

def is_malformed_uuid(value):
    if not value:
        return False
    return not is_valid_uuid(value)
```

**engine.py 集成**（仅检查 36 字符 + 4 dash 的段，避免误报）:

```python
for seg in uri_path.strip("/").split("/"):
    if len(seg) == 36 and seg.count('-') >= 4 and is_malformed_uuid(seg):
        record_uuid_signal(ip, "malformed_uuid")
        await self._emit_alert(std_log, "UUIDTamper:malformed_uuid")
        break
```

**评分系统** (`record_uuid_signal()`):

每个 IP 维护一个滑动窗口（60 秒）内的评分：

| 信号 | 权重 |
|---|---|
| `malformed` | +5 |
| `not_found` (404) | +1 |
| `success` (<400) | -2 |

```python
score = sum(d for _, d in events)
blocked = score >= 5  # block_threshold
```

### 配置方式

| 配置项 | YAML 字段 | 环境变量 | 默认值 | Redis 覆盖 |
|---|---|---|---|---|
| 蜜罐/UUID TTL | `honeypot_ttl` | `HONEYPOT_TTL` | `300` | ✅ |

UUID 评分参数使用内置默认值（`get_uuid_score_defaults()`）:
```python
{"window_seconds": 60, "block_threshold": 5, "malformed_weight": 5, "not_found_weight": 1, "success_decay": 2}
```

---

## 4. 地理围栏 (GeoBlock)

### 源码位置

- **模块**: `aiwaf/core/geoip.py` — 函数 `lookup_country_name()`
- **模块**: `aiwaf/core/geo_policy.py` — 函数 `evaluate_geo_policy()`
- **调用点**: `engine.py` `process_log()` L228-244

### 实现机制

**IP → 国家** (`lookup_country_name()`):

使用 MaxMind GeoIP2 数据库查询。`GEOIP_AVAILABLE` 标记是否安装了 `geoip2` 库。

**策略判定** (`evaluate_geo_policy()`):

```python
def evaluate_geo_policy(*, country, allow_countries, block_countries, dynamic_blocked):
    normalized_country = country.strip().upper()

    allow = normalize_country_list(allow_countries)
    block = normalize_country_list(block_countries)
    dynamic = normalize_country_list(dynamic_blocked)

    if allow:
        blocked = normalized_country not in allow  # 白名单模式
    else:
        blocked = normalized_country in block or normalized_country in dynamic  # 黑名单模式

    return GeoDecision(blocked, normalized_country, reason)
```

**两种模式**:
- **白名单模式**（`allow_countries` 非空）：只有列表中的国家允许访问
- **黑名单模式**（`allow_countries` 为空）：列表中的国家被阻止

**engine.py 集成**:

```python
if self.settings.geoip_db_path and GEOIP_AVAILABLE:
    country = lookup_country_name(ip, self.settings.geoip_db_path)
    if country:
        geo_dec = evaluate_geo_policy(
            country=country,
            allow_countries=set(s for s in self.settings.geo_allow_countries.split(",") if s),
            block_countries=set(s for s in self.settings.geo_block_countries.split(",") if s),
            dynamic_blocked=[],
        )
        if geo_dec.block:
            await self._emit_alert(std_log, f"GeoBlock:{country}")
            return  # 终止后续检测
```

### 配置方式

| 配置项 | YAML 字段 | 环境变量 | 默认值 | Redis 覆盖 |
|---|---|---|---|---|
| GeoIP 数据库路径 | `geoip_db_path` | `GEOIP_DB_PATH` | `""` (禁用) | ❌ |
| 阻止国家 | `geo_block_countries` | `GEO_BLOCK_COUNTRIES` | `""` | ✅ |
| 允许国家 | `geo_allow_countries` | `GEO_ALLOW_COUNTRIES` | `""` | ✅ |

**YAML 示例**:
```yaml
geoip_db_path: "/data/geoip2/GeoLite2-Country.mmdb"
geo_block_countries: "CN,RU,KP,IR"
# 或白名单模式:
# geo_allow_countries: "US,GB,DE,JP"
```

**Redis 运行时覆盖**:
```bash
redis-cli SET aiwaf:config:geo_block_countries "CN,RU"
```

---

## 5. 关键词策略检测 (KeywordBlock)

### 源码位置

- **模块**: `aiwaf/core/ip_keyword.py` — 函数 `evaluate_keyword_policy()`
- **调用点**: `aiwaf/stream/acl_bootstrap.py` `run_core_logic_batch_isolated()` L142-154（子进程中）

### 实现机制

`evaluate_keyword_policy()` 接收 11 个参数，执行 3 层检测：

**第 1 层：探测路径检测**（仅 `path_exists=False` 时执行）

```python
PROBE_PATH_PATTERNS = (
    r"(^|/)\.(env|git|htaccess|htpasswd)(/|$)",   # 敏感文件
    r"\.(php|asp|aspx|jsp|cgi|bak|sql)(/|$)",       # 脚本文件
    r"xmlrpc\.php",                                   # WordPress
)

if not path_exists:
    for pattern in PROBE_PATH_PATTERNS:
        if re.search(pattern, raw_path):
            return KeywordDecision(
                block_reason="Keyword block: Inherently suspicious: probe path",
                ...
            )
```

**第 2 层：学习关键词匹配**

```python
all_kw = set(static_keywords) | set(dynamic_keywords)
# 排除豁免关键词、合法关键词（path_exists 时）
suspicious_kw = all_kw - exempt_keywords

for seg in segments:
    if seg in suspicious_kw:
        # path_exists 时需要 very_strong 信号才拦截
        if path_exists:
            very_strong = [
                sum(["../" in raw_path, "..\\" in raw_path,
                     any(p in query_keys for p in ["cmd", "exec", "system"]),
                     raw_path.count("%") > 5,
                     len([s for s in segments if s in malicious_keywords]) > 2]) >= 2,
                any(pattern in raw_path for pattern in VERY_STRONG_ATTACK_PATTERNS),
            ]
            if not any(very_strong):
                continue
        return KeywordDecision(block_reason=f"Keyword block: Learned keyword: {seg}", ...)
```

**VERY_STRONG_ATTACK_PATTERNS**（9 个）:
```
union+select, drop+table, <script, javascript:, onload=, onerror=, ${, {{, eval(
```

**第 3 层：固有恶意模式匹配**

```python
INHERENTLY_MALICIOUS_PATTERNS = (
    "hack", "exploit", "attack", "malicious", "evil", "backdoor", "inject", "xss",
)

for seg in segments:
    if (not path_exists
        and seg not in legitimate_keywords
        and (is_malicious_context(seg) or any(p in seg for p in INHERENTLY_MALICIOUS_PATTERNS))):
        return KeywordDecision(block_reason=f"Keyword block: Inherently suspicious: {seg}", ...)
```

### 配置方式

| 配置项 | YAML 字段 | 环境变量 | 默认值 | Redis 覆盖 |
|---|---|---|---|---|
| 关键词刷新间隔 | `keyword_refresh_interval` | `KEYWORD_REFRESH_INTERVAL` | `10` | ✅ |
| Top N 关键词数 | `keyword_top_n` | `KEYWORD_TOP_N` | `500` | ✅ |
| 路径段最小长度 | `keyword_min_segment_length` | `KEYWORD_MIN_SEGMENT_LENGTH` | `3` | ✅ |
| 自动学习关键词 | `auto_learn_keywords` | `AUTO_LEARN_KEYWORDS` | `true` | ✅ |

**预定义常量**（代码内硬编码，不可配置）:

| 常量 | 值 | 来源 |
|---|---|---|
| `STATIC_KW` | `[".php", "xmlrpc", "wp-", ".env", ".git", ".bak", "conflg", "shell", "filemanager"]` | `malicious_context.py` |
| `INHERENTLY_MALICIOUS_PATTERNS` | `("hack", "exploit", "attack", "malicious", "evil", "backdoor", "inject", "xss")` | `ip_keyword.py` |
| `VERY_STRONG_ATTACK_PATTERNS` | `("union+select", "drop+table", "<script", "javascript:", "onload=", "onerror=", "${", "{{", "eval(")` | `ip_keyword.py` |
| `PROBE_PATH_PATTERNS` | 3 个正则 | `ip_keyword.py` |
| `DEFAULT_LEGITIMATE_KEYWORDS` | 100+ 个合法关键词 | `malicious_context.py` |

**Redis 关键词库**:

| Redis Key | 类型 | 内容 |
|---|---|---|
| `aiwaf:keywords` | Sorted Set | 关键词 → score（出现次数） |

**管理命令**:
```bash
# 查看关键词库
redis-cli ZREVRANGE aiwaf:keywords 0 9 WITHSCORES

# 删除误判关键词
redis-cli ZREM aiwaf:keywords shell

# 手动添加关键词
redis-cli ZADD aiwaf:keywords 100 admin
```

---

## 6. 关键词自学习 (malicious_context)

### 源码位置

- **模块**: `aiwaf/core/malicious_context.py` — 函数 `is_malicious_context()`
- **调用点**: `acl_bootstrap.py` `_ctx_fn()` 闭包 → 传给 `evaluate_keyword_policy(is_malicious_context=_ctx_fn)`

### 实现机制

`is_malicious_context()` 接收 4 个参数：`path`、`keyword`、`status`、`static_keywords`，检查 6 个恶意指标，任一命中返回 `True`：

| # | 指标 | 检查内容 |
|---|---|---|
| 1 | 多静态关键词命中 | `len([seg for seg in segments if seg in static_keywords]) > 1` |
| 2 | 常见攻击模式 | path 含 `../`, `..\\`, `.env`, `wp-admin`, `phpmyadmin`, `config`, `backup`, `database`, `mysql`, `passwd`, `shadow`, `xmlrpc`, `shell`, `cmd`, `exec`, `eval`, `system` |
| 3 | SQL注入/XSS/模板注入 | path 含 `union+select`, `drop+table`, `<script`, `javascript:`, `${`, `{{`, `onload=`, `onerror=`, `file://`, `http://` |
| 4 | 多次目录遍历 | `path.count("../") > 1` 或 `path.count("..\\") > 1` |
| 5 | 编码攻击 | path 含 `%2e%2e`, `%252e`, `%c0%ae`, `%3c%73%63%72%69%70%74`（`<script`的URL编码） |
| 6 | 404+异常路径 | status=404 且 (路径>50字符 或 `/`>10 个 或 含 `<>{}`$`` `) |

**自学习闭环**:

```
请求到达 → evaluate_keyword_policy(is_malicious_context=_ctx_fn)
  │
  ├── 路径段不在 legitimate_keywords 且 is_malicious_context(seg) == True
  │   → learned_keywords.append(seg)
  │
  └── learned_keywords → ProcessLocalCollector → side_effects
      → engine._batch_add_keywords() → Redis ZINCRBY aiwaf:keywords
      → 下次 get_top_keywords() 读取到新词 → dynamic_keywords
      → 形成闭环
```

### 配置方式

| 配置项 | YAML 字段 | 环境变量 | 默认值 | Redis 覆盖 |
|---|---|---|---|---|
| 自动学习关键词 | `auto_learn_keywords` | `AUTO_LEARN_KEYWORDS` | `true` | ✅ |

设为 `false` 时，`learned_keywords` 仍会被收集但不会写入 Redis。

---

## 7. 速率限制 (RateLimitFlood)

### 源码位置

- **模块**: `aiwaf/core/rate_limit.py` — 函数 `evaluate_rate_limit()`
- **模块**: `aiwaf/stream/redis_facade.py` — `RedisClusterStateManager.get_and_update_rate_limit()`
- **调用点**: `acl_bootstrap.py` L122-130（子进程判定） + `engine.py` L288-292（Redis 状态获取）

### 实现机制

**Redis 速率状态**（Sorted Set + 滑动窗口）:

```python
key = f"aiwaf:rl:{ip}"
score = event_time * 1000 + random.randint(0, 999)  # 防乱序

pipe = redis.pipeline()
pipe.zremrangebyscore(key, 0, (event_time - window) * 1000)  # 删除窗口外的
pipe.zremrangebyrank(key, 0, -(max_req * 2 + 1))               # 限制集合大小
pipe.zadd(key, {member: score})                                 # 添加当前请求
pipe.expire(key, window * 2)                                    # 过期
pipe.zrange(key, 0, -1, withscores=True)                        # 获取全部
```

**判定逻辑** (`evaluate_rate_limit()`):

```python
trimmed = [t for t in timestamps if now - t < window]
trimmed.append(now)
count = len(trimmed)

if count > flood_threshold:
    action = FLOOD_BLOCK    # → 403 + 拉黑
elif count > max_requests:
    action = THROTTLE       # → 429
else:
    action = ALLOW
```

### 配置方式

| 配置项 | YAML 字段 | 环境变量 | 默认值 | Redis 覆盖 |
|---|---|---|---|---|
| 窗口大小（秒） | `rate_limit_window` | `RATE_LIMIT_WINDOW` | `60` | ✅ |
| 窗口内最大请求数 | `rate_limit_max_requests` | `RATE_LIMIT_MAX_REQUESTS` | `100` | ✅ |
| 洪泛阈值 | `rate_limit_flood_threshold` | `RATE_LIMIT_FLOOD_THRESHOLD` | `150` | ✅ |

**Redis 运行时覆盖**:
```bash
redis-cli SET aiwaf:config:rate_limit_max_requests 200
redis-cli SET aiwaf:config:rate_limit_window 30
```

**Redis Key 结构**:

| Key | 类型 | TTL | 内容 |
|---|---|---|---|
| `aiwaf:rl:{ip}` | Sorted Set | `window * 2` 秒 | score=timestamp*1000+rand, member=score-rand |

---

## 8. 请求去重

### 源码位置

- **模块**: `aiwaf/stream/redis_facade.py` — `RedisClusterStateManager.is_duplicate_and_add()`

### 实现机制

```python
async def is_duplicate_and_add(self, trace_id, is_retry=False, retry_count=0):
    idem_key = f"aiwaf:idem:{trace_id}:retry_{retry_count}" if is_retry else f"aiwaf:idem:{trace_id}"
    result = await self.redis.set(idem_key, "1", nx=True, ex=self.dedup_ttl)
    return result is None  # None=已存在(重复), True=新建(非重复)
```

### 配置方式

| 配置项 | YAML 字段 | 环境变量 | 默认值 | Redis 覆盖 |
|---|---|---|---|---|
| 去重记录 TTL | `dedup_ttl` | `DEDUP_TTL` | `86400` (24h) | ❌ |

**Redis Key**: `aiwaf:idem:{trace_id}` (SET NX, TTL=86400s)

---

## 9. IP 黑名单

### 源码位置

- **模块**: `aiwaf/stream/redis_facade.py` — `batch_block_ips()`

### 实现机制

```python
async def batch_block_ips(self, ips_reasons):
    pipe = self.redis.pipeline()
    for ip, reason in ips_reasons:
        pipe.set(f"aiwaf:blk:{ip}", reason, ex=self.blacklist_ttl)
    await pipe.execute()
```

### 配置方式

| 配置项 | YAML 字段 | 环境变量 | 默认值 | Redis 覆盖 |
|---|---|---|---|---|
| 黑名单 TTL | `blacklist_ttl` | `BLACKLIST_TTL` | `3600` (1h) | ❌ |
| 自动拉黑开关 | `auto_block_enabled` | `AUTO_BLOCK_ENABLED` | `true` | ✅ |

**Redis Key**: `aiwaf:blk:{ip}` → reason 字符串

**管理命令**:
```bash
redis-cli SET aiwaf:blk:10.0.1.5 "RateLimitFlood"     # 手动拉黑
redis-cli DEL aiwaf:blk:10.0.1.5                        # 手动解封
redis-cli KEYS "aiwaf:blk:*"                            # 查看所有黑名单
```

---

## 10. Fail-Secure 降级

### 源码位置

- **模块**: `aiwaf/stream/redis_facade.py` — `init_fail_secure()` + 全局对象 + `background_sync_worker()`
- **模块**: `aiwaf/stream/asyncbreaker.py` — `CircuitBreaker`
- **调用点**: `engine.py` `process_log()` L293-303

### 实现机制

**熔断器**:

```python
redis_breaker = CircuitBreaker(
    fail_max=settings.circuit_breaker_fail_max,      # 默认 5
    timeout_duration=timedelta(seconds=settings.circuit_breaker_timeout),  # 默认 60s
)
```

- 连续失败 5 次 → 跳闸（抛 `CircuitBreakerError`）
- 跳闸后 60 秒 → 半开探测
- 探测成功 → 恢复

**本地黑名单 + 速率限制**（Redis 不可用时）:

```python
local_blacklist = TTLCache(maxsize=10000, ttl=300)    # 本地黑名单 5 分钟 TTL
local_rate_limit = TTLCache(maxsize=10000, ttl=60)    # 本地速率 60 秒窗口
```

**process_log 降级路径**:

```python
except asyncbreaker.CircuitBreakerError:
    redis_available = False

    # 1. 检查本地黑名单
    if ip in local_blacklist or ip in _current_buffer or ip in _backup_buffer:
        await self._emit_alert(std_log, "Local_Blacklist_Block")
        return

    # 2. 本地速率限制
    local_rate_limit[ip] = local_rate_limit.get(ip, 0) + 1
    if local_rate_limit[ip] > fail_secure_local_limit:  # 默认 50
        if auto_block_enabled:
            local_blacklist[ip] = True
            _backup_buffer.append(ip)
        await self._emit_alert(std_log, "Local_RateLimit_Block")
        return
    return  # 降级期间放行（不进入关键词/AI 检测）
```

**双缓冲同步**:

```python
async def background_sync_worker(state_mgr, cancel_event, sync_interval):
    while not cancel_event.is_set():
        await asyncio.sleep(sync_interval)
        _current_buffer, _backup_buffer = _backup_buffer, _current_buffer
        ips_to_sync = list(_backup_buffer)
        try:
            await state_mgr.batch_block_ips([(ip, "Local_FailSecure") for ip in ips_to_sync])
            _backup_buffer.clear()
        except Exception:
            # 合并 _current_buffer 到 _backup_buffer，下次重试
            while _current_buffer:
                _backup_buffer.append(_current_buffer.popleft())
```

### 配置方式

| 配置项 | YAML 字段 | 环境变量 | 默认值 | Redis 覆盖 |
|---|---|---|---|---|
| 熔断器失败次数 | `circuit_breaker_fail_max` | `CIRCUIT_BREAKER_FAIL_MAX` | `5` | ❌ |
| 熔断器恢复间隔 | `circuit_breaker_timeout` | `CIRCUIT_BREAKER_TIMEOUT` | `60` | ❌ |
| 本地黑名单 TTL | `local_blacklist_ttl` | `LOCAL_BLACKLIST_TTL` | `300` (5min) | ❌ |
| 本地速率限制 TTL | `local_rate_limit_ttl` | `LOCAL_RATE_LIMIT_TTL` | `60` | ❌ |
| 本地速率阈值 | `fail_secure_local_limit` | `FAIL_SECURE_LOCAL_LIMIT` | `50` | ✅ |
| 缓冲区最大长度 | `max_pending_ips` | `MAX_PENDING_IPS` | `10000` | ❌ |
| 后台同步间隔 | `background_sync_interval` | `BACKGROUND_SYNC_INTERVAL` | `5` | ❌ |
| 自动拉黑 | `auto_block_enabled` | `AUTO_BLOCK_ENABLED` | `true` | ✅ |

---

## 11. HTTP 方法验证 (MethodBlock)

### 源码位置

- **模块**: `aiwaf/core/method_validation.py` — 函数 `evaluate_method_policy()`
- **模块**: `aiwaf/core/honeypot.py` — `should_block_get_to_post_only_endpoint()` + `OBVIOUS_POST_ONLY_SUFFIXES`

### 实现机制

```python
OBVIOUS_POST_ONLY_SUFFIXES = (
    "/create/", "/submit/", "/upload/", "/delete/", "/process/",
)

def evaluate_method_policy(*, method, path, ...):
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

def should_block_get_to_post_only_endpoint(path, accepts_get):
    if accepts_get:
        return False
    path_l = path.lower()
    return any(path_l.endswith(suffix) for suffix in OBVIOUS_POST_ONLY_SUFFIXES)
```

### 配置方式

方法验证参数不可配置（硬编码在 `honeypot.py` 中）。

| 配置项 | YAML 字段 | 环境变量 | 默认值 | Redis 覆盖 |
|---|---|---|---|---|
| 蜜罐 TTL | `honeypot_ttl` | `HONEYPOT_TTL` | `300` | ✅ |

---

## 12. AI 异常检测 (IsolationForest)

### 源码位置

- **模块**: `aiwaf/core/stream_trainer.py` — `train_from_records()` + `predict_with_model()`
- **模块**: `aiwaf/core/anomaly.py` — `analyze_recent_behavior_python()` + `evaluate_anomaly()`

### 实现机制

**训练** (`train_from_records()`):

1. 构建训练记录（ip, path, status, timestamp → datetime）
2. 特征提取（`training_features.python_feature_from_record()`）:
   - `path_len`: 路径长度
   - `kw_hits`: 关键词命中数
   - `resp_time`: 响应时间
   - `status_idx`: 状态码索引 (0=200, 1=403, 2=404, 3=500)
   - `burst`: 10 秒内同 IP 请求数
   - `total_404`: 该 IP 累计 404 数
3. IsolationForest 训练:
   ```python
   model = IsolationForest(
       n_estimators=n_estimators,      # 默认 100
       max_samples=max_samples,        # 默认 "auto"
       contamination=contamination,    # 默认 0.05
       random_state=42,
   )
   model.fit(feature_matrix)
   ```
4. 预测：`prediction = model.predict(X)` → `1`=正常, `-1`=异常
5. 异常 IP → `blocked_ips` 列表

**预测** (`predict_with_model()`):

```python
def predict_with_model(model, features):
    if is_rust_isolation_forest(model):
        return int(model.predict([list(map(float, features))])[0])
    X = np.array(list(features), dtype=float).reshape(1, -1)
    return int(model.predict(X)[0])
```

### 配置方式

| 配置项 | YAML 字段 | 环境变量 | 默认值 | Redis 覆盖 |
|---|---|---|---|---|
| 最小训练样本数 | `ai_min_logs` | `AI_MIN_LOGS` | `50` | ✅ |
| 污染率 | `ai_contamination` | `AI_CONTAMINATION` | `0.05` | ✅ |
| 树数 | `ai_n_estimators` | `AI_N_ESTIMATORS` | `100` | ✅ |
| 最大样本数 | `ai_max_samples` | `AI_MAX_SAMPLES` | `"auto"` | ❌ |

**Redis 运行时覆盖**:
```bash
redis-cli SET aiwaf:config:ai_contamination 0.1
redis-cli SET aiwaf:config:ai_min_logs 30
```

---

## 13. 路径豁免

### 源码位置

- **静态配置**: `engine.py` `process_log()` L236-241
- **运行时 Redis**: `redis_facade.py` `add_exempt_path()` / `remove_exempt_path()` / `get_exempt_paths()`

### 实现机制

**静态配置豁免**（`header_skip_paths`）:

```python
uri_path = std_log.get("uri_path", "")
skip_paths = [s.strip() for s in self.settings.header_skip_paths.split(",") if s.strip()]
for prefix in skip_paths:
    if uri_path.startswith(prefix):
        return  # 豁免路径跳过所有检测
```

**运行时 Redis 豁免**:

| Redis Key | 类型 | 内容 |
|---|---|---|
| `aiwaf:exempt:paths` | Set | 豁免路径列表 |

```python
await self.facade.add_exempt_path("/api/health")
await self.facade.remove_exempt_path("/api/health")
paths = await self.facade.get_exempt_paths()
```

### 配置方式

| 配置项 | YAML 字段 | 环境变量 | 默认值 | Redis 覆盖 |
|---|---|---|---|---|
| 豁免路径前缀 | `header_skip_paths` | `HEADER_SKIP_PATHS` | `""` | ✅ |

**Redis 运行时管理**:
```bash
redis-cli SADD aiwaf:exempt:paths "/api/health"
redis-cli SREM aiwaf:exempt:paths "/api/health"
redis-cli SMEMBERS aiwaf:exempt:paths
```

---

## 14. 告警输出

### 源码位置

- **模块**: `engine.py` `_emit_alert()`

### 实现机制

```python
alert = {
    "trace_id": std_log.get("trace_id"),
    "rule_id": rule,
    "alert_timestamp": std_log.get("timestamp"),
    "client_ip": std_log.get("client_ip"),
    "akto_account_id": std_log.get("akto_account_id", ""),
    "akto_vxlan_id": std_log.get("akto_vxlan_id", ""),
    "source": std_log.get("source", ""),
    "direction": std_log.get("direction", ""),
    "method": std_log.get("method", "GET"),
    "uri_path": std_log.get("uri_path", "/"),
    "status_code": std_log.get("status_code", 200),
    "detected_at": time.time(),
    "severity": self._classify_severity(rule),
    "req_body_truncated": std_log.get("req_body_truncated", ""),
}
await self.producer.send_and_wait(self.settings.alert_topic, orjson.dumps(alert))
```

### 配置方式

| 配置项 | YAML 字段 | 环境变量 | 默认值 |
|---|---|---|---|
| 告警 Topic | `alert_topic` | `KAFKA_ALERT_TOPIC` | `akto.aiwaf.alerts` |
| DLQ Topic | `dlq_topic` | `KAFKA_DLQ_TOPIC` | `akto.aiwaf.dlq` |
| Kafka brokers | `kafka_brokers` | `KAFKA_BROKERS` | `localhost:9092` |
| 幂等生产者 | `kafka_enable_idempotence` | `KAFKA_ENABLE_IDEMPOTENCE` | `true` |
| ACK 级别 | `kafka_acks` | `KAFKA_ACKS` | `"all"` |

---

## 15. 死信队列 (DLQ)

### 源码位置

- **模块**: `engine.py` `_route_to_dlq()` + `_consume_loop()` L370-390

### 实现机制

**两处 DLQ 写入**:

1. `_consume_loop` 中消息处理失败:
```python
dlq_payload = {
    "trace_id": None,
    "error": f"Processing failed: {e}",
    "error_type": type(e).__name__,
    "raw_log": msg.value.hex(),
    "topic": msg.topic,
    "partition": msg.partition,
    "offset": msg.offset,
}
```

2. `_route_to_dlq` 中 process_log 内部异常:
```python
dlq_payload = {
    "trace_id": std_log.get("trace_id"),
    "error": str(error),
    "error_type": type(error).__name__,
    "raw_log": std_log,
}
```

---

## 16. 微批处理

### 源码位置

- **模块**: `engine.py` `_batch_dispatcher()` L114-166

### 实现机制

```python
# 取第 1 条（阻塞等待）
item = await self.batch_queue.get()

# 非阻塞取更多（超时 batch_timeout_ms 毫秒）
async with asyncio.timeout(batch_timeout_ms / 1000):  # 默认 10ms
    while len(batch_logs) < batch_max_size:  # 默认 50
        item = await self.batch_queue.get()
        ...

# 提交到进程池
batch_results = await loop.run_in_executor(
    self.core_executor, run_core_logic_batch_isolated,
    batch_logs, batch_ts, batch_et, current_kws, ...
)
```

### 配置方式

| 配置项 | YAML 字段 | 环境变量 | 默认值 | Redis 覆盖 |
|---|---|---|---|---|
| 每批最大消息数 | `batch_max_size` | `BATCH_MAX_SIZE` | `50` | ✅ |
| 批处理超时（ms） | `batch_timeout_ms` | `BATCH_TIMEOUT_MS` | `10` | ✅ |
| 队列最大长度 | `batch_queue_maxsize` | `BATCH_QUEUE_MAXSIZE` | `10000` | ❌ |
| 进程池大小 | `core_process_pool_size` | `CORE_PROCESS_POOL_SIZE` | `4` | ❌ |
| 子进程最大任务数 | `max_tasks_per_child` | `MAX_TASKS_PER_CHILD` | `200` | ❌ |

---

## 配置体系总览

### 三级配置优先级

```
环境变量 (最高) > YAML 配置文件 > 内置默认值 (最低)
```

### Redis 运行时覆盖（第四级，仅 25 项检测参数）

```
Redis key: aiwaf:config:{field_name}
TTL: 10 秒本地缓存
覆盖范围: 仅检测参数，不含连接参数
```

### 完整配置文件示例

见 `config.example.yaml`（72 项配置）。
