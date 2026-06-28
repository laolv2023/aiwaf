# AIWAF-Stream 检测模式三类分类详解

> 版本: 3.0 | 最后更新: 2026-06-28
> 来源: 全部内容基于代码实际逻辑，无推测。

---

## 概述

AIWAF-Stream 的 16 项检测能力按决策来源分为三类：

| 类型 | 检测能力数 | 决策来源 | 开箱即用 |
|---|---|---|---|
| **一、预定义特征** | 18 项 | 代码硬编码模式/规则/阈值 | ✅ |
| **二、自学习** | 7 项 | 运行时从流量中积累 → Redis/内存 | ❌ 需流量积累 |
| **三、ML 建模** | 3 项 | 历史数据训练 IsolationForest 模型 | ❌ 需训练数据 |

---

## 一、预定义特征检测（18 项）

这些检测基于代码中写死的模式/规则/阈值，部署即可工作。其中 14 项现已支持**追加配置**（用户可通过 YAML/环境变量追加自定义特征，不替换默认值）。

### 1.1 关键词策略检测（3 组硬编码模式）

**源码**: `aiwaf/core/ip_keyword.py`

#### ① 探测路径检测 — PROBE_PATH_PATTERNS

```python
# ip_keyword.py L31-35
PROBE_PATH_PATTERNS = (
    r"(^|/)\.(env|git|htaccess|htpasswd)(/|$)",    # 敏感文件
    r"\.(php|asp|aspx|jsp|cgi|bak|sql)(/|$)",      # 脚本/备份文件
    r"xmlrpc\.php",                                  # WordPress XML-RPC
)
```

- **触发条件**: URL 路径匹配任一正则
- **告警规则**: `KeywordBlock:Keyword block: Inherently suspicious: probe path`（severity=HIGH）
- **可配置**: ✅ `probe_path_patterns_extra`（追加正则，逗号分隔）

#### ② 固有恶意模式 — INHERENTLY_MALICIOUS_PATTERNS

```python
# ip_keyword.py L8-17
INHERENTLY_MALICIOUS_PATTERNS = (
    "hack", "exploit", "attack", "malicious",
    "evil", "backdoor", "inject", "xss",
)
```

- **触发条件**: URL 路径段包含任一模式（且不在合法白名单中）
- **告警规则**: `KeywordBlock:Keyword block: Inherently suspicious: {seg}`（severity=HIGH）
- **可配置**: ✅ `inherently_malicious_extra`（追加，逗号分隔）

#### ③ 强力攻击模式 — VERY_STRONG_ATTACK_PATTERNS

```python
# ip_keyword.py L19-29
VERY_STRONG_ATTACK_PATTERNS = (
    "union+select", "drop+table", "<script",
    "javascript:", "onload=", "onerror=",
    "${", "{{", "eval(",
)
```

- **触发条件**: URL 路径包含任一模式（仅在 `path_exists=True` 时作为增强判定）
- **可配置**: ✅ `very_strong_attacks_extra`（追加，逗号分隔）

### 1.2 恶意上下文判定（6 个硬编码指标）

**源码**: `aiwaf/core/malicious_context.py` `is_malicious_context()`

```python
# 6 个指标的 OR 逻辑（任一命中即判定为恶意上下文）
malicious_indicators = [
    # 指标1: 多个静态关键词命中
    len([seg for seg in segments if seg in static_keywords]) > 1,

    # 指标2: 攻击模式匹配（17 个字符串）
    any(pattern in path_lower for pattern in [
        "../", "..\\", ".env", "wp-admin", "phpmyadmin", "config",
        "backup", "database", "mysql", "passwd", "shadow", "xmlrpc",
        "shell", "cmd", "exec", "eval", "system",
    ]),

    # 指标3: SQL注入/XSS/模板注入（10 个字符串）
    any(attack in path_lower for attack in [
        "union+select", "drop+table", "<script", "javascript:",
        "${", "{{", "onload=", "onerror=", "file://", "http://",
    ]),

    # 指标4: 多次目录遍历
    path_lower.count("../") > 1 or path_lower.count("..\\") > 1,

    # 指标5: 编码攻击（4 个编码模式）
    any(encoded in path_lower for encoded in [
        "%2e%2e", "%252e", "%c0%ae",
        "%3c%73%63%72%69%70%74",  # <script 的 URL 编码
    ]),

    # 指标6: 404 + 异常路径特征
    status_str == "404" and (
        len(path_lower) > 50 or
        path_lower.count("/") > 10 or
        any(c in path_lower for c in ["<", ">", "{", "}", "$", "`"])
    ),
]
```

- **触发条件**: 任一指标为 True
- **用途**: 关键词自学习的判定依据（`is_malicious_context(seg)=True` → 加入 `learned_keywords`）
- **可配置**: ❌ 不可配置（6 个指标的组合逻辑复杂，不建议单独配置）

### 1.3 静态恶意关键词 — STATIC_KW

**源码**: `aiwaf/core/malicious_context.py` L20-23

```python
STATIC_KW = [
    ".php", "xmlrpc", "wp-", ".env", ".git", ".bak",
    "conflg", "shell", "filemanager",
]
```

- **用途**: `is_malicious_context()` 的指标 1 使用；`acl_bootstrap.py` 中作为 `static_keywords` 参数传递给子进程
- **可配置**: ✅ `static_keywords_extra`（追加，逗号分隔）

### 1.4 合法关键词白名单 — DEFAULT_LEGITIMATE_KEYWORDS

**源码**: `aiwaf/core/malicious_context.py` L26-47

```python
DEFAULT_LEGITIMATE_KEYWORDS: Set[str] = {
    "profile", "user", "users", "account", "accounts", "settings", "dashboard",
    "home", "about", "contact", "help", "search", "list", "lists",
    "view", "views", "edit", "create", "update", "delete",
    "api", "v1", "v2", "v3", "static", "assets",
    "css", "js", "img", "images", "fonts", "media",
    "public", "favicon", "robots", "sitemap",
    "login", "logout", "register", "signup", "signin",
    "admin", "product", "products", "category", "categories",
    "order", "orders", "cart", "checkout", "payment",
    "blog", "post", "posts", "article", "articles",
    "page", "pages", "tag", "tags", "comment", "comments",
}
```

- **用途**: 路径段在白名单中 → 不参与关键词学习（防止误学习正常路径段）
- **可配置**: ✅ `legitimate_keywords_extra`（追加，逗号分隔）

### 1.5 扫描路径判定 — is_scanning_path

**源码**: `aiwaf/core/malicious_context.py` L127-148

```python
scanning_patterns = [
    'wp-admin', 'wp-content', 'wp-includes', 'wp-config', 'xmlrpc.php',
    'admin', 'phpmyadmin', 'adminer', 'config', 'configuration',
    'settings', 'setup', 'install', 'installer',
    'backup', 'database', 'db', 'mysql', 'sql', 'dump',
    '.env', '.git', '.htaccess', '.htpasswd', 'passwd', 'shadow',
    'cgi-bin', 'scripts', 'shell', 'cmd', 'exec',
    '.php', '.asp', '.aspx', '.jsp', '.cgi', '.pl'
]
```

- **用途**: `is_scanning_path()` 用于 AI 异常检测中的行为统计（`scanning_404s` 计数）
- **可配置**: ❌ 不可配置（与 `is_malicious_context` 指标 2 高度重叠）

### 1.6 请求头验证（6 层检查）

**源码**: `aiwaf/core/header_validation.py` `evaluate_header_policy()`

| 层 | 检查内容 | 硬编码默认值 | 可配置 |
|---|---|---|---|
| 1 | Header 字节总量 | `MAX_HEADER_BYTES = 32768` (32KB) | ✅ `header_max_bytes` |
| 2 | Header 数量 | `MAX_HEADER_COUNT = 100` | ✅ `header_max_count` |
| 3 | 必需头缺失 | `REQUIRED_HEADERS = ['HTTP_USER_AGENT', 'HTTP_ACCEPT']` | ✅ `header_required` |
| 4 | 可疑 User-Agent | `SUSPICIOUS_USER_AGENTS`（21 个正则：bot/crawler/curl/wget/python/java/okhttp/...） | ✅ `header_suspicious_ua` |
| 4 | 合法爬虫白名单 | `LEGITIMATE_BOTS`（16 个：googlebot/bingbot/baiduspider/...） | ✅ `header_legitimate_bots` |
| 5 | 可疑头组合 | `SUSPICIOUS_COMBINATIONS`（有UA无Accept / 有Accept无UA） | ❌ 不可配置（lambda 无法序列化） |
| 6 | Header 质量评分 | `BROWSER_HEADERS`（4 个：accept-language/accept-encoding/connection/cache-control），评分 < 3 告警 | ❌ 不可配置 |
| — | UA 最大长度 | `MAX_USER_AGENT_LENGTH = 500` | ✅ `header_max_ua_length` |
| — | Accept 最大长度 | `MAX_ACCEPT_LENGTH = 4096` | ✅ `header_max_accept_length` |

### 1.7 HTTP 方法验证

**源码**: `aiwaf/core/method_validation.py` + `aiwaf/core/honeypot.py`

#### POST-only 端点后缀

```python
# honeypot.py L28-34
OBVIOUS_POST_ONLY_SUFFIXES = (
    "/create/", "/submit/", "/upload/", "/delete/", "/process/",
)
```

- **触发条件**: GET 请求访问以这些后缀结尾的路径
- **告警规则**: `MethodBlock:GET to obvious POST-only endpoint`（severity=HIGH）
- **可配置**: ✅ `post_only_suffixes_extra`（追加，逗号分隔）

#### 登录路径前缀

```python
# honeypot.py L20-26
LOGIN_PATH_PREFIXES = (
    "/admin/login/", "/login/", "/accounts/login/",
    "/auth/login/", "/signin/",
)
```

- **用途**: 蜜罐时序检测中使用（GET 访问登录页 → 记录时间戳 → POST 提交时检查时序）
- **可配置**: ✅ `login_paths_extra`（追加，逗号分隔）

#### HTTP 方法白名单

```python
# method_validation.py
# GET → 检查是否 POST-only 端点
# POST → 允许
# HEAD/OPTIONS → 允许
# 其他 → 拦截
```

- **可配置**: ❌ 不可配置（HTTP 协议标准）

### 1.8 UUID 格式检测

**源码**: `aiwaf/core/uuid_tamper.py`

```python
# UUID 格式正则（RFC 4122 标准）
UUID_RE = re.compile(r"^[a-f0-9\-]{36}$")
```

- **触发条件**: URL 路径段长度=36 + 含 ≥4 个 dash + `is_malformed_uuid(seg)=True`（看起来像 UUID 但解析失败）
- **告警规则**: `UUIDTamper:malformed_uuid`（severity=HIGH）
- **可配置**: ❌ UUID 格式正则不可配置（RFC 标准）

### 1.9 UUID 篡改评分系统

**源码**: `aiwaf/core/uuid_tamper.py` `get_uuid_score_defaults()` + `record_uuid_signal()`

```python
# 默认评分参数
{
    "enabled": True,
    "window_seconds": 60,      # 评分窗口
    "block_threshold": 5,      # 拦截阈值
    "malformed_weight": 5,     # malformed UUID 权重
    "not_found_weight": 1,     # UUID 不存在权重
    "success_decay": 2,        # 成功衰减
}
```

- **评分逻辑**: `score += malformed_weight`（malformed）/ `+= not_found_weight`（404）/ `-= success_decay`（成功）
- **拦截条件**: `score >= block_threshold`
- **可配置**: ✅ 全部 5 个参数可配置

| 配置项 | 默认值 |
|---|---|
| `uuid_block_threshold` | 5 |
| `uuid_malformed_weight` | 5 |
| `uuid_not_found_weight` | 1 |
| `uuid_success_decay` | 2 |
| `uuid_window_seconds` | 60 |

### 1.10 速率限制阈值

**源码**: `aiwaf/core/rate_limit.py` + `aiwaf/stream/redis_facade.py`

| 配置项 | 默认值 | 说明 |
|---|---|---|
| `rate_limit_window` | 60 | 窗口大小（秒） |
| `rate_limit_max_requests` | 100 | 窗口内最大请求数 |
| `rate_limit_flood_threshold` | 150 | 洪泛检测阈值 |
| `fail_secure_local_limit` | 50 | Redis 不可用时本地降级阈值 |

- **告警规则**: `RateLimitFlood`（severity=MEDIUM）/ `Local_RateLimit_Block`（severity=HIGH）
- **可配置**: ✅ 全部 4 项

### 1.11 地理围栏策略

**源码**: `aiwaf/core/geo_policy.py` `evaluate_geo_policy()`

```python
# 白名单模式：allow_countries 非空时，只允许列表内国家
# 黑名单模式：allow_countries 为空时，拦截 block_countries 中的国家
if allow:
    blocked = country not in allow
else:
    blocked = country in block or country in dynamic
```

- **告警规则**: `GeoBlock:{country}`（severity=MEDIUM）
- **可配置**: ✅ `geoip_db_path` / `geo_block_countries` / `geo_allow_countries`

### 1.12 路径段最小长度

**源码**: `aiwaf/core/ip_keyword.py` `extract_path_segments()`

```python
# ip_keyword.py L47
return [seg for seg in re.split(r"\W+", value) if len(seg) > 3]
```

- **用途**: 路径段长度 ≤3 的段不参与关键词检测（如 `/api/v1/` 中的 `v1` 被跳过）
- **可配置**: ✅ `keyword_min_segment_length`（默认 3）

---

## 二、自学习检测（7 项）

这些检测没有预定义规则，从实际流量中自动学习，形成检测闭环。

### 2.1 动态关键词自学习

**数据流**:

```
请求到达
  │
  ├── URL 路径段提取（extract_path_segments）
  │
  ├── 条件检查：
  │   ├── 段不在 DEFAULT_LEGITIMATE_KEYWORDS（合法白名单）
  │   ├── 段不在 exempt_keywords（豁免列表）
  │   ├── is_malicious_context(seg) = True（6 指标判定）
  │   └── keyword_learning_enabled = True
  │
  ├── 满足条件 → learned_keywords.append(seg)
  │
  ├── batch_add_keywords(learned_keywords)
  │   └→ Redis ZINCRBY aiwaf:keywords {seg} 1  （score +1）
  │
  └── 每 10 秒 get_top_keywords(500)
      └→ dynamic_keywords_cache 刷新
          └→ 新请求匹配 dynamic_keywords → KeywordBlock: Learned keyword
              └→ 闭环完成 ✅
```

**Redis Key**: `aiwaf:keywords`（Sorted Set，score=出现次数）
**配置项**: `keyword_refresh_interval`（默认 10 秒）/ `keyword_top_n`（默认 500）/ `auto_learn_keywords`（默认 True）

### 2.2 IP 黑名单

**数据流**:

```
检测到威胁（任何 Rule）
  │
  ├── auto_block_enabled = True
  │
  ├── result.side_effects.blocked_ips = [(ip, reason), ...]
  │
  ├── batch_block_ips(blocked_ips)
  │   └→ Redis SET aiwaf:blk:{ip} {reason} EX 3600  （TTL=1h）
  │
  └── 后续请求 is_blocked(ip) → 拦截
      └→ 闭环完成 ✅
```

**Redis Key**: `aiwaf:blk:{ip}`（String，TTL=`blacklist_ttl` 默认 1h）
**配置项**: `auto_block_enabled` / `blacklist_ttl`

### 2.3 路径清单（Path Manifest）

**数据流**:

```
每条请求 process_log()
  │
  ├── templify_path("/api/users/123") → "/api/users/{id}"
  │   （整数→{id}、UUID→{uuid}、长hex→{hex}、Base64→{b64}、长随机→{token}）
  │
  ├── PathManifest.record(template, method, status_code)
  │   └→ _paths[template].total_count += 1
  │       _paths[template].methods.add(method)
  │       if 200<=status<300: ok_count += 1
  │       elif status>=400: error_count += 1
  │
  └── path_exists(path) 判定：
      ├── 模板存在 + total_count >= 3 + ok_ratio > 0.5 → True（已知路径）
      └── 否则 → False（未知路径，关键词学习激活）
          └→ 防止误学习正常路径 ✅
```

**存储**: 内存 `PathManifest._paths`（dict，线程安全 `threading.Lock`）
**配置项**: 无（自动运行）

### 2.4 UUID 篡改评分状态

**数据流**:

```
URL 路径段匹配 UUID 格式特征（36 字符 + 4 dash）
  │
  ├── is_malformed_uuid(seg) = True
  │
  ├── record_uuid_signal(ip, "malformed", config=...)
  │   └→ _UUID_SCORE_STATE[ip] += malformed_weight (5)
  │       （60 秒滑动窗口，成功请求衰减 -2）
  │
  └── score >= block_threshold (5) → 拦截
      └→ 闭环完成 ✅
```

**存储**: 内存 `_UUID_SCORE_STATE`（dict + Lock，60 秒窗口）
**配置项**: `uuid_block_threshold` / `uuid_malformed_weight` / `uuid_not_found_weight` / `uuid_success_decay` / `uuid_window_seconds`

### 2.5 本地速率限制（Fail-Secure 降级）

**数据流**:

```
Redis 不可用（CircuitBreakerError）
  │
  ├── local_rate_limit[ip] += 1  （TTLCache，TTL=60s）
  │
  ├── local_rate_limit[ip] > fail_secure_local_limit (50)
  │   ├── auto_block_enabled → local_blacklist[ip] = True
  │   └── _backup_buffer.append(ip)
  │
  └── 后续请求 ip in local_blacklist → 拦截
      └→ 闭环完成 ✅
```

**存储**: 内存 `local_rate_limit` / `local_blacklist`（TTLCache）
**配置项**: `fail_secure_local_limit` / `local_rate_limit_ttl` / `local_blacklist_ttl`

### 2.6 本地黑名单（Fail-Secure 降级）

**数据流**: 与 2.5 联动 — 本地速率超限 → IP 加入 `local_blacklist`（TTLCache，TTL=300s）

**配置项**: `local_blacklist_ttl` / `auto_block_enabled`

### 2.7 双缓冲写回

**数据流**:

```
Fail-Secure 期间积累的 IP → _backup_buffer
  │
  ├── background_sync_worker（每 background_sync_interval 秒）
  │
  ├── 交换 _current_buffer ↔ _backup_buffer
  │
  ├── 从 _backup_buffer 取数据
  │   ├── Redis 可用 → batch_block_ips → 同步成功 → 清空 _backup_buffer
  │   └── Redis 不可用 → 保留数据 → 合并 _current_buffer → 下次重试
  │
  └→ Redis 恢复后自动同步 ✅
```

**存储**: 内存 `_pending_buffer_A/B`（deque，maxlen=`max_pending_ips`）
**配置项**: `background_sync_interval` / `max_pending_ips`

---

## 三、ML 建模检测（3 项）

需要先用历史数据训练 IsolationForest 模型，然后加载模型进行预测。

### 3.1 AI 异常检测训练

**源码**: `aiwaf/core/stream_trainer.py` `train_from_records()`

**训练流程**:

```
train_from_records(records)
  │
  ├── 1. 解析请求记录 → 提取 IP/路径/状态码/时间戳
  │      （parsed_count ≥ ai_min_logs 才训练，否则跳过）
  │
  ├── 2. 特征提取（python_feature_from_record）
  │      特征向量: [path_len, kw_hits, resp_time, status_idx, burst, total_404]
  │      ├── path_len: URL 长度
  │      ├── kw_hits: 静态关键词命中数
  │      ├── resp_time: 响应时间
  │      ├── status_idx: 状态码索引（200=0, 403=1, 404=2, 500=3）
  │      ├── burst: 10 秒内同 IP 请求计数
  │      └── total_404: 同 IP 累计 404 数
  │
  ├── 3. IsolationForest 训练
  │      IsolationForest(
  │          n_estimators=ai_n_estimators,     # 默认 100
  │          contamination=ai_contamination,   # 默认 0.05
  │          max_samples=ai_max_samples,       # 默认 "auto"
  │      )
  │      model.fit(X)
  │
  ├── 4. 预测 + 异常 IP 检测
  │      predictions = model.predict(X)  # -1=异常, 1=正常
  │      anomalous_ips = [records[i]["ip"] for i where predictions[i]==-1]
  │      batch_block_ips(anomalous_ips) → Redis 黑名单
  │
  └── 5. 模型持久化
       joblib.dump(model, model_save_path) → .pkl 文件
```

**配置项**: `ai_min_logs`(50) / `ai_contamination`(0.05) / `ai_n_estimators`(100) / `ai_max_samples`("auto")

### 3.2 AI 异常检测预测

**源码**: `aiwaf/stream/acl_bootstrap.py` `init_worker()` + `aiwaf/core/stream_trainer.py` `predict_with_model()`

**预测流程**:

```
ProcessPoolExecutor 子进程启动
  │
  ├── init_worker(model_path)
  │   ├── 路径白名单校验（防目录穿越 + .pkl 后缀）
  │   ├── joblib.load(model_path) → _local_model
  │   └── 加载失败 → _local_model = None（降级，关键词检测仍工作）
  │
  ├── 每条消息处理时
  │   ├── 构建特征向量
  │   ├── predict_with_model(_local_model, features)
  │   │   ├── model.predict([features]) → -1=异常 / 1=正常
  │   │   └── model=None → 返回 None（跳过 AI 检测）
  │   └── prediction == -1 → 标记为异常 IP
  │
  └── 异常 IP → batch_block_ips → Redis 黑名单
```

### 3.3 批量训练关键词学习

**源码**: `aiwaf/core/stream_trainer.py` `train_from_records()` 关键词学习部分

**训练流程**:

```
train_from_records(records)
  │
  ├── 遍历所有请求记录
  │   ├── 路径不存在（path_exists=False）+ 状态码 4xx/5xx
  │   ├── URL 路径段拆分（re.split(r"\W+")）
  │   ├── 段长度 > 3 + 不在 STATIC_KW + 不在 legitimate_keywords
  │   ├── is_malicious_context(path, seg, status, STATIC_KW) = True
  │   └── tokens[seg] += 1（Counter 统计）
  │
  ├── 过滤：出现 ≥2 次 + 长度 ≥4 + 在恶意上下文中
  │
  └── keyword_store.add_keyword(kw, cnt) → Redis aiwaf:keywords
      └→ 与自学习共用 Redis ZSET，形成统一关键词库
```

**与运行时自学习的区别**:

| 维度 | 运行时自学习（2.1） | 批量训练学习（3.3） |
|---|---|---|
| 数据来源 | 实时 Kafka 流量 | 历史请求记录列表 |
| 触发时机 | 每条请求 | 手动调用 `train_from_records()` |
| 学习条件 | `is_malicious_context(seg)=True` | 同 + 出现≥2次 + 长度≥4 |
| 权重 | 每次出现 +1 | 按出现次数 `cnt` 写入 |
| 写入目标 | Redis `aiwaf:keywords` | 同 |

---

## 四、三类检测对比总结

| 维度 | 预定义特征 | 自学习 | ML 建模 |
|---|---|---|---|
| **检测能力数** | 18 项 | 7 项 | 3 项 |
| **开箱即用** | ✅ 部署即工作 | ❌ 需流量积累 | ❌ 需训练数据 |
| **检测精度** | 高（精确匹配） | 中高（基于运行时积累） | 中（基于统计模型） |
| **误报风险** | 低（白名单保护） | 中（可能学到误判关键词） | 中高（模型可能过拟合） |
| **可配置项** | 14 项可追加配置 | 25 项可 Redis 覆盖 | 4 项训练参数 |
| **维护成本** | 零（硬编码） | 低（自动闭环） | 高（需定期重训练） |
| **适用场景** | 已知攻击模式 | 新型攻击发现 | 未知异常行为 |
| **数据来源** | 代码内置 | Kafka 流量 → Redis | 历史请求记录 → IsolationForest |
| **存储位置** | 代码常量 | Redis + 内存 | .pkl 文件 |

---

## 五、配置体系总览

### 三级配置优先级

```
环境变量 (最高) > YAML 配置文件 > 内置默认值 (最低)
```

### 第四级：Redis 运行时覆盖（25 项检测参数）

```
Redis key: aiwaf:config:{field_name}
10 秒本地缓存
仅覆盖检测参数，不含连接参数
```

### 完整配置统计

| 类别 | 项数 | 说明 |
|---|---|---|
| 连接参数 | 7 | Redis/Kafka（不可 Redis 覆盖） |
| 检测参数 | 33 | 速率限制/请求头/地理围栏/AI/UUID/蜜罐 |
| 预定义特征追加 | 14 | 关键词/模式/路径追加到默认列表 |
| 运维参数 | 11 | 进程池/微批/熔断器/Fail-Secure/同步 |
| **合计** | **65** | YAML + 环境变量 |
| Redis 可覆盖 | 25 | 运行时热更新 |

### 配置文件

详见 `config.example.yaml`（65 项配置）。
