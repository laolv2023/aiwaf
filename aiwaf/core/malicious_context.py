"""
关键词自学习 — 恶意上下文判定引擎

移植自 aiwaf-project/aiwaf 官方仓库：
  - aiwaf/core/training_logic.py (is_malicious_context)
  - aiwaf/django/middleware.py (_is_malicious_context)
  - aiwaf/django/trainer.py (STATIC_KW, get_default_legitimate_keywords)

适配说明：
  - 流式版本无 Django URL 路由，path_exists 恒返回 False（所有路径视为不存在）
  - status 从 std_log["status_code"] 获取（Akto 消息中的 HTTP 响应码）
  - static_keywords 使用与官方仓库一致的 STATIC_KW 列表
  - legitimate_keywords 使用官方仓库的 get_default_legitimate_keywords() 默认集
"""
import re
from typing import List, Set


# ── 静态恶意关键词（与官方仓库 aiwaf/django/middleware.py STATIC_KW 一致）──
STATIC_KW = [
    ".php", "xmlrpc", "wp-", ".env", ".git", ".bak",
    "conflg", "shell", "filemanager",
]

# ── 合法关键词白名单（与官方仓库 training_logic.get_default_legitimate_keywords 一致）──
DEFAULT_LEGITIMATE_KEYWORDS: Set[str] = {
    "profile", "user", "users", "account", "accounts", "settings", "dashboard",
    "home", "about", "contact", "help", "search", "list", "lists",
    "view", "views", "edit", "create", "update", "delete", "detail", "details",
    "api", "auth", "login", "logout", "register", "signup", "signin",
    "reset", "confirm", "activate", "verify", "page", "pages",
    "category", "categories", "tag", "tags", "post", "posts",
    "article", "articles", "blog", "blogs", "news", "item", "items",
    "admin", "administration", "manage", "manager", "control", "panel",
    "config", "configuration", "option", "options", "preference", "preferences",
    "contenttypes", "contenttype", "sessions", "session", "messages", "message",
    "staticfiles", "static", "sites", "site", "flatpages", "flatpage",
    "redirects", "redirect", "permissions", "permission", "groups", "group",
    "token", "tokens", "oauth", "social", "rest", "framework", "cors",
    "debug", "toolbar", "extensions", "allauth", "crispy", "forms",
    "channels", "celery", "redis", "cache", "email", "mail",
    "static", "favicon", "robots", "sitemap", "manifest", "health", "ping",
    "status", "metrics", "test", "docs", "documentation",
    "endpoint", "endpoints", "resource", "resources", "data", "export",
    "import", "upload", "download", "file", "files", "media", "images",
    "documents", "reports", "analytics", "stats", "statistics",
    "customer", "customers", "client", "clients", "company", "companies",
    "department", "departments", "employee", "employees", "team", "teams",
    "project", "projects", "task", "tasks", "event", "events",
    "notification", "notifications", "alert", "alerts",
    "language", "languages", "locale", "locales", "translation", "translations",
    "en", "fr", "de", "es", "it", "pt", "ru", "ja", "zh", "ko",
}


def is_malicious_context(
    path: str,
    keyword: str,
    status: int = 404,
    static_keywords: List[str] = None,
) -> bool:
    """
    判定关键词是否出现在恶意上下文中。

    移植自 aiwaf/core/training_logic.py:is_malicious_context，
    去除 path_exists_fn 依赖（流式版本无 Django 路由，路径一律视为不存在）。

    Args:
        path: 请求路径（含 query string）
        keyword: 被检测的关键词段
        status: HTTP 响应状态码
        static_keywords: 静态恶意关键词列表

    Returns:
        True 如果关键词在恶意上下文中
    """
    if static_keywords is None:
        static_keywords = STATIC_KW

    path_lower = (path or "").lower()
    segments = re.split(r"\W+", path_lower)

    status_str = str(status) if status is not None else "0"

    malicious_indicators = [
        # 1. 路径中包含多个静态恶意关键词
        len([seg for seg in segments if seg in static_keywords]) > 1,

        # 2. 常见攻击模式
        any(pattern in path_lower for pattern in [
            "../", "..\\", ".env", "wp-admin", "phpmyadmin", "config",
            "backup", "database", "mysql", "passwd", "shadow", "xmlrpc",
            "shell", "cmd", "exec", "eval", "system",
        ]),

        # 3. SQL 注入 / XSS / 模板注入
        any(attack in path_lower for attack in [
            "union+select", "drop+table", "<script", "javascript:",
            "${", "{{", "onload=", "onerror=", "file://", "http://",
        ]),

        # 4. 多次目录遍历
        path_lower.count("../") > 1 or path_lower.count("..\\") > 1,

        # 5. 编码攻击
        any(encoded in path_lower for encoded in [
            "%2e%2e", "%252e", "%c0%ae",
            "%3c%73%63%72%69%70%74",  # <script
        ]),

        # 6. 404 + 异常路径特征
        status_str == "404" and (
            len(path_lower) > 50 or
            path_lower.count("/") > 10 or
            any(c in path_lower for c in ["<", ">", "{", "}", "$", "`"])
        ),
    ]

    return any(malicious_indicators)


def is_scanning_path(path: str) -> bool:
    """
    判定路径是否像自动化扫描。

    移植自 aiwaf/core/training_logic.py:is_scanning_path。
    """
    path_lower = (path or "").lower()

    scanning_patterns = [
        'wp-admin', 'wp-content', 'wp-includes', 'wp-config', 'xmlrpc.php',
        'admin', 'phpmyadmin', 'adminer', 'config', 'configuration',
        'settings', 'setup', 'install', 'installer',
        'backup', 'database', 'db', 'mysql', 'sql', 'dump',
        '.env', '.git', '.htaccess', '.htpasswd', 'passwd', 'shadow',
        'cgi-bin', 'scripts', 'shell', 'cmd', 'exec',
        '.php', '.asp', '.aspx', '.jsp', '.cgi', '.pl'
    ]

    for pattern in scanning_patterns:
        if pattern in path_lower:
            return True

    if '../' in path or '..' in path:
        return True

    if any(encoded in path for encoded in ['%2e%2e', '%252e', '%c0%ae']):
        return True

    return False
