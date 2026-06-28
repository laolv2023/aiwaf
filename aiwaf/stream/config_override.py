"""
运行时配置覆盖层

通过 Redis 覆盖 YAML/环境变量的配置值，支持运行时热更新检测参数。
不覆盖连接参数（Kafka/Redis/进程池），这些需要重启。

使用方式:
  redis-cli SET aiwaf:config:rate_limit_max_requests 200
  redis-cli DEL aiwaf:config:rate_limit_max_requests  # 恢复默认值

特性:
  - 10 秒本地缓存（避免每请求查 Redis）
  - 只覆盖白名单内的配置项（检测参数，不含连接参数）
  - 类型安全（int/float/bool/str 自动转换）
  - Redis 不可用时降级到 YAML/默认值
"""
import time
import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)

# 可被 Redis 覆盖的配置项白名单（检测参数，不含连接参数）
_OVERRIDABLE_KEYS = frozenset({
    "rate_limit_window",
    "rate_limit_max_requests",
    "rate_limit_flood_threshold",
    "fail_secure_local_limit",
    "auto_block_enabled",
    "auto_learn_keywords",
    "header_required",
    "header_skip_ips",
    "header_skip_paths",
    "header_max_ua_length",
    "header_max_accept_length",
    "header_suspicious_ua",
    "header_legitimate_bots",
    "geo_block_countries",
    "geo_allow_countries",
    "keyword_refresh_interval",
    "keyword_top_n",
    "batch_max_size",
    "batch_timeout_ms",
    "kafka_retry_interval",
    "ai_min_logs",
    "ai_contamination",
    "ai_n_estimators",
    "honeypot_ttl",
    "keyword_min_segment_length",
})

# 类型映射（与 Settings dataclass 一致）
_INT_KEYS = frozenset({
    "rate_limit_window", "rate_limit_max_requests", "rate_limit_flood_threshold",
    "fail_secure_local_limit", "header_max_ua_length", "header_max_accept_length",
    "keyword_refresh_interval", "keyword_top_n", "batch_max_size", "batch_timeout_ms",
    "kafka_retry_interval", "ai_min_logs", "ai_n_estimators",
    "honeypot_ttl", "keyword_min_segment_length",
})

_FLOAT_KEYS = frozenset({
    "ai_contamination",
})

_BOOL_KEYS = frozenset({
    "auto_block_enabled", "auto_learn_keywords",
})


class ConfigOverride:
    """
    运行时配置覆盖层。

    从 Redis 读取覆盖值，10 秒本地缓存。
    只覆盖白名单内的配置项。
    """

    CACHE_TTL = 10  # 秒

    def __init__(self, redis_facade=None):
        self._facade = redis_facade
        self._cache: dict = {}  # key → (value, timestamp)
        self._last_full_refresh = 0.0

    def _get_from_cache(self, key: str) -> Optional[Any]:
        """从本地缓存获取"""
        if key in self._cache:
            val, ts = self._cache[key]
            if time.time() - ts < self.CACHE_TTL:
                return val
        return None

    def _convert(self, key: str, raw: str) -> Any:
        """类型转换"""
        if key in _INT_KEYS:
            try:
                return int(raw)
            except (ValueError, TypeError):
                return None
        elif key in _FLOAT_KEYS:
            try:
                return float(raw)
            except (ValueError, TypeError):
                return None
        elif key in _BOOL_KEYS:
            return raw.lower() in ("true", "1", "yes", "on")
        else:
            return raw

    def get(self, key: str, default: Any) -> Any:
        """
        获取配置值：Redis 覆盖值 > 默认值。

        如果 Redis 中有 aiwaf:config:{key}，返回覆盖值；
        否则返回 default（来自 Settings）。
        """
        if key not in _OVERRIDABLE_KEYS:
            return default

        # 1. 查本地缓存
        cached = self._get_from_cache(key)
        if cached is not None:
            return cached

        # 2. 查 Redis（非阻塞，失败返回 default）
        if self._facade is not None:
            try:
                import asyncio
                loop = asyncio.get_running_loop()
                # 在异步上下文中同步获取（有缓存兜底，不阻塞太久）
                raw = loop.run_until_complete(
                    self._facade.mgr.redis.get(f"aiwaf:config:{key}")
                )
                if raw is not None:
                    val = self._convert(key, raw)
                    if val is not None:
                        self._cache[key] = (val, time.time())
                        return val
            except Exception:
                pass

        return default

    async def get_async(self, key: str, default: Any) -> Any:
        """异步获取配置值（在 process_log 中使用）"""
        if key not in _OVERRIDABLE_KEYS:
            return default

        # 1. 查本地缓存
        cached = self._get_from_cache(key)
        if cached is not None:
            return cached

        # 2. 查 Redis
        if self._facade is not None:
            try:
                raw = await self._facade.mgr.redis.get(f"aiwaf:config:{key}")
                if raw is not None:
                    val = self._convert(key, raw)
                    if val is not None:
                        self._cache[key] = (val, time.time())
                        return val
            except Exception:
                pass

        return default

    def invalidate(self, key: str = None):
        """使缓存失效（测试用）"""
        if key:
            self._cache.pop(key, None)
        else:
            self._cache.clear()

    async def set_override(self, key: str, value: Any):
        """设置 Redis 覆盖值"""
        if key not in _OVERRIDABLE_KEYS:
            raise ValueError(f"Config key '{key}' is not overridable")
        if self._facade is not None:
            await self._facade.mgr.redis.set(f"aiwaf:config:{key}", str(value))
            self._cache[key] = (self._convert(key, str(value)), time.time())

    async def remove_override(self, key: str):
        """移除 Redis 覆盖值（恢复默认）"""
        if self._facade is not None:
            await self._facade.mgr.redis.delete(f"aiwaf:config:{key}")
            self._cache.pop(key, None)
