"""
Redis 状态管理、异步熔断与 Fail-Secure 本地防线

全局对象通过 init_fail_secure(settings) 初始化配置参数。
未调用 init_fail_secure 时使用默认值（向后兼容）。
"""
import asyncio
import collections
import datetime
import random
import asyncbreaker
import cachetools
from typing import List, Tuple, Optional
from prometheus_client import Counter

METRIC_PENDING_OVERFLOW = Counter('aiwaf_pending_overflow_total', 'Shadow table overflow count')


class RedisClusterStateManager:
    def __init__(self, redis_cluster_url: str,
                 dedup_ttl: int = 86400,
                 blacklist_ttl: int = 3600):
        import redis.asyncio as redis
        self.redis_url = redis_cluster_url
        self.redis = redis.from_url(redis_cluster_url, decode_responses=True)
        self.dedup_ttl = dedup_ttl
        self.blacklist_ttl = blacklist_ttl

    async def is_duplicate_and_add(self, trace_id: str, is_retry: bool = False, retry_count: int = 0) -> bool:
        """SETNX 绝对幂等，无 Cluster 热点"""
        idem_key = f"aiwaf:idem:{trace_id}:retry_{retry_count}" if is_retry else f"aiwaf:idem:{trace_id}"
        result = await self.redis.set(idem_key, "1", nx=True, ex=self.dedup_ttl)
        return result is None

    async def get_and_update_rate_limit(self, ip: str, event_time: float, window: int, max_req: int) -> list:
        """防乱序内存泄漏的限流状态获取"""
        key = f"aiwaf:rl:{ip}"
        score = event_time * 1000 + random.randint(0, 999)
        member = f"{score}-{random.getrandbits(32)}"

        pipe = self.redis.pipeline(transaction=False)
        pipe.zremrangebyscore(key, 0, (event_time - window) * 1000)
        pipe.zremrangebyrank(key, 0, -(max_req * 2 + 1))
        pipe.zadd(key, {member: score})
        pipe.expire(key, window * 2)
        pipe.zrange(key, 0, -1, withscores=True)

        results = await pipe.execute()
        return [float(s) / 1000.0 for _, s in results[4]]

    async def batch_block_ips(self, ips_reasons: List[Tuple[str, str]]):
        pipe = self.redis.pipeline(transaction=False)
        for ip, reason in ips_reasons:
            pipe.set(f"aiwaf:blk:{ip}", reason, ex=self.blacklist_ttl)
        await pipe.execute()

    async def get_top_keywords(self, n: int = 500) -> List[str]:
        return await self.redis.zrevrange("aiwaf:keywords", 0, n - 1)

    async def batch_add_keywords(self, kws: List[str]):
        if not kws:
            return
        pipe = self.redis.pipeline(transaction=False)
        for kw in kws:
            pipe.zincrby("aiwaf:keywords", 1, kw)
        await pipe.execute()


# ── 全局 Fail-Secure 状态（通过 init_fail_secure 配置）──

redis_breaker: asyncbreaker.CircuitBreaker = asyncbreaker.CircuitBreaker(
    fail_max=5, timeout_duration=datetime.timedelta(seconds=60)
)

local_blacklist: cachetools.TTLCache = cachetools.TTLCache(maxsize=10000, ttl=300)
local_rate_limit: cachetools.TTLCache = cachetools.TTLCache(maxsize=10000, ttl=60)

MAX_PENDING_IPS: int = 10000
_pending_buffer_A = collections.deque(maxlen=MAX_PENDING_IPS)
_pending_buffer_B = collections.deque(maxlen=MAX_PENDING_IPS)
_current_buffer = _pending_buffer_A
_backup_buffer = _pending_buffer_B


def init_fail_secure(settings):
    """
    根据 Settings 重新初始化全局 Fail-Secure 对象。
    应在 engine.__init__ 中调用。

    注意：TTLCache 和 CircuitBreaker 创建后不支持动态修改 TTL/maxsize，
    此函数会重建全局对象。必须在 process_log 开始前调用。
    """
    global redis_breaker, local_blacklist, local_rate_limit
    global MAX_PENDING_IPS, _pending_buffer_A, _pending_buffer_B, _current_buffer, _backup_buffer

    redis_breaker = asyncbreaker.CircuitBreaker(
        fail_max=settings.circuit_breaker_fail_max,
        timeout_duration=datetime.timedelta(seconds=settings.circuit_breaker_timeout),
    )
    local_blacklist = cachetools.TTLCache(
        maxsize=settings.max_pending_ips,
        ttl=settings.local_blacklist_ttl,
    )
    local_rate_limit = cachetools.TTLCache(
        maxsize=settings.max_pending_ips,
        ttl=settings.local_rate_limit_ttl,
    )
    MAX_PENDING_IPS = settings.max_pending_ips
    _pending_buffer_A = collections.deque(maxlen=MAX_PENDING_IPS)
    _pending_buffer_B = collections.deque(maxlen=MAX_PENDING_IPS)
    _current_buffer = _pending_buffer_A
    _backup_buffer = _pending_buffer_B


async def background_sync_worker(state_mgr: RedisClusterStateManager, cancel_event: asyncio.Event = None):
    """高优先级写回 Worker (双缓冲机制)"""
    global _current_buffer, _backup_buffer
    while not (cancel_event and cancel_event.is_set()):
        await asyncio.sleep(5)
        if not _current_buffer:
            continue

        # 交换 buffer：_current_buffer 变为 _backup_buffer（供后续写入）
        # _backup_buffer 变为 _current_buffer（待同步的旧数据）
        _current_buffer, _backup_buffer = _backup_buffer, _current_buffer
        # 此时 _backup_buffer 包含待同步的数据
        ips_to_sync = list(_backup_buffer)

        try:
            await state_mgr.batch_block_ips([(ip, "Local_FailSecure") for ip in ips_to_sync])
            # 同步成功，清空 _backup_buffer
            _backup_buffer.clear()
        except Exception:
            # 同步失败，数据保留在 _backup_buffer 中，下次再试
            # 同时将 _current_buffer 的数据也合并过来
            while _current_buffer:
                _backup_buffer.append(_current_buffer.popleft())
            if len(_backup_buffer) >= MAX_PENDING_IPS:
                METRIC_PENDING_OVERFLOW.inc()


class RedisStateFacade:
    def __init__(self, state_mgr: RedisClusterStateManager):
        self.mgr = state_mgr

    async def is_duplicate_and_add(self, trace_id: str, is_retry: bool, retry_count: int) -> bool:
        async with redis_breaker.context():
            return await self.mgr.is_duplicate_and_add(trace_id, is_retry, retry_count)

    async def get_and_update_rate_limit(self, ip: str, event_time: float, window: int, max_req: int) -> list:
        async with redis_breaker.context():
            return await self.mgr.get_and_update_rate_limit(ip, event_time, window, max_req)

    async def batch_block_ips(self, ips_reasons: List[Tuple[str, str]]):
        async with redis_breaker.context():
            await self.mgr.batch_block_ips(ips_reasons)

    async def get_top_keywords(self, n: int = 500) -> List[str]:
        async with redis_breaker.context():
            return await self.mgr.get_top_keywords(n)

    async def batch_add_keywords(self, kws: List[str]):
        if not kws:
            return
        async with redis_breaker.context():
            await self.mgr.batch_add_keywords(kws)
