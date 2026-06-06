"""
Redis 状态管理、异步熔断与 Fail-Secure 本地防线
"""
import asyncio
import collections
import datetime
import random
import asyncbreaker
import cachetools
from typing import List, Tuple
from prometheus_client import Counter

METRIC_PENDING_OVERFLOW = Counter('aiwaf_pending_overflow_total', 'Shadow table overflow count')


class RedisClusterStateManager:
    def __init__(self, redis_cluster_url: str):
        import redis.asyncio as redis
        self.redis_url = redis_cluster_url
        self.redis = redis.from_url(redis_cluster_url, decode_responses=True)

    async def is_duplicate_and_add(self, trace_id: str, is_retry: bool = False, retry_count: int = 0) -> bool:
        """SETNX 绝对幂等，无 Cluster 热点"""
        idem_key = f"aiwaf:idem:{trace_id}:retry_{retry_count}" if is_retry else f"aiwaf:idem:{trace_id}"
        result = await self.redis.set(idem_key, "1", nx=True, ex=86400)
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
            pipe.set(f"aiwaf:blk:{ip}", reason, ex=3600)
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


redis_breaker = asyncbreaker.CircuitBreaker(fail_max=5, timeout_duration=datetime.timedelta(seconds=60))

local_blacklist = cachetools.TTLCache(maxsize=10000, ttl=300)
local_rate_limit = cachetools.TTLCache(maxsize=10000, ttl=60)

MAX_PENDING_IPS = 10000
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

        _current_buffer, _backup_buffer = _backup_buffer, _current_buffer
        ips_to_sync = list(_current_buffer)
        sync_count = len(ips_to_sync)

        try:
            await state_mgr.batch_block_ips([(ip, "Local_FailSecure") for ip in ips_to_sync])
            for _ in range(sync_count):
                _current_buffer.popleft()
        except Exception:
            if len(_current_buffer) >= MAX_PENDING_IPS:
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
