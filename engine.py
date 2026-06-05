"""
AIWAF-Stream 异步流式检测引擎
"""
import asyncio
import orjson
import asyncbreaker
from concurrent.futures import ProcessPoolExecutor
from concurrent.futures.process import BrokenProcessPool
from aiokafka import AIOKafkaProducer
from prometheus_client import Counter

from acl_bootstrap import init_worker, run_core_logic_batch_isolated, ItemErrorResult
from redis_facade import (
    RedisStateFacade, RedisClusterStateManager,
    local_blacklist, local_rate_limit,
    _current_buffer, _backup_buffer, background_sync_worker
)

METRIC_ENGINE_IN = Counter('aiwaf_engine_in_total', 'Logs received')
METRIC_DLQ_OUT = Counter('aiwaf_dlq_out_total', 'Messages routed to DLQ')
METRIC_POOL_FATAL = Counter('aiwaf_pool_fatal_total', 'ProcessPool broken count')


class AIWAFStreamEngine:
    def __init__(self, settings, state_mgr: RedisClusterStateManager, model_path: str):
        self.facade = RedisStateFacade(state_mgr)
        self.model_path = model_path
        self.settings = settings

        self.core_executor = ProcessPoolExecutor(
            max_workers=settings.core_process_pool_size,
            max_tasks_per_child=200,
            initializer=init_worker,
            initargs=(self.model_path,)
        )
        self.batch_queue = asyncio.Queue(maxsize=10000)

        self.producer = AIOKafkaProducer(
            bootstrap_servers=settings.kafka_brokers,
            enable_idempotence=True, acks='all'
        )

        self.dynamic_keywords_cache = []

    async def start(self):
        await self.producer.start()
        asyncio.create_task(self._batch_dispatcher())
        asyncio.create_task(background_sync_worker(self.facade.mgr))
        asyncio.create_task(self._keyword_refresh_worker())

    async def _keyword_refresh_worker(self):
        """后台独立 Task 每 10 秒刷新缓存"""
        while True:
            try:
                self.dynamic_keywords_cache = await self.facade.get_top_keywords(500)
            except (asyncbreaker.CircuitBreakerError, OSError, asyncio.TimeoutError):
                pass
            await asyncio.sleep(10)

    async def _batch_dispatcher(self):
        """自适应微批调度器 (带 BrokenProcessPool 容错)"""
        while True:
            batch_logs, batch_ts, batch_et, batch_futures = [], [], [], []
            try:
                item = await self.batch_queue.get()
                batch_logs.append(item['log']); batch_ts.append(item['ts'])
                batch_et.append(item['et']); batch_futures.append(item['future'])

                if not self.batch_queue.empty():
                    try:
                        async with asyncio.timeout(0.01):
                            while len(batch_logs) < 50:
                                item = await self.batch_queue.get()
                                batch_logs.append(item['log']); batch_ts.append(item['ts'])
                                batch_et.append(item['et']); batch_futures.append(item['future'])
                    except asyncio.TimeoutError:
                        pass

                current_kws = self.dynamic_keywords_cache

                loop = asyncio.get_running_loop()
                batch_results = await loop.run_in_executor(
                    self.core_executor, run_core_logic_batch_isolated,
                    batch_logs, batch_ts, batch_et, current_kws
                )
                if len(batch_results) != len(batch_futures):
                    min_len = min(len(batch_futures), len(batch_results))
                    for i in range(min_len):
                        batch_futures[i].set_result(batch_results[i])
                    for i in range(min_len, len(batch_futures)):
                        if not batch_futures[i].done():
                            batch_futures[i].set_exception(RuntimeError("Missing batch result"))
                else:
                    for future, result in zip(batch_futures, batch_results):
                        future.set_result(result)
            except BrokenProcessPool:
                METRIC_POOL_FATAL.inc()
                self.core_executor.shutdown(wait=False, cancel_futures=True)
                self.core_executor = ProcessPoolExecutor(
                    max_workers=self.settings.core_process_pool_size,
                    max_tasks_per_child=200,
                    initializer=init_worker,
                    initargs=(self.model_path,)
                )
                for f in batch_futures:
                    if not f.done():
                        f.set_exception(RuntimeError("ProcessPool Broken"))
            except Exception as e:
                for f in batch_futures:
                    if not f.done():
                        f.set_exception(e)

    async def process_log(self, std_log: dict, is_retry=False, retry_count=0):
        METRIC_ENGINE_IN.inc()
        trace_id = std_log["trace_id"]
        ip = std_log["client_ip"]
        event_time = std_log["timestamp"]

        redis_available = True
        try:
            if await self.facade.is_duplicate_and_add(trace_id, is_retry, retry_count):
                return
            timestamps = await self.facade.get_and_update_rate_limit(ip, event_time, 60, 100)
        except asyncbreaker.CircuitBreakerError:
            redis_available = False

            # Fail-Secure 本地防线
            if ip in local_blacklist or ip in _current_buffer or ip in _backup_buffer:
                try:
                    await self._emit_alert(std_log, "Local_Blacklist_Block")
                except Exception:
                    pass
                return

            local_rate_limit[ip] = local_rate_limit.get(ip, 0) + 1
            if local_rate_limit[ip] > 50:
                local_blacklist[ip] = True
                _backup_buffer.append(ip)
                try:
                    await self._emit_alert(std_log, "Local_RateLimit_Block")
                except Exception:
                    pass
                return
            return

        future = asyncio.get_running_loop().create_future()
        await self.batch_queue.put({
            'log': orjson.dumps(std_log), 'ts': timestamps,
            'et': event_time, 'future': future
        })

        try:
            result = await future
        except Exception as e:
            await self._route_to_dlq(std_log, e)
            return

        if isinstance(result, ItemErrorResult):
            if redis_available and result.side_effects.get('blocked_ips'):
                asyncio.create_task(self.facade.batch_block_ips(result.side_effects['blocked_ips']))
            await self._route_to_dlq(std_log, Exception(f"{result.error_type}: {result.error_msg}"))
            return

        if redis_available:
            if result.side_effects['blocked_ips']:
                asyncio.create_task(self.facade.batch_block_ips(result.side_effects['blocked_ips']))
            if result.side_effects['learned_keywords']:
                asyncio.create_task(self._batch_add_keywords(result.side_effects['learned_keywords']))

        if result.rl_decision.action == "flood_block":
            await self._emit_alert(std_log, "RateLimitFlood")
        elif result.kw_decision.block_reason:
            await self._emit_alert(std_log, f"KeywordBlock:{result.kw_decision.block_reason}")

    async def _batch_add_keywords(self, kws: list):
        if not kws:
            return
        try:
            await self.facade.batch_add_keywords(kws)
        except Exception:
            pass

    async def _emit_alert(self, std_log: dict, rule: str):
        alert = {"trace_id": std_log["trace_id"], "rule_id": rule, "alert_timestamp": std_log["timestamp"], "client_ip": std_log["client_ip"]}
        await self.producer.send_and_wait(self.settings.alert_topic, orjson.dumps(alert))

    async def _route_to_dlq(self, std_log: dict, error: Exception):
        METRIC_DLQ_OUT.inc()
        dlq_payload = {
            "trace_id": std_log.get("trace_id"),
            "error": str(error),
            "error_type": type(error).__name__,
            "raw_log": std_log
        }
        await self.producer.send_and_wait(self.settings.dlq_topic, orjson.dumps(dlq_payload))
