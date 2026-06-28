"""
AIWAF-Stream 异步流式检测引擎
"""
import asyncio
import time
import orjson
import asyncbreaker
from concurrent.futures import ProcessPoolExecutor
from concurrent.futures.process import BrokenProcessPool
from typing import List
from aiokafka import AIOKafkaProducer, AIOKafkaConsumer
from prometheus_client import Counter

from acl_bootstrap import init_worker, run_core_logic_batch_isolated, ItemErrorResult
from redis_facade import (
    RedisStateFacade, RedisClusterStateManager,
    local_blacklist, local_rate_limit,
    _current_buffer, _backup_buffer, background_sync_worker
)
from aiwaf.core.rate_limit import FLOOD_BLOCK
from akto_adapter import parse_akto_json_message
from preprocessor import transform_raw_log
from aiwaf.core.path_manifest import PathManifest

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

        self.dynamic_keywords_cache: List[str] = []
        self._tasks: list = []
        self._cancel_event = asyncio.Event()
        self.consumer = None
        self.path_manifest = PathManifest()

    async def start(self):
        await self.producer.start()

        # Consumer（新增：消费 Akto Kafka 流量）
        self.consumer = AIOKafkaConsumer(
            self.settings.input_topic,
            bootstrap_servers=self.settings.kafka_brokers,
            group_id=self.settings.consumer_group,
            value_deserializer=lambda v: v,
            key_deserializer=lambda v: v.decode('utf-8') if v else None,
            auto_offset_reset="earliest",
            enable_auto_commit=False,
            max_poll_records=500,
        )
        await self.consumer.start()

        self._tasks.append(asyncio.create_task(self._batch_dispatcher()))
        self._tasks.append(asyncio.create_task(background_sync_worker(self.facade.mgr, self._cancel_event)))
        self._tasks.append(asyncio.create_task(self._keyword_refresh_worker()))
        self._tasks.append(asyncio.create_task(self._consume_loop()))

    async def shutdown(self):
        """优雅关闭：取消后台任务、排空队列、关闭连接。"""
        self._cancel_event.set()
        for t in self._tasks:
            t.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self.core_executor.shutdown(wait=True)
        if self.consumer is not None:
            try:
                await self.consumer.stop()
            except Exception:
                pass
        try:
            await self.producer.stop()
        except Exception:
            pass

    async def _keyword_refresh_worker(self):
        """后台独立 Task 每 10 秒刷新缓存"""
        while not self._cancel_event.is_set():
            try:
                self.dynamic_keywords_cache = await self.facade.get_top_keywords(500)
            except (asyncbreaker.CircuitBreakerError, OSError, asyncio.TimeoutError):
                pass
            try:
                await asyncio.wait_for(
                    asyncio.sleep(10),
                    timeout=10,
                )
            except (asyncio.TimeoutError, asyncio.CancelledError):
                return

    async def _batch_dispatcher(self):
        """自适应微批调度器 (带 BrokenProcessPool 容错)"""
        while not self._cancel_event.is_set():
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
                # 传入已知路径模板集（用于 path_exists 判定）
                known_paths = self.path_manifest.get_all_templates()
                batch_results = await loop.run_in_executor(
                    self.core_executor, run_core_logic_batch_isolated,
                    batch_logs, batch_ts, batch_et, current_kws,
                    (), None, None, (), None,
                    self.settings.rate_limit_flood_threshold, True, known_paths,
                    self.settings.rate_limit_window,
                    self.settings.rate_limit_max_requests,
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
        trace_id = std_log.get("trace_id", "unknown")
        ip = std_log.get("client_ip", "unknown")
        event_time = std_log.get("timestamp", 0.0)

        # 记录路径到 Path Manifest（用于 path_exists 判定）
        self.path_manifest.record(
            path=std_log.get("uri_path", "/"),
            method=std_log.get("method", "GET"),
            status_code=std_log.get("status_code", 0),
        )

        redis_available = True
        try:
            if await self.facade.is_duplicate_and_add(trace_id, is_retry, retry_count):
                return
            timestamps = await self.facade.get_and_update_rate_limit(
                ip, event_time,
                self.settings.rate_limit_window,
                self.settings.rate_limit_max_requests,
            )
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
            if local_rate_limit[ip] > self.settings.fail_secure_local_limit:
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
            try:
                await self._route_to_dlq(std_log, e)
            except Exception:
                pass
            return

        if isinstance(result, ItemErrorResult):
            if redis_available and result.side_effects.get('blocked_ips'):
                asyncio.create_task(self.facade.batch_block_ips(result.side_effects.get('blocked_ips', [])))
            try:
                await self._route_to_dlq(std_log, Exception(f"{result.error_type}: {result.error_msg}"))
            except Exception:
                pass
            return

        if redis_available:
            if result.side_effects.get('blocked_ips'):
                asyncio.create_task(self.facade.batch_block_ips(result.side_effects.get('blocked_ips', [])))
            if result.side_effects.get('learned_keywords'):
                asyncio.create_task(self._batch_add_keywords(result.side_effects.get('learned_keywords', [])))

        if result.rl_decision.action == FLOOD_BLOCK:
            try:
                await self._emit_alert(std_log, "RateLimitFlood")
            except Exception:
                pass
        elif result.kw_decision.block_reason:
            try:
                await self._emit_alert(std_log, f"KeywordBlock:{result.kw_decision.block_reason}")
            except Exception:
                pass

    async def _batch_add_keywords(self, kws: list):
        if not kws:
            return
        try:
            await self.facade.batch_add_keywords(kws)
        except Exception:
            pass

    async def _emit_alert(self, std_log: dict, rule: str):
        alert = {
            # 现有字段
            "trace_id": std_log.get("trace_id"),
            "rule_id": rule,
            "alert_timestamp": std_log.get("timestamp"),
            "client_ip": std_log.get("client_ip"),

            # 新增：akto 上下文（便于 akto 侧关联分析）
            "akto_account_id": std_log.get("akto_account_id", ""),
            "akto_vxlan_id": std_log.get("akto_vxlan_id", ""),
            "source": std_log.get("source", ""),
            "direction": std_log.get("direction", ""),

            # 新增：请求上下文
            "method": std_log.get("method", "GET"),
            "uri_path": std_log.get("uri_path", "/"),
            "status_code": std_log.get("status_code", 200),

            # 新增：检测元数据
            "detected_at": time.time(),
            "severity": self._classify_severity(rule),
            "req_body_truncated": std_log.get("req_body_truncated", ""),
        }
        await self.producer.send_and_wait(self.settings.alert_topic, orjson.dumps(alert))

    def _classify_severity(self, rule: str) -> str:
        """根据规则名称分类严重程度"""
        rule_lower = (rule or "").lower()
        if "flood" in rule_lower or "ratelimit" in rule_lower:
            return "MEDIUM"
        if "keyword" in rule_lower:
            return "HIGH"
        if "blacklist" in rule_lower:
            return "HIGH"
        return "LOW"

    async def _consume_loop(self):
        """Kafka 消费循环 — 消费 akto.api.logs，适配后送入检测引擎"""
        while not self._cancel_event.is_set():
            try:
                async for batch in self.consumer:
                    for msg in batch:
                        try:
                            # JSON → raw_log dict
                            raw_log = parse_akto_json_message(msg.value.decode('utf-8'))
                            # raw_log → std_log (生成 trace_id, 拆分 query, 截断 body)
                            std_log = transform_raw_log(raw_log)
                            await self.process_log(std_log)
                        except Exception as e:
                            # 处理失败 → DLQ
                            try:
                                dlq_payload = {
                                    "trace_id": None,
                                    "error": f"Processing failed: {e}",
                                    "error_type": type(e).__name__,
                                    "raw_log": msg.value.hex(),
                                    "topic": msg.topic,
                                    "partition": msg.partition,
                                    "offset": msg.offset,
                                }
                                await self.producer.send_and_wait(
                                    self.settings.dlq_topic,
                                    orjson.dumps(dlq_payload)
                                )
                                METRIC_DLQ_OUT.inc()
                            except Exception:
                                # DLQ 发送也失败，记录日志后继续，不阻断消费
                                pass

                    # 手动提交 offset（commit 失败不阻断，下次会重新消费）
                    try:
                        await self.consumer.commit()
                    except Exception:
                        pass

                    if self._cancel_event.is_set():
                        break
            except asyncio.CancelledError:
                break
            except Exception:
                # 消费循环异常（如 Kafka rebalance），等待后重试
                try:
                    await asyncio.sleep(5)
                except asyncio.CancelledError:
                    break

    async def _route_to_dlq(self, std_log: dict, error: Exception):
        METRIC_DLQ_OUT.inc()
        dlq_payload = {
            "trace_id": std_log.get("trace_id"),
            "error": str(error),
            "error_type": type(error).__name__,
            "raw_log": std_log
        }
        await self.producer.send_and_wait(self.settings.dlq_topic, orjson.dumps(dlq_payload))
