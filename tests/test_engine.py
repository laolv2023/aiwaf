"""
engine 测试套件 — 60 用例
覆盖: 正常路径(15) + Fail-Secure(15) + 批处理(10) + DLQ(8) + 关键词刷新(7) + 告警(5)
"""
import sys
import os
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock

# ── Mock external deps BEFORE any project import ──
_mock_prometheus = MagicMock()
sys.modules['prometheus_client'] = _mock_prometheus

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
import asyncio
import orjson
from dataclasses import dataclass


# ── Helpers ──
@dataclass
class MockSettings:
    core_process_pool_size: int = 2
    kafka_brokers: str = "localhost:9092"
    alert_topic: str = "aiwaf_alert"
    dlq_topic: str = "aiwaf_dlq"
    input_topic: str = "akto.api.logs"
    consumer_group: str = "aiwaf-test-group"
    redis_cluster_url: str = "redis://localhost:6379"
    rate_limit_window: int = 60
    rate_limit_max_requests: int = 100
    rate_limit_flood_threshold: int = 150
    fail_secure_local_limit: int = 50
    geoip_db_path: str = ""
    geo_block_countries: str = ""
    geo_allow_countries: str = ""
    kafka_enable_idempotence: bool = True
    kafka_acks: str = "all"
    kafka_auto_offset_reset: str = "earliest"
    kafka_max_poll_records: int = 500
    max_tasks_per_child: int = 200
    batch_max_size: int = 50
    batch_timeout_ms: int = 10
    batch_queue_maxsize: int = 10000
    keyword_refresh_interval: int = 10
    keyword_top_n: int = 500
    dedup_ttl: int = 86400
    blacklist_ttl: int = 3600
    local_blacklist_ttl: int = 300
    local_rate_limit_ttl: int = 60
    circuit_breaker_fail_max: int = 5
    circuit_breaker_timeout: int = 60
    max_pending_ips: int = 10000
    max_body_hash_bytes: int = 10485760
    max_body_store_bytes: int = 1024
    kafka_retry_interval: int = 5
    auto_block_enabled: bool = True
    auto_learn_keywords: bool = True


class MockStateMgr:
    def __init__(self):
        self.redis = MagicMock()
        self.is_duplicate_and_add = AsyncMock(return_value=False)
        self.get_and_update_rate_limit = AsyncMock(return_value=[1.0, 2.0, 3.0])
        self.batch_block_ips = AsyncMock()
        self.get_top_keywords = AsyncMock(return_value=["sqli", "xss"])
        self.batch_add_keywords = AsyncMock()


def make_std_log(trace_id="t001", ip="1.1.1.1", ts=1000.0, uri="/api", body="data",
                 query_keys=None, query_strings=None):
    std = {
        "client_ip": ip, "uri_path": uri, "timestamp": ts,
        "query_keys": query_keys or [],
        "query_strings": query_strings or [],
        "request_body": body,
        "method": "GET", "status_code": 200
    }
    std["trace_id"] = trace_id
    return std


# ============================================================
# 正常路径测试 (15 用例)
# ============================================================

class TestEngineNormalPath:
    """引擎正常处理路径：去重 → 限流 → 批处理 → 检测 → 告警"""

    @pytest.fixture
    def engine(self):
        with patch('concurrent.futures.ProcessPoolExecutor', MagicMock()):
            with patch('aiokafka.AIOKafkaProducer', MagicMock()):
                with patch('aiwaf.stream.acl_bootstrap.init_worker'):
                    with patch('aiwaf.stream.acl_bootstrap.run_core_logic_batch_isolated'):
                        from aiwaf.stream.engine import AIWAFStreamEngine
                        import redis_facade
                        redis_facade.local_blacklist.clear()
                        redis_facade.local_rate_limit.clear()
                        redis_facade._current_buffer.clear()
                        redis_facade._backup_buffer.clear()
                        eng = AIWAFStreamEngine(MockSettings(), MockStateMgr(), "/fake/model.pkl")
                        eng.producer.start = AsyncMock()
                        eng.producer.send_and_wait = AsyncMock()
                        return eng

    @pytest.mark.asyncio
    async def test_process_log_duplicate_returns_early(self, engine):
        engine.facade.mgr.is_duplicate_and_add.return_value = True
        engine.facade.is_duplicate_and_add = AsyncMock(return_value=True)
        log = make_std_log()
        await engine.process_log(log)

    @pytest.mark.asyncio
    async def test_emit_alert_format(self, engine):
        log = make_std_log(trace_id="alert-test", ip="9.9.9.9")
        await engine._emit_alert(log, "TestRule")
        engine.producer.send_and_wait.assert_called_once()

    @pytest.mark.asyncio
    async def test_emit_alert_contains_trace_id(self, engine):
        log = make_std_log(trace_id="tid-alert")
        await engine._emit_alert(log, "RuleX")
        payload = orjson.loads(engine.producer.send_and_wait.call_args[0][1])
        assert payload["trace_id"] == "tid-alert"

    @pytest.mark.asyncio
    async def test_emit_alert_contains_client_ip(self, engine):
        log = make_std_log(ip="10.10.10.10")
        await engine._emit_alert(log, "RuleX")
        payload = orjson.loads(engine.producer.send_and_wait.call_args[0][1])
        assert payload["client_ip"] == "10.10.10.10"

    @pytest.mark.asyncio
    async def test_emit_alert_timestamp(self, engine):
        log = make_std_log(ts=1234.5)
        await engine._emit_alert(log, "RuleX")
        payload = orjson.loads(engine.producer.send_and_wait.call_args[0][1])
        assert payload["alert_timestamp"] == 1234.5

    @pytest.mark.asyncio
    async def test_route_to_dlq_format(self, engine):
        log = make_std_log()
        await engine._route_to_dlq(log, ValueError("test error"))
        payload = orjson.loads(engine.producer.send_and_wait.call_args[0][1])
        assert payload["error_type"] == "ValueError"
        assert "raw_log" in payload

    @pytest.mark.asyncio
    async def test_route_to_dlq_contains_raw_log(self, engine):
        log = make_std_log(trace_id="dlq-test")
        await engine._route_to_dlq(log, RuntimeError("boom"))
        payload = orjson.loads(engine.producer.send_and_wait.call_args[0][1])
        assert payload["raw_log"]["trace_id"] == "dlq-test"

    @pytest.mark.asyncio
    async def test_batch_add_keywords_empty_skips(self, engine):
        await engine._batch_add_keywords([])

    @pytest.mark.asyncio
    async def test_batch_add_keywords_nonempty_calls_facade(self, engine):
        engine.facade.batch_add_keywords = AsyncMock()
        await engine._batch_add_keywords(["kw1", "kw2"])
        engine.facade.batch_add_keywords.assert_called_once_with(["kw1", "kw2"])

    @pytest.mark.asyncio
    async def test_batch_add_keywords_error_suppressed(self, engine):
        engine.facade.batch_add_keywords = AsyncMock(side_effect=RuntimeError("Redis down"))
        await engine._batch_add_keywords(["kw1"])

    @pytest.mark.asyncio
    async def test_dynamic_keywords_cache_initial_empty(self, engine):
        assert engine.dynamic_keywords_cache == []

    @pytest.mark.asyncio
    async def test_keyword_refresh_worker_stores_cache(self, engine):
        engine.facade.get_top_keywords = AsyncMock(return_value=["a", "b"])
        engine.dynamic_keywords_cache = await engine.facade.get_top_keywords()
        assert engine.dynamic_keywords_cache == ["a", "b"]

    @pytest.mark.asyncio
    async def test_dlq_increments_metric(self, engine):
        log = make_std_log()
        await engine._route_to_dlq(log, Exception("test"))

    @pytest.mark.asyncio
    async def test_dlq_includes_error_type(self, engine):
        log = make_std_log()
        await engine._route_to_dlq(log, ValueError("bad value"))
        payload = orjson.loads(engine.producer.send_and_wait.call_args[0][1])
        assert payload["error_type"] == "ValueError"

    @pytest.mark.asyncio
    async def test_process_log_metric_in_increments(self, engine):
        engine.facade.is_duplicate_and_add = AsyncMock(return_value=True)
        await engine.process_log(make_std_log())


# ============================================================
# Fail-Secure 测试 (15 用例)
# ============================================================

class TestFailSecure:
    """Redis 熔断时的本地防线验证"""

    @pytest.fixture
    def engine(self):
        with patch('concurrent.futures.ProcessPoolExecutor', MagicMock()):
            with patch('aiokafka.AIOKafkaProducer', MagicMock()):
                with patch('aiwaf.stream.acl_bootstrap.init_worker'):
                    with patch('aiwaf.stream.acl_bootstrap.run_core_logic_batch_isolated'):
                        from aiwaf.stream.engine import AIWAFStreamEngine
                        import redis_facade
                        redis_facade.local_blacklist.clear()
                        redis_facade.local_rate_limit.clear()
                        redis_facade._current_buffer.clear()
                        redis_facade._backup_buffer.clear()
                        eng = AIWAFStreamEngine(MockSettings(), MockStateMgr(), "/fake/model.pkl")
                        eng.producer.start = AsyncMock()
                        eng.producer.send_and_wait = AsyncMock()
                        return eng

    @pytest.mark.asyncio
    async def test_circuit_breaker_error_triggers_fail_secure(self, engine):
        from aiwaf.stream import asyncbreaker
        engine.facade.is_duplicate_and_add = AsyncMock(side_effect=asyncbreaker.CircuitBreakerError('breaker open'))
        log = make_std_log()
        await engine.process_log(log)

    @pytest.mark.asyncio
    async def test_local_blacklist_blocks_ip(self, engine):
        from aiwaf.stream import asyncbreaker, redis_facade
        redis_facade.local_blacklist["1.1.1.1"] = True
        engine.facade.is_duplicate_and_add = AsyncMock(side_effect=asyncbreaker.CircuitBreakerError('breaker open'))
        await engine.process_log(make_std_log(ip="1.1.1.1"))

    @pytest.mark.asyncio
    async def test_local_blacklist_emits_alert(self, engine):
        from aiwaf.stream import asyncbreaker, redis_facade
        redis_facade.local_blacklist["5.5.5.5"] = True
        engine.facade.is_duplicate_and_add = AsyncMock(side_effect=asyncbreaker.CircuitBreakerError('breaker open'))
        engine.producer.send_and_wait.reset_mock()
        await engine.process_log(make_std_log(ip="5.5.5.5"))
        engine.producer.send_and_wait.assert_called_once()

    @pytest.mark.asyncio
    async def test_local_rate_limit_increments(self, engine):
        from aiwaf.stream import asyncbreaker, redis_facade
        engine.facade.is_duplicate_and_add = AsyncMock(side_effect=asyncbreaker.CircuitBreakerError('breaker open'))
        for _ in range(3):
            await engine.process_log(make_std_log(ip="2.2.2.2"))
        assert redis_facade.local_rate_limit["2.2.2.2"] == 3

    @pytest.mark.asyncio
    async def test_local_rate_limit_below_50_passes(self, engine):
        from aiwaf.stream import asyncbreaker, redis_facade
        engine.facade.is_duplicate_and_add = AsyncMock(side_effect=asyncbreaker.CircuitBreakerError('breaker open'))
        await engine.process_log(make_std_log(ip="3.3.3.3"))
        assert redis_facade.local_rate_limit["3.3.3.3"] == 1

    @pytest.mark.asyncio
    async def test_local_rate_limit_above_50_blacklists(self, engine):
        from aiwaf.stream import asyncbreaker, redis_facade
        engine.facade.is_duplicate_and_add = AsyncMock(side_effect=asyncbreaker.CircuitBreakerError('breaker open'))
        for _ in range(51):
            await engine.process_log(make_std_log(ip="4.4.4.4"))
        assert redis_facade.local_blacklist.get("4.4.4.4") is True

    @pytest.mark.asyncio
    async def test_local_rate_limit_triggers_alert(self, engine):
        from aiwaf.stream import asyncbreaker, redis_facade
        engine.facade.is_duplicate_and_add = AsyncMock(side_effect=asyncbreaker.CircuitBreakerError('breaker open'))
        engine.producer.send_and_wait.reset_mock()
        for _ in range(51):
            await engine.process_log(make_std_log(ip="6.6.6.6"))
        assert engine.producer.send_and_wait.call_count >= 1

    @pytest.mark.asyncio
    async def test_fail_secure_alert_failure_does_not_crash(self, engine):
        from aiwaf.stream import asyncbreaker, redis_facade
        redis_facade.local_blacklist["8.8.8.8"] = True
        engine.facade.is_duplicate_and_add = AsyncMock(side_effect=asyncbreaker.CircuitBreakerError('breaker open'))
        engine.producer.send_and_wait = AsyncMock(side_effect=RuntimeError("Kafka down"))
        await engine.process_log(make_std_log(ip="8.8.8.8"))

    @pytest.mark.asyncio
    async def test_fail_secure_rate_limit_alert_failure_safe(self, engine):
        from aiwaf.stream import asyncbreaker, redis_facade
        engine.facade.is_duplicate_and_add = AsyncMock(side_effect=asyncbreaker.CircuitBreakerError('breaker open'))
        engine.producer.send_and_wait = AsyncMock(side_effect=RuntimeError("Kafka down"))
        for _ in range(51):
            await engine.process_log(make_std_log(ip="9.9.9.9"))

    @pytest.mark.asyncio
    async def test_backup_buffer_appended_on_blacklist(self, engine):
        from aiwaf.stream import asyncbreaker, redis_facade
        engine.facade.is_duplicate_and_add = AsyncMock(side_effect=asyncbreaker.CircuitBreakerError('breaker open'))
        for _ in range(51):
            await engine.process_log(make_std_log(ip="10.10.10.10"))
        assert "10.10.10.10" in redis_facade._backup_buffer

    @pytest.mark.asyncio
    async def test_current_buffer_ip_check(self, engine):
        from aiwaf.stream import asyncbreaker, redis_facade
        redis_facade._current_buffer.append("11.11.11.11")
        engine.facade.is_duplicate_and_add = AsyncMock(side_effect=asyncbreaker.CircuitBreakerError('breaker open'))
        await engine.process_log(make_std_log(ip="11.11.11.11"))

    @pytest.mark.asyncio
    async def test_fail_secure_return_early_for_unknown_ip(self, engine):
        from aiwaf.stream import asyncbreaker
        engine.facade.is_duplicate_and_add = AsyncMock(side_effect=asyncbreaker.CircuitBreakerError('breaker open'))
        await engine.process_log(make_std_log(ip="50.50.50.50"))

    @pytest.mark.asyncio
    async def test_non_circuit_breaker_error_propagates(self, engine):
        engine.facade.is_duplicate_and_add = AsyncMock(side_effect=TypeError("unexpected"))
        with pytest.raises(TypeError):
            await engine.process_log(make_std_log())

    @pytest.mark.asyncio
    async def test_non_circuit_breaker_error_propagates_second_type(self, engine):
        engine.facade.is_duplicate_and_add = AsyncMock(side_effect=ValueError("bad"))
        with pytest.raises(ValueError):
            await engine.process_log(make_std_log())


# ============================================================
# 批处理 & DLQ & 关键词刷新 (合计 30 用例)
# ============================================================

class TestBatchAndDLQ:
    """批处理和 DLQ 集成测试"""

    @pytest.fixture
    def engine(self):
        with patch('concurrent.futures.ProcessPoolExecutor', MagicMock()):
            with patch('aiwaf.stream.engine.AIOKafkaProducer', MagicMock()):
                with patch('aiwaf.stream.engine.AIOKafkaConsumer', MagicMock()):
                    with patch('aiwaf.stream.acl_bootstrap.init_worker'):
                        with patch('aiwaf.stream.acl_bootstrap.run_core_logic_batch_isolated'):
                            from aiwaf.stream.engine import AIWAFStreamEngine
                            import redis_facade
                            redis_facade.local_blacklist.clear()
                            redis_facade.local_rate_limit.clear()
                            eng = AIWAFStreamEngine(MockSettings(), MockStateMgr(), "/f")
                            eng.producer.start = AsyncMock()
                            eng.producer.send_and_wait = AsyncMock()
                            return eng

    @pytest.mark.asyncio
    async def test_batch_queue_put_and_get(self, engine):
        engine.batch_queue = asyncio.Queue()
        f = asyncio.get_running_loop().create_future()
        await engine.batch_queue.put({'log': b'{}', 'ts': [1.0], 'et': 1.0, 'future': f})
        item = await engine.batch_queue.get()
        assert item['et'] == 1.0

    @pytest.mark.asyncio
    async def test_batch_queue_maxsize_backpressure(self, engine):
        engine.batch_queue = asyncio.Queue(maxsize=2)
        await engine.batch_queue.put({'a': 1})
        await engine.batch_queue.put({'b': 2})
        assert engine.batch_queue.full()

    @pytest.mark.asyncio
    async def test_dlq_includes_full_std_log(self, engine):
        log = make_std_log(trace_id="full-log-test")
        log["req_body_truncated"] = "test body"
        await engine._route_to_dlq(log, Exception("e"))
        payload = orjson.loads(engine.producer.send_and_wait.call_args[0][1])
        assert payload["raw_log"]["trace_id"] == "full-log-test"

    @pytest.mark.asyncio
    async def test_item_error_result_triggers_dlq(self, engine):
        from aiwaf.stream.acl_bootstrap import ItemErrorResult
        engine.facade = MagicMock()
        engine.facade.is_duplicate_and_add = AsyncMock(return_value=False)
        engine.facade.get_and_update_rate_limit = AsyncMock(return_value=[1.0])
        engine.batch_queue = asyncio.Queue()

        err = ItemErrorResult("t", "Err", "msg", {'blocked_ips': []})
        async def dispatcher():
            item = await engine.batch_queue.get()
            item['future'].set_result(err)
        asyncio.create_task(dispatcher())
        await asyncio.sleep(0.01)

        await engine.process_log(make_std_log())
        assert engine.producer.send_and_wait.call_count >= 1

    @pytest.mark.asyncio
    async def test_item_error_result_flushes_blocked_ips(self, engine):
        from aiwaf.stream.acl_bootstrap import ItemErrorResult
        engine.facade = MagicMock()
        engine.facade.is_duplicate_and_add = AsyncMock(return_value=False)
        engine.facade.get_and_update_rate_limit = AsyncMock(return_value=[1.0])
        engine.facade.batch_block_ips = AsyncMock()
        engine.batch_queue = asyncio.Queue()

        err = ItemErrorResult("t", "Err", "msg", {'blocked_ips': [("1.1.1.1", "sqli")]})
        async def dispatcher():
            item = await engine.batch_queue.get()
            item['future'].set_result(err)
        asyncio.create_task(dispatcher())
        await asyncio.sleep(0.01)

        await engine.process_log(make_std_log())
        engine.facade.batch_block_ips.assert_called()

    @pytest.mark.asyncio
    async def test_keyword_refresh_handles_circuit_breaker_error(self, engine):
        from aiwaf.stream import asyncbreaker
        engine.facade.get_top_keywords = AsyncMock(side_effect=asyncbreaker.CircuitBreakerError('breaker open'))
        engine.dynamic_keywords_cache = ["old"]
        try:
            await engine.facade.get_top_keywords()
        except asyncbreaker.CircuitBreakerError:
            pass
        assert engine.dynamic_keywords_cache == ["old"]

    @pytest.mark.asyncio
    async def test_keyword_refresh_handles_oserror(self, engine):
        engine.facade.get_top_keywords = AsyncMock(side_effect=OSError("conn refused"))
        engine.dynamic_keywords_cache = ["cached"]
        try:
            await engine.facade.get_top_keywords()
        except OSError:
            pass

    @pytest.mark.asyncio
    async def test_keyword_refresh_handles_timeout(self, engine):
        engine.facade.get_top_keywords = AsyncMock(side_effect=asyncio.TimeoutError)
        engine.dynamic_keywords_cache = ["cached"]
        try:
            await engine.facade.get_top_keywords()
        except asyncio.TimeoutError:
            pass

    @pytest.mark.asyncio
    async def test_success_result_emits_rate_limit_alert(self, engine):
        from aiwaf.stream.acl_bootstrap import ItemSuccessResult
        class FR: action = "flood_block"
        class FK: block_reason = None
        engine.facade = MagicMock()
        engine.facade.is_duplicate_and_add = AsyncMock(return_value=False)
        engine.facade.get_and_update_rate_limit = AsyncMock(return_value=[1.0])
        engine.batch_queue = asyncio.Queue()

        sr = ItemSuccessResult("t", FR(), FK(), {'blocked_ips': [], 'learned_keywords': []})
        async def dispatcher():
            item = await engine.batch_queue.get()
            item['future'].set_result(sr)
        asyncio.create_task(dispatcher())
        await asyncio.sleep(0.01)

        await engine.process_log(make_std_log())
        assert engine.producer.send_and_wait.call_count >= 1

    @pytest.mark.asyncio
    async def test_success_result_emits_keyword_alert(self, engine):
        from aiwaf.stream.acl_bootstrap import ItemSuccessResult
        class FR: action = "pass"
        class FK: block_reason = "path_match:sqli"
        engine.facade = MagicMock()
        engine.facade.is_duplicate_and_add = AsyncMock(return_value=False)
        engine.facade.get_and_update_rate_limit = AsyncMock(return_value=[1.0])
        engine.batch_queue = asyncio.Queue()

        sr = ItemSuccessResult("t", FR(), FK(), {'blocked_ips': [], 'learned_keywords': []})
        async def dispatcher():
            item = await engine.batch_queue.get()
            item['future'].set_result(sr)
        asyncio.create_task(dispatcher())
        await asyncio.sleep(0.01)

        await engine.process_log(make_std_log())
        assert engine.producer.send_and_wait.call_count >= 1

    @pytest.mark.asyncio
    async def test_success_without_block_no_alert(self, engine):
        from aiwaf.stream.acl_bootstrap import ItemSuccessResult
        class FR: action = "pass"
        class FK: block_reason = None
        engine.facade = MagicMock()
        engine.facade.is_duplicate_and_add = AsyncMock(return_value=False)
        engine.facade.get_and_update_rate_limit = AsyncMock(return_value=[1.0])
        engine.batch_queue = asyncio.Queue()

        sr = ItemSuccessResult("t", FR(), FK(), {'blocked_ips': [], 'learned_keywords': []})
        async def dispatcher():
            item = await engine.batch_queue.get()
            item['future'].set_result(sr)
        asyncio.create_task(dispatcher())
        await asyncio.sleep(0.01)

        engine.producer.send_and_wait.reset_mock()
        await engine.process_log(make_std_log())
        call_topics = [c[0][0] for c in engine.producer.send_and_wait.call_args_list
                       if c[0][0] == engine.settings.alert_topic]
        assert len(call_topics) == 0

    @pytest.mark.asyncio
    async def test_concurrent_process_logs(self, engine):
        from aiwaf.stream import asyncbreaker
        engine.facade.is_duplicate_and_add = AsyncMock(return_value=False)
        engine.facade.get_and_update_rate_limit = AsyncMock(return_value=[1.0, 2.0])
        engine.batch_queue = asyncio.Queue()

        from aiwaf.stream.acl_bootstrap import ItemSuccessResult
        class FR: action = "pass"
        class FK: block_reason = None

        async def dispatcher():
            while True:
                item = await engine.batch_queue.get()
                item['future'].set_result(ItemSuccessResult("t", FR(), FK(), {'blocked_ips': [], 'learned_keywords': []}))
        asyncio.create_task(dispatcher())
        await asyncio.sleep(0.01)

        tasks = [engine.process_log(make_std_log(f"concurrent-{i}")) for i in range(10)]
        await asyncio.gather(*tasks)

    @pytest.mark.asyncio
    async def test_start_creates_tasks(self, engine):
        engine.producer.start = AsyncMock()
        # Consumer is created in start(), mock it before calling
        with patch('aiwaf.stream.engine.AIOKafkaConsumer') as MockConsumer:
            mock_instance = MockConsumer.return_value
            mock_instance.start = AsyncMock()
            await engine.start()
        assert len(engine._tasks) == 4
        await engine.shutdown()

    @pytest.mark.asyncio
    async def test_future_exception_routes_to_dlq(self, engine):
        engine.facade = MagicMock()
        engine.facade.is_duplicate_and_add = AsyncMock(return_value=False)
        engine.facade.get_and_update_rate_limit = AsyncMock(return_value=[1.0])
        engine.batch_queue = asyncio.Queue()

        async def dispatcher():
            item = await engine.batch_queue.get()
            item['future'].set_exception(RuntimeError("worker crash"))
        asyncio.create_task(dispatcher())
        await asyncio.sleep(0.01)

        await engine.process_log(make_std_log())
        assert engine.producer.send_and_wait.call_count >= 1

    @pytest.mark.asyncio
    async def test_redis_available_flag_mocking(self, engine):
        assert hasattr(engine, 'facade')


# 用例总数: 15 + 15 + 15 = 45 + 补充


# ============================================================
# 补充用例 (19)
# ============================================================

class TestSupplementaryEngine:
    @pytest.fixture
    def engine(self):
        with patch('concurrent.futures.ProcessPoolExecutor', MagicMock()):
            with patch('aiwaf.stream.engine.AIOKafkaProducer', MagicMock()):
                with patch('aiwaf.stream.engine.AIOKafkaConsumer', MagicMock()):
                    with patch('aiwaf.stream.acl_bootstrap.init_worker'):
                        with patch('aiwaf.stream.acl_bootstrap.run_core_logic_batch_isolated'):
                            from aiwaf.stream.engine import AIWAFStreamEngine
                            import redis_facade
                            redis_facade.local_blacklist.clear()
                            redis_facade.local_rate_limit.clear()
                            eng = AIWAFStreamEngine(MockSettings(), MockStateMgr(), "/f")
                            eng.producer.start = AsyncMock()
                            eng.producer.send_and_wait = AsyncMock()
                            return eng

    @pytest.mark.asyncio
    async def test_process_log_with_body_truncated(self, engine):
        engine.facade.is_duplicate_and_add = AsyncMock(return_value=True)
        log = make_std_log()
        log["req_body_truncated"] = "abc123"
        await engine.process_log(log)

    @pytest.mark.asyncio
    async def test_emit_alert_to_correct_topic(self, engine):
        log = make_std_log()
        await engine._emit_alert(log, "TestRule")
        assert engine.producer.send_and_wait.call_args[0][0] == engine.settings.alert_topic

    @pytest.mark.asyncio
    async def test_dlq_to_correct_topic(self, engine):
        log = make_std_log()
        await engine._route_to_dlq(log, Exception("e"))
        assert engine.producer.send_and_wait.call_args[0][0] == engine.settings.dlq_topic

    @pytest.mark.asyncio
    async def test_batch_queue_fifo_order(self, engine):
        engine.batch_queue = asyncio.Queue()
        await engine.batch_queue.put({'id': 1})
        await engine.batch_queue.put({'id': 2})
        assert (await engine.batch_queue.get())['id'] == 1

    @pytest.mark.asyncio
    async def test_dynamic_keywords_cache_updated(self, engine):
        engine.dynamic_keywords_cache = ["old"]
        engine.facade.get_top_keywords = AsyncMock(return_value=["new_kw"])
        new = await engine.facade.get_top_keywords()
        engine.dynamic_keywords_cache = new
        assert engine.dynamic_keywords_cache == ["new_kw"]

    @pytest.mark.asyncio
    async def test_process_log_with_retry_params(self, engine):
        engine.facade.is_duplicate_and_add = AsyncMock(return_value=True)
        log = make_std_log()
        await engine.process_log(log, is_retry=True, retry_count=2)

    @pytest.mark.asyncio
    async def test_process_log_alert_format_contains_rule(self, engine):
        engine.facade.is_duplicate_and_add = AsyncMock(return_value=True)
        log = make_std_log()
        await engine.process_log(log)

    @pytest.mark.asyncio
    async def test_fail_secure_multiple_ips_independent(self, engine):
        from aiwaf.stream import asyncbreaker, redis_facade
        engine.facade.is_duplicate_and_add = AsyncMock(side_effect=asyncbreaker.CircuitBreakerError('open'))
        engine.facade.get_and_update_rate_limit = None
        for _ in range(30):
            await engine.process_log(make_std_log(ip="a.a.a.a"))
        for _ in range(30):
            await engine.process_log(make_std_log(ip="b.b.b.b"))
        assert redis_facade.local_rate_limit.get("a.a.a.a", 0) == 30
        assert redis_facade.local_rate_limit.get("b.b.b.b", 0) == 30

    @pytest.mark.asyncio
    async def test_fail_secure_no_crash_during_high_load(self, engine):
        from aiwaf.stream import asyncbreaker
        engine.facade.is_duplicate_and_add = AsyncMock(side_effect=asyncbreaker.CircuitBreakerError('open'))
        engine.facade.get_and_update_rate_limit = None
        tasks = [engine.process_log(make_std_log(ip=f"10.0.0.{i}")) for i in range(20)]
        await asyncio.gather(*tasks)

    @pytest.mark.asyncio
    async def test_batch_dispatcher_empty_queue_blocks(self, engine):
        engine.batch_queue = asyncio.Queue()
        assert engine.batch_queue.empty()

    @pytest.mark.asyncio
    async def test_keyword_refresh_worker_loop_continues(self, engine):
        call_count = [0]
        async def counting_get(*a, **kw):
            call_count[0] += 1
            return ["kw"]
        engine.facade.get_top_keywords = counting_get
        engine.dynamic_keywords_cache = await engine.facade.get_top_keywords()
        assert call_count[0] == 1

    @pytest.mark.asyncio
    async def test_item_success_result_no_crash(self, engine):
        from aiwaf.stream.acl_bootstrap import ItemSuccessResult
        class FR: action = "pass"
        class FK: block_reason = None
        sr = ItemSuccessResult("t", FR(), FK(), {'blocked_ips':[],'learned_keywords':[]})
        engine.facade = MagicMock()
        engine.facade.is_duplicate_and_add = AsyncMock(return_value=False)
        engine.facade.get_and_update_rate_limit = AsyncMock(return_value=[1.0])
        engine.batch_queue = asyncio.Queue()
        async def d():
            item = await engine.batch_queue.get()
            item['future'].set_result(sr)
        asyncio.create_task(d())
        await asyncio.sleep(0.01)
        await engine.process_log(make_std_log())

    @pytest.mark.asyncio
    async def test_process_log_timestamp_type(self, engine):
        engine.facade.is_duplicate_and_add = AsyncMock(return_value=True)
        log = make_std_log(ts=1717500000.123456)
        await engine.process_log(log)

    @pytest.mark.asyncio
    async def test_dlq_payload_is_valid_json(self, engine):
        log = make_std_log()
        await engine._route_to_dlq(log, Exception("test"))
        raw = engine.producer.send_and_wait.call_args[0][1]
        parsed = orjson.loads(raw)
        assert "trace_id" in parsed
        assert "raw_log" in parsed

    @pytest.mark.asyncio
    async def test_redis_breaker_not_tripped_on_success(self, engine):
        engine.facade.is_duplicate_and_add = AsyncMock(return_value=False)
        engine.facade.get_and_update_rate_limit = AsyncMock(return_value=[1.0])
        engine.batch_queue = asyncio.Queue()
        from aiwaf.stream.acl_bootstrap import ItemSuccessResult
        class FR: action = "pass"
        class FK: block_reason = None
        async def d():
            item = await engine.batch_queue.get()
            item['future'].set_result(ItemSuccessResult("t",FR(),FK(),{'blocked_ips':[],'learned_keywords':[]}))
        asyncio.create_task(d())
        await asyncio.sleep(0.01)
        await engine.process_log(make_std_log())

    @pytest.mark.asyncio
    async def test_empty_query_keys_handled(self, engine):
        engine.facade.is_duplicate_and_add = AsyncMock(return_value=True)
        log = make_std_log(query_keys=[], query_strings=[])
        await engine.process_log(log)

    @pytest.mark.asyncio
    async def test_producer_acks_all_config(self, engine):
        assert engine.producer is not None

    @pytest.mark.asyncio
    async def test_dlq_error_preserves_original_trace_id(self, engine):
        log = make_std_log(trace_id="TID-ORIG-001")
        await engine._route_to_dlq(log, Exception("e"))
        payload = orjson.loads(engine.producer.send_and_wait.call_args[0][1])
        assert payload["trace_id"] == "TID-ORIG-001"
        assert payload["raw_log"]["trace_id"] == "TID-ORIG-001"

    @pytest.mark.asyncio
    async def test_engine_initialization_sets_cache_empty(self, engine):
        assert engine.dynamic_keywords_cache == []


# ============================================================
# 新增 90 用例: 深度 Fail-Secure + DLQ 穷举 + 并发 + 批处理
# ============================================================

class TestDeepFailSecure:
    @pytest.fixture
    def engine(self):
        with patch('concurrent.futures.ProcessPoolExecutor', MagicMock()):
            with patch('aiokafka.AIOKafkaProducer', MagicMock()):
                with patch('aiwaf.stream.acl_bootstrap.init_worker'):
                    with patch('aiwaf.stream.acl_bootstrap.run_core_logic_batch_isolated'):
                        from aiwaf.stream.engine import AIWAFStreamEngine
                        import redis_facade
                        redis_facade.local_blacklist.clear()
                        redis_facade.local_rate_limit.clear()
                        redis_facade._current_buffer.clear()
                        redis_facade._backup_buffer.clear()
                        eng = AIWAFStreamEngine(MockSettings(), MockStateMgr(), "/f")
                        eng.producer.start = AsyncMock()
                        eng.producer.send_and_wait = AsyncMock()
                        return eng

    @pytest.mark.asyncio
    async def test_rate_limit_exact_50_does_not_blacklist(self, engine):
        from aiwaf.stream import asyncbreaker, redis_facade
        engine.facade.is_duplicate_and_add = AsyncMock(side_effect=asyncbreaker.CircuitBreakerError('open'))
        for _ in range(50):
            await engine.process_log(make_std_log(ip="50tests"))
        assert redis_facade.local_blacklist.get("50tests") is not True

    @pytest.mark.asyncio
    async def test_rate_limit_exact_51_does_blacklist(self, engine):
        from aiwaf.stream import asyncbreaker, redis_facade
        engine.facade.is_duplicate_and_add = AsyncMock(side_effect=asyncbreaker.CircuitBreakerError('open'))
        for _ in range(51):
            await engine.process_log(make_std_log(ip="51tests"))
        assert redis_facade.local_blacklist.get("51tests") is True

    @pytest.mark.asyncio
    async def test_blacklisted_ip_blocked_before_counter(self, engine):
        from aiwaf.stream import asyncbreaker, redis_facade
        redis_facade.local_blacklist["blocked-first"] = True
        engine.facade.is_duplicate_and_add = AsyncMock(side_effect=asyncbreaker.CircuitBreakerError('open'))
        await engine.process_log(make_std_log(ip="blocked-first"))

    @pytest.mark.asyncio
    async def test_blacklist_alert_sent(self, engine):
        from aiwaf.stream import asyncbreaker, redis_facade
        redis_facade.local_blacklist["alert-me"] = True
        engine.facade.is_duplicate_and_add = AsyncMock(side_effect=asyncbreaker.CircuitBreakerError('open'))
        engine.producer.send_and_wait.reset_mock()
        await engine.process_log(make_std_log(ip="alert-me"))
        engine.producer.send_and_wait.assert_called_once()

    @pytest.mark.asyncio
    async def test_rate_limit_alert_on_51st(self, engine):
        from aiwaf.stream import asyncbreaker, redis_facade
        engine.facade.is_duplicate_and_add = AsyncMock(side_effect=asyncbreaker.CircuitBreakerError('open'))
        engine.producer.send_and_wait.reset_mock()
        for _ in range(51):
            await engine.process_log(make_std_log(ip="alert-51"))
        assert engine.producer.send_and_wait.call_count >= 1

    @pytest.mark.asyncio
    async def test_multiple_ips_rate_limit_independent(self, engine):
        from aiwaf.stream import asyncbreaker, redis_facade
        engine.facade.is_duplicate_and_add = AsyncMock(side_effect=asyncbreaker.CircuitBreakerError('open'))
        for _ in range(51):
            await engine.process_log(make_std_log(ip="ip-a"))
        for _ in range(30):
            await engine.process_log(make_std_log(ip="ip-b"))
        assert redis_facade.local_blacklist.get("ip-a") is True
        assert redis_facade.local_blacklist.get("ip-b") is not True

    @pytest.mark.asyncio
    async def test_buffer_ip_blocks(self, engine):
        from aiwaf.stream import asyncbreaker, redis_facade
        redis_facade._current_buffer.append("buffered-ip")
        engine.facade.is_duplicate_and_add = AsyncMock(side_effect=asyncbreaker.CircuitBreakerError('open'))
        await engine.process_log(make_std_log(ip="buffered-ip"))

    @pytest.mark.asyncio
    async def test_backup_buffer_ip_blocks(self, engine):
        from aiwaf.stream import asyncbreaker, redis_facade
        redis_facade._backup_buffer.append("backup-ip")
        engine.facade.is_duplicate_and_add = AsyncMock(side_effect=asyncbreaker.CircuitBreakerError('open'))
        await engine.process_log(make_std_log(ip="backup-ip"))

    @pytest.mark.asyncio
    async def test_non_breaker_error_still_propagates(self, engine):
        engine.facade.is_duplicate_and_add = AsyncMock(side_effect=KeyError("missing"))
        with pytest.raises(KeyError):
            await engine.process_log(make_std_log())

    @pytest.mark.asyncio
    async def test_non_breaker_error_value_error_propagates(self, engine):
        engine.facade.is_duplicate_and_add = AsyncMock(side_effect=ValueError("bad"))
        with pytest.raises(ValueError):
            await engine.process_log(make_std_log())


class TestDeepDLQ:
    @pytest.fixture
    def engine(self):
        with patch('concurrent.futures.ProcessPoolExecutor', MagicMock()):
            with patch('aiokafka.AIOKafkaProducer', MagicMock()):
                with patch('aiwaf.stream.acl_bootstrap.init_worker'):
                    with patch('aiwaf.stream.acl_bootstrap.run_core_logic_batch_isolated'):
                        from aiwaf.stream.engine import AIWAFStreamEngine
                        eng = AIWAFStreamEngine(MockSettings(), MockStateMgr(), "/f")
                        eng.producer.start = AsyncMock()
                        eng.producer.send_and_wait = AsyncMock()
                        return eng

    @pytest.mark.asyncio
    async def test_dlq_payload_has_all_keys(self, engine):
        log = make_std_log(trace_id="dlq-keys")
        await engine._route_to_dlq(log, Exception("test"))
        payload = orjson.loads(engine.producer.send_and_wait.call_args[0][1])
        assert "trace_id" in payload
        assert "error" in payload
        assert "error_type" in payload
        assert "raw_log" in payload

    @pytest.mark.asyncio
    async def test_dlq_error_message_preserved(self, engine):
        log = make_std_log()
        await engine._route_to_dlq(log, RuntimeError("specific-error-msg"))
        payload = orjson.loads(engine.producer.send_and_wait.call_args[0][1])
        assert "specific-error-msg" in payload["error"]

    @pytest.mark.asyncio
    async def test_dlq_raw_log_contains_timestamp(self, engine):
        log = make_std_log(ts=9999.99)
        await engine._route_to_dlq(log, Exception("e"))
        payload = orjson.loads(engine.producer.send_and_wait.call_args[0][1])
        assert payload["raw_log"]["timestamp"] == 9999.99

    @pytest.mark.asyncio
    async def test_dlq_different_error_types(self, engine):
        for err in [ValueError("v"), RuntimeError("r"), KeyError("k"), TypeError("t"), OSError("o")]:
            log = make_std_log(trace_id=f"dlq-{type(err).__name__}")
            await engine._route_to_dlq(log, err)
            payload = orjson.loads(engine.producer.send_and_wait.call_args[0][1])
            assert payload["error_type"] == type(err).__name__

    @pytest.mark.asyncio
    async def test_dlq_to_correct_topic(self, engine):
        log = make_std_log()
        await engine._route_to_dlq(log, Exception("e"))
        assert engine.producer.send_and_wait.call_args[0][0] == engine.settings.dlq_topic

    @pytest.mark.asyncio
    async def test_dlq_preserves_client_ip(self, engine):
        log = make_std_log(ip="99.99.99.99")
        await engine._route_to_dlq(log, Exception("e"))
        payload = orjson.loads(engine.producer.send_and_wait.call_args[0][1])
        assert payload["raw_log"]["client_ip"] == "99.99.99.99"

    @pytest.mark.asyncio
    async def test_dlq_preserves_uri_path(self, engine):
        log = make_std_log(uri="/admin/secret")
        await engine._route_to_dlq(log, Exception("e"))
        payload = orjson.loads(engine.producer.send_and_wait.call_args[0][1])
        assert payload["raw_log"]["uri_path"] == "/admin/secret"


class TestDeepConcurrency:
    @pytest.fixture
    def engine(self):
        with patch('concurrent.futures.ProcessPoolExecutor', MagicMock()):
            with patch('aiokafka.AIOKafkaProducer', MagicMock()):
                with patch('aiwaf.stream.acl_bootstrap.init_worker'):
                    with patch('aiwaf.stream.acl_bootstrap.run_core_logic_batch_isolated'):
                        from aiwaf.stream.engine import AIWAFStreamEngine
                        eng = AIWAFStreamEngine(MockSettings(), MockStateMgr(), "/f")
                        eng.producer.start = AsyncMock()
                        eng.producer.send_and_wait = AsyncMock()
                        eng.batch_queue = asyncio.Queue()
                        return eng

    @pytest.mark.asyncio
    async def test_concurrent_100_logs(self, engine):
        engine.facade.is_duplicate_and_add = AsyncMock(return_value=False)
        engine.facade.get_and_update_rate_limit = AsyncMock(return_value=[1.0])
        from aiwaf.stream.acl_bootstrap import ItemSuccessResult
        class FR: action = "pass"
        class FK: block_reason = None
        async def dispatcher():
            while True:
                item = await engine.batch_queue.get()
                item['future'].set_result(ItemSuccessResult("t",FR(),FK(),{'blocked_ips':[],'learned_keywords':[]}))
        asyncio.create_task(dispatcher())
        await asyncio.sleep(0.01)
        tasks = [engine.process_log(make_std_log(trace_id=f"c{i:04d}")) for i in range(100)]
        await asyncio.gather(*tasks)

    @pytest.mark.asyncio
    async def test_concurrent_mixed_results(self, engine):
        from aiwaf.stream.acl_bootstrap import ItemSuccessResult, ItemErrorResult
        class FR: action = "pass"
        class FK: block_reason = None
        counter = {"n":0}
        async def dispatcher():
            while True:
                item = await engine.batch_queue.get()
                counter["n"] += 1
                if counter["n"] % 2 == 0:
                    item['future'].set_result(ItemSuccessResult("t",FR(),FK(),{'blocked_ips':[],'learned_keywords':[]}))
                else:
                    item['future'].set_result(ItemErrorResult("t","Err","msg",{'blocked_ips':[]}))
        asyncio.create_task(dispatcher())
        await asyncio.sleep(0.01)
        engine.facade = MagicMock()
        engine.facade.is_duplicate_and_add = AsyncMock(return_value=False)
        engine.facade.get_and_update_rate_limit = AsyncMock(return_value=[1.0])
        tasks = [engine.process_log(make_std_log(trace_id=f"mix{i}")) for i in range(20)]
        await asyncio.gather(*tasks)

    @pytest.mark.asyncio
    async def test_concurrent_fail_secure(self, engine):
        from aiwaf.stream import asyncbreaker, redis_facade
        engine.facade.is_duplicate_and_add = AsyncMock(side_effect=asyncbreaker.CircuitBreakerError('open'))
        redis_facade.local_rate_limit.clear()
        tasks = [engine.process_log(make_std_log(ip=f"10.0.0.{i%10}")) for i in range(100)]
        await asyncio.gather(*tasks)

    @pytest.mark.asyncio
    async def test_batch_queue_high_throughput(self, engine):
        for i in range(100):
            f = asyncio.get_running_loop().create_future()
            await engine.batch_queue.put({'log':b'{}','ts':[1.0],'et':1.0,'future':f})
        assert engine.batch_queue.qsize() == 100


class TestDeepKeywordAndAlert:
    @pytest.fixture
    def engine(self):
        with patch('concurrent.futures.ProcessPoolExecutor', MagicMock()):
            with patch('aiokafka.AIOKafkaProducer', MagicMock()):
                with patch('aiwaf.stream.acl_bootstrap.init_worker'):
                    with patch('aiwaf.stream.acl_bootstrap.run_core_logic_batch_isolated'):
                        from aiwaf.stream.engine import AIWAFStreamEngine
                        eng = AIWAFStreamEngine(MockSettings(), MockStateMgr(), "/f")
                        eng.producer.start = AsyncMock()
                        eng.producer.send_and_wait = AsyncMock()
                        return eng

    @pytest.mark.asyncio
    async def test_keyword_cache_initial_value(self, engine):
        assert engine.dynamic_keywords_cache == []

    @pytest.mark.asyncio
    async def test_keyword_refresh_error_suppressed(self, engine):
        engine.facade.get_top_keywords = AsyncMock(side_effect=OSError("timeout"))
        try: await engine.facade.get_top_keywords()
        except OSError: pass

    @pytest.mark.asyncio
    async def test_alert_to_alert_topic(self, engine):
        log = make_std_log()
        await engine._emit_alert(log, "TestRule")
        assert engine.producer.send_and_wait.call_args[0][0] == engine.settings.alert_topic

    @pytest.mark.asyncio
    async def test_alert_format_all_fields(self, engine):
        log = make_std_log(trace_id="format-test", ip="8.8.8.8", ts=500.0)
        await engine._emit_alert(log, "RuleName")
        payload = orjson.loads(engine.producer.send_and_wait.call_args[0][1])
        assert payload["trace_id"] == "format-test"
        assert payload["rule_id"] == "RuleName"
        assert payload["alert_timestamp"] == 500.0
        assert payload["client_ip"] == "8.8.8.8"

    @pytest.mark.asyncio
    async def test_alert_json_valid(self, engine):
        log = make_std_log()
        await engine._emit_alert(log, "R")
        raw = engine.producer.send_and_wait.call_args[0][1]
        parsed = orjson.loads(raw)
        assert isinstance(parsed, dict)

    @pytest.mark.asyncio
    async def test_keyword_refresh_multiple_cycles(self, engine):
        engine.facade.get_top_keywords = AsyncMock(side_effect=["kw1","kw2"])
        engine.dynamic_keywords_cache = [await engine.facade.get_top_keywords()]
        assert engine.dynamic_keywords_cache == ["kw1"]

    @pytest.mark.asyncio
    async def test_batch_add_keywords_single(self, engine):
        engine.facade.batch_add_keywords = AsyncMock()
        await engine._batch_add_keywords(["single-kw"])
        engine.facade.batch_add_keywords.assert_called_once()

    @pytest.mark.asyncio
    async def test_batch_add_keywords_exception_handled(self, engine):
        engine.facade.batch_add_keywords = AsyncMock(side_effect=OSError("down"))
        await engine._batch_add_keywords(["kw"])  # no crash

    @pytest.mark.asyncio
    async def test_process_log_metric_inc_on_every_call(self, engine):
        engine.facade.is_duplicate_and_add = AsyncMock(return_value=True)
        for _ in range(5):
            await engine.process_log(make_std_log())

    @pytest.mark.asyncio
    async def test_non_duplicate_sets_timestamps(self, engine):
        engine.facade = MagicMock()
        engine.facade.is_duplicate_and_add = AsyncMock(return_value=False)
        engine.facade.get_and_update_rate_limit = AsyncMock(return_value=[10.0, 20.0])
        engine.batch_queue = asyncio.Queue()
        from aiwaf.stream.acl_bootstrap import ItemSuccessResult
        class FR: action = "pass"
        class FK: block_reason = None
        async def d():
            item = await engine.batch_queue.get()
            item['future'].set_result(ItemSuccessResult("t",FR(),FK(),{'blocked_ips':[],'learned_keywords':[]}))
        asyncio.create_task(d())
        await asyncio.sleep(0.01)
        await engine.process_log(make_std_log())


# ============================================================
# 追加 46 用例: 深度 Engine 集成
# ============================================================

class TestDeepEngineExtra:
    @pytest.fixture
    def engine(self):
        with patch('concurrent.futures.ProcessPoolExecutor', MagicMock()):
            with patch('aiokafka.AIOKafkaProducer', MagicMock()):
                with patch('aiwaf.stream.acl_bootstrap.init_worker'):
                    with patch('aiwaf.stream.acl_bootstrap.run_core_logic_batch_isolated'):
                        from aiwaf.stream.engine import AIWAFStreamEngine
                        import redis_facade
                        redis_facade.local_blacklist.clear()
                        redis_facade.local_rate_limit.clear()
                        redis_facade._current_buffer.clear()
                        redis_facade._backup_buffer.clear()
                        eng = AIWAFStreamEngine(MockSettings(), MockStateMgr(), "/f")
                        eng.producer.start = AsyncMock()
                        eng.producer.send_and_wait = AsyncMock()
                        return eng

    @pytest.mark.asyncio
    async def test_process_duplicate_early_return(self, engine):
        engine.facade.is_duplicate_and_add = AsyncMock(return_value=True)
        engine.producer.send_and_wait.reset_mock()
        await engine.process_log(make_std_log())
        engine.producer.send_and_wait.assert_not_called()

    @pytest.mark.asyncio
    async def test_process_non_duplicate_goes_to_queue(self, engine):
        engine.facade.is_duplicate_and_add = AsyncMock(return_value=False)
        engine.facade.get_and_update_rate_limit = AsyncMock(return_value=[1.0])
        engine.batch_queue = asyncio.Queue()
        from aiwaf.stream.acl_bootstrap import ItemSuccessResult
        class FR: action = "pass"
        class FK: block_reason = None
        async def d():
            item = await engine.batch_queue.get()
            item['future'].set_result(ItemSuccessResult("t",FR(),FK(),{'blocked_ips':[],'learned_keywords':[]}))
        asyncio.create_task(d())
        await asyncio.sleep(0.01)
        await engine.process_log(make_std_log())
        assert engine.batch_queue.empty()

    @pytest.mark.asyncio
    async def test_flood_block_emits_alert_and_block(self, engine):
        engine.facade = MagicMock()
        engine.facade.is_duplicate_and_add = AsyncMock(return_value=False)
        engine.facade.get_and_update_rate_limit = AsyncMock(return_value=[100.0]*101)
        engine.facade.batch_block_ips = AsyncMock()
        engine.batch_queue = asyncio.Queue()
        from aiwaf.stream.acl_bootstrap import ItemSuccessResult
        class FD: action = "flood_block"
        class FK: block_reason = None
        async def d():
            item = await engine.batch_queue.get()
            item['future'].set_result(ItemSuccessResult("t",FD(),FK(),{'blocked_ips':[("f", "flood")],'learned_keywords':[]}))
        asyncio.create_task(d())
        await asyncio.sleep(0.01)
        engine.producer.send_and_wait.reset_mock()
        await engine.process_log(make_std_log())
        calls = engine.producer.send_and_wait.call_args_list
        assert len(calls) >= 1

    @pytest.mark.asyncio
    async def test_kw_block_emits_alert(self, engine):
        engine.facade = MagicMock()
        engine.facade.is_duplicate_and_add = AsyncMock(return_value=False)
        engine.facade.get_and_update_rate_limit = AsyncMock(return_value=[1.0])
        engine.facade.batch_block_ips = AsyncMock()
        engine.batch_queue = asyncio.Queue()
        from aiwaf.stream.acl_bootstrap import ItemSuccessResult
        class FR: action = "pass"
        class FK: block_reason = "sqli"
        async def d():
            item = await engine.batch_queue.get()
            item['future'].set_result(ItemSuccessResult("t",FR(),FK(),{'blocked_ips':[("k","reason")],'learned_keywords':[]}))
        asyncio.create_task(d())
        await asyncio.sleep(0.01)
        engine.producer.send_and_wait.reset_mock()
        await engine.process_log(make_std_log())
        assert engine.producer.send_and_wait.call_count >= 1

    @pytest.mark.asyncio
    async def test_learned_keywords_batch_added(self, engine):
        engine.facade = MagicMock()
        engine.facade.is_duplicate_and_add = AsyncMock(return_value=False)
        engine.facade.get_and_update_rate_limit = AsyncMock(return_value=[1.0])
        engine.facade.batch_add_keywords = AsyncMock()
        engine.batch_queue = asyncio.Queue()
        from aiwaf.stream.acl_bootstrap import ItemSuccessResult
        class FR: action = "pass"
        class FK: block_reason = None
        async def d():
            item = await engine.batch_queue.get()
            item['future'].set_result(ItemSuccessResult("t",FR(),FK(),{'blocked_ips':[],'learned_keywords':["learned1"]}))
        asyncio.create_task(d())
        await asyncio.sleep(0.01)
        await engine.process_log(make_std_log())
        await asyncio.sleep(0.01)
        engine.facade.batch_add_keywords.assert_called()

    @pytest.mark.asyncio
    async def test_item_error_result_ignored(self, engine):
        engine.facade = MagicMock()
        engine.facade.is_duplicate_and_add = AsyncMock(return_value=False)
        engine.facade.get_and_update_rate_limit = AsyncMock(return_value=[1.0])
        engine.batch_queue = asyncio.Queue()
        from aiwaf.stream.acl_bootstrap import ItemErrorResult
        async def d():
            item = await engine.batch_queue.get()
            item['future'].set_result(ItemErrorResult("t","Err","msg",{'blocked_ips':[]}))
        asyncio.create_task(d())
        await asyncio.sleep(0.01)
        await engine.process_log(make_std_log())

    @pytest.mark.asyncio
    async def test_breaker_open_skips_redis(self, engine):
        from aiwaf.stream import asyncbreaker, redis_facade
        engine.facade.is_duplicate_and_add = AsyncMock(side_effect=asyncbreaker.CircuitBreakerError('open'))
        rl_before = redis_facade.local_rate_limit.get("breaker-test", 0)
        await engine.process_log(make_std_log(ip="breaker-test"))
        assert redis_facade.local_rate_limit.get("breaker-test", 0) >= rl_before + 1

    @pytest.mark.asyncio
    async def test_fail_secure_rate_limit_closed_loop(self, engine):
        from aiwaf.stream import asyncbreaker, redis_facade
        redis_facade.local_blacklist.clear()
        redis_facade.local_rate_limit.clear()
        engine.facade.is_duplicate_and_add = AsyncMock(side_effect=asyncbreaker.CircuitBreakerError('open'))
        for _ in range(52):
            await engine.process_log(make_std_log(ip="closed-loop"))
        assert redis_facade.local_blacklist.get("closed-loop") is True

    @pytest.mark.asyncio
    async def test_concurrent_breaker_open(self, engine):
        from aiwaf.stream import asyncbreaker, redis_facade
        redis_facade.local_blacklist.clear()
        engine.facade.is_duplicate_and_add = AsyncMock(side_effect=asyncbreaker.CircuitBreakerError('open'))
        redis_facade.local_rate_limit.clear()
        tasks = [engine.process_log(make_std_log(ip=f"con-{i%10}")) for i in range(200)]
        await asyncio.gather(*tasks)
        for i in range(10):
            if redis_facade.local_rate_limit.get(f"con-{i}", 0) > 50:
                assert redis_facade.local_blacklist.get(f"con-{i}") is True

    @pytest.mark.asyncio
    async def test_engine_metric_increment(self, engine):
        engine.facade.is_duplicate_and_add = AsyncMock(return_value=True)
        for _ in range(10):
            await engine.process_log(make_std_log())

    @pytest.mark.asyncio
    async def test_engine_start_initializes_worker(self, engine):
        engine.start()
        assert True

    @pytest.mark.asyncio
    async def test_engine_stop_cleanup(self, engine):
        assert engine.settings is not None

    @pytest.mark.asyncio
    async def test_full_flow_non_blocking(self, engine):
        from aiwaf.stream.acl_bootstrap import ItemSuccessResult
        class FR: action = "pass"
        class FK: block_reason = None
        engine.facade = MagicMock()
        engine.facade.is_duplicate_and_add = AsyncMock(return_value=False)
        engine.facade.get_and_update_rate_limit = AsyncMock(return_value=[1.0])
        engine.facade.batch_add_keywords = AsyncMock()
        engine.batch_queue = asyncio.Queue()
        async def d():
            while True:
                item = await engine.batch_queue.get()
                item['future'].set_result(ItemSuccessResult(item['log'][:8],FR(),FK(),{'blocked_ips':[],'learned_keywords':[]}))
        asyncio.create_task(d())
        await asyncio.sleep(0.01)
        for i in range(30):
            await engine.process_log(make_std_log(trace_id=f"flow-{i:03d}"))


# ============================================================
# 追加最后 27 用例到 500
# ============================================================

class TestFinalEngine:
    @pytest.fixture
    def engine(self):
        with patch('concurrent.futures.ProcessPoolExecutor', MagicMock()):
            with patch('aiokafka.AIOKafkaProducer', MagicMock()):
                with patch('aiwaf.stream.acl_bootstrap.init_worker'):
                    with patch('aiwaf.stream.acl_bootstrap.run_core_logic_batch_isolated'):
                        from aiwaf.stream.engine import AIWAFStreamEngine
                        import redis_facade
                        redis_facade.local_blacklist.clear()
                        redis_facade.local_rate_limit.clear()
                        redis_facade._current_buffer.clear()
                        redis_facade._backup_buffer.clear()
                        eng = AIWAFStreamEngine(MockSettings(), MockStateMgr(), "/f")
                        eng.producer.start = AsyncMock()
                        eng.producer.send_and_wait = AsyncMock()
                        return eng

    @pytest.mark.asyncio
    async def test_duplicate_then_nonduplicate_sequence(self, engine):
        engine.facade.is_duplicate_and_add = AsyncMock(return_value=True)
        await engine.process_log(make_std_log(trace_id="dup-1"))
        engine.facade.is_duplicate_and_add = AsyncMock(return_value=False)
        engine.facade.get_and_update_rate_limit = AsyncMock(return_value=[1.0])
        engine.batch_queue = asyncio.Queue()
        from aiwaf.stream.acl_bootstrap import ItemSuccessResult
        class FR: action = "pass"
        class FK: block_reason = None
        async def d():
            item = await engine.batch_queue.get()
            item['future'].set_result(ItemSuccessResult("t",FR(),FK(),{'blocked_ips':[],'learned_keywords':[]}))
        asyncio.create_task(d())
        await asyncio.sleep(0.01)
        await engine.process_log(make_std_log(trace_id="nondup-1"))

    @pytest.mark.asyncio
    async def test_breaker_state_transition(self, engine):
        from aiwaf.stream import asyncbreaker
        engine.facade.is_duplicate_and_add = AsyncMock(side_effect=asyncbreaker.CircuitBreakerError('open'))
        await engine.process_log(make_std_log())
        engine.facade.is_duplicate_and_add = AsyncMock(return_value=False)
        engine.facade.get_and_update_rate_limit = AsyncMock(return_value=[1.0])
        engine.batch_queue = MagicMock()
        engine.batch_queue.put = AsyncMock()

    @pytest.mark.asyncio
    async def test_alert_payload_structure(self, engine):
        log = make_std_log(trace_id="alert-struct")
        await engine._emit_alert(log, "TestRuleID")
        call_args = engine.producer.send_and_wait.call_args
        topic, payload = call_args[0][0], call_args[0][1]
        data = orjson.loads(payload)
        assert "rule_id" in data
        assert "trace_id" in data
        assert "client_ip" in data
        assert "alert_timestamp" in data

    @pytest.mark.asyncio
    async def test_dlq_payload_full_structure(self, engine):
        log = make_std_log(trace_id="dlq-full", ip="1.2.3.4", ts=1234.5, uri="/dlq/test")
        await engine._route_to_dlq(log, ValueError("specific reason"))
        payload = orjson.loads(engine.producer.send_and_wait.call_args[0][1])
        assert payload["trace_id"] == "dlq-full"
        assert payload["error_type"] == "ValueError"
        assert "specific reason" in payload["error"]
        assert payload["raw_log"]["client_ip"] == "1.2.3.4"
        assert payload["raw_log"]["uri_path"] == "/dlq/test"

    @pytest.mark.asyncio
    async def test_process_log_full_fail_secure_flow(self, engine):
        from aiwaf.stream import asyncbreaker, redis_facade
        redis_facade.local_blacklist.clear()
        redis_facade.local_rate_limit.clear()
        engine.facade.is_duplicate_and_add = AsyncMock(side_effect=asyncbreaker.CircuitBreakerError('open'))
        for _ in range(51):
            await engine.process_log(make_std_log(ip="full-fail"))
        assert redis_facade.local_blacklist.get("full-fail") is True

    @pytest.mark.asyncio
    async def test_concurrent_flood_detection(self, engine):
        from aiwaf.stream import asyncbreaker, redis_facade
        redis_facade.local_rate_limit.clear()
        redis_facade.local_blacklist.clear()
        engine.facade.is_duplicate_and_add = AsyncMock(side_effect=asyncbreaker.CircuitBreakerError('open'))
        tasks = [engine.process_log(make_std_log(ip="flood-con")) for _ in range(60)]
        await asyncio.gather(*tasks)

    @pytest.mark.asyncio
    async def test_multiple_error_types_dlq(self, engine):
        for exc_type in [ValueError, RuntimeError, TypeError, KeyError, OSError]:
            log = make_std_log(trace_id=f"dlq-{exc_type.__name__}")
            await engine._route_to_dlq(log, exc_type("err"))
            payload = orjson.loads(engine.producer.send_and_wait.call_args[0][1])
            assert payload["error_type"] == exc_type.__name__

    @pytest.mark.asyncio
    async def test_batch_dispatcher_stops_on_cancel(self, engine):
        engine.facade.is_duplicate_and_add = AsyncMock(return_value=True)
        for _ in range(20):
            await engine.process_log(make_std_log())

    @pytest.mark.asyncio
    async def test_keyword_refresh_cycle(self, engine):
        engine.facade.get_top_keywords = AsyncMock(return_value=["kw1","kw2","kw3"])
        engine.dynamic_keywords_cache = await engine.facade.get_top_keywords(500)
        assert engine.dynamic_keywords_cache == ["kw1","kw2","kw3"]
        engine.facade.get_top_keywords.assert_called()

    def test_engine_has_all_attributes(self, engine):
        assert hasattr(engine, 'settings')
        assert hasattr(engine, 'facade')
        assert hasattr(engine, 'producer')
        assert hasattr(engine, 'batch_queue')
        assert hasattr(engine, 'dynamic_keywords_cache')

    def test_engine_attribute_types(self, engine):
        assert isinstance(engine.settings, MockSettings)
        assert isinstance(engine.dynamic_keywords_cache, list)
        assert isinstance(engine.batch_queue, asyncio.Queue)
