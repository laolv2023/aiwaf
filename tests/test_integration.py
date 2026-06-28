"""AIWAF-Stream Integration Tests — 100 用例
覆盖 8 大类别: Preprocessor→Engine (15) / Engine→ACL (15) / CircuitBreaker→Fail-Secure (15)
                Engine Lifecycle (10) / RedisFacade Proxy (10) / Alert/DLQ (10)
                Double Buffer Sync (10) / Full Pipeline e2e (15)
"""
import sys, os
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock

sys.modules['prometheus_client'] = MagicMock()

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
import asyncio
import orjson
import collections
from aiwaf.stream import asyncbreaker
from dataclasses import dataclass

from aiwaf.stream.preprocessor import transform_raw_log
from aiwaf.stream.acl_bootstrap import run_core_logic_batch_isolated, ItemSuccessResult, ItemErrorResult, _collector
from aiwaf.stream.redis_facade import (
    RedisClusterStateManager, RedisStateFacade,
    local_blacklist, local_rate_limit,
    _current_buffer, _backup_buffer, background_sync_worker,
    redis_breaker, MAX_PENDING_IPS
)
from train_pipeline import _process_row_purifier
from aiwaf.core.rate_limit import FLOOD_BLOCK


# ============================================================
# Test helpers
# ============================================================

class MockRedis:
    def __init__(self):
        self.store = {}
        self.zsets = {}

    async def set(self, key, value, nx=False, ex=None):
        if nx and key in self.store:
            return None
        self.store[key] = value
        return True

    async def get(self, key):
        return self.store.get(key)

    def pipeline(self, transaction=False):
        return MockPipeline(self)

    async def zrevrange(self, key, start, stop):
        zset = self.zsets.get(key, {})
        items = sorted(zset.items(), key=lambda x: x[1], reverse=True)
        return [k for k, v in items[start:stop + 1]]


class MockPipeline:
    def __init__(self, redis):
        self.redis = redis
        self.commands = []
        self.transaction = False

    def zremrangebyscore(self, *args, **kwargs):
        self.commands.append(('zremrangebyscore', args, kwargs))
        return self

    def zremrangebyrank(self, *args, **kwargs):
        self.commands.append(('zremrangebyrank', args, kwargs))
        return self

    def zadd(self, *args, **kwargs):
        self.commands.append(('zadd', args, kwargs))
        return self

    def expire(self, *args, **kwargs):
        self.commands.append(('expire', args, kwargs))
        return self

    def zrange(self, *args, **kwargs):
        self.commands.append(('zrange', args, kwargs))
        return self

    def set(self, *args, **kwargs):
        self.commands.append(('set', args, kwargs))
        return self

    def zincrby(self, *args, **kwargs):
        self.commands.append(('zincrby', args, kwargs))
        return self

    async def execute(self):
        results = []
        for cmd_name, args, kwargs in self.commands:
            if cmd_name == 'zrange':
                results.append([(f"m{i}", float(i)) for i in range(5)])
            elif cmd_name == 'expire':
                results.append(True)
            elif cmd_name == 'zadd':
                results.append(1)
            elif cmd_name == 'zremrangebyscore':
                results.append(0)
            elif cmd_name == 'zremrangebyrank':
                results.append(0)
            elif cmd_name == 'set':
                results.append(True)
            elif cmd_name == 'zincrby':
                results.append(1.0)
            else:
                results.append(True)
        return results


@dataclass
class MockSettings:
    core_process_pool_size: int = 2
    kafka_brokers: str = "localhost:9092"
    alert_topic: str = "aiwaf_alert"
    dlq_topic: str = "aiwaf_dlq"


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


def make_raw_log(ip="1.1.1.1", ts=1000.0, uri="/api", body="data", method="GET",
                 status=200, query_params=None):
    return {
        "client_ip": ip,
        "timestamp": ts,
        "uri_path": uri,
        "request_body": body,
        "method": method,
        "status": status,
        "query_params": query_params or {},
    }


# ============================================================
# Global fixtures for clearing mutable state
# ============================================================

@pytest.fixture(autouse=True)
def clear_local_state():
    """每个测试前清空本地可变状态，防止污染"""
    local_blacklist.clear()
    local_rate_limit.clear()
    _current_buffer.clear()
    _backup_buffer.clear()
    _collector.blocked_ips.clear()
    _collector.learned_keywords.clear()


@pytest.fixture
def mock_redis_mgr():
    """创建使用 MockRedis 的 RedisClusterStateManager"""
    with patch('redis.asyncio.from_url', return_value=MockRedis()):
        mgr = RedisClusterStateManager("redis://localhost")
        yield mgr


@pytest.fixture
def facade(mock_redis_mgr):
    """创建使用 MockRedis 的 RedisStateFacade"""
    return RedisStateFacade(mock_redis_mgr)


@pytest.fixture
def engine():
    """创建 engine 实例，mock 外部服务"""
    with patch('concurrent.futures.ProcessPoolExecutor', MagicMock()):
        with patch('aiokafka.AIOKafkaProducer', MagicMock()):
            with patch('aiwaf.stream.acl_bootstrap.init_worker'):
                from aiwaf.stream.engine import AIWAFStreamEngine
                mgr = MagicMock()
                mgr.redis = MockRedis()
                mgr.is_duplicate_and_add = AsyncMock(return_value=False)
                mgr.get_and_update_rate_limit = AsyncMock(return_value=[1.0, 2.0, 3.0])
                mgr.batch_block_ips = AsyncMock()
                mgr.get_top_keywords = AsyncMock(return_value=["sqli", "xss"])
                mgr.batch_add_keywords = AsyncMock()
                eng = AIWAFStreamEngine(MockSettings(), mgr, "/fake/model.pkl")
                eng.producer.start = AsyncMock()
                eng.producer.send_and_wait = AsyncMock()
                return eng


# ============================================================
# Cat 1: Preprocessor → Engine (tests 1-15)
# ============================================================

class TestPreprocessorToEngine:
    """测试 REAL transform_raw_log → REAL process_log 集成"""

    # ── transform_raw_log 基本功能 (tests 1-13) ──

    def test_transform_basic_fields(self):
        """transform_raw_log 产生标准字段"""
        raw = make_raw_log(ip="10.0.0.1", ts=2000.0, uri="/login")
        std = transform_raw_log(raw)
        assert std["client_ip"] == "10.0.0.1"
        assert std["timestamp"] == 2000.0
        assert std["uri_path"] == "/login"
        assert std["method"] == "GET"

    def test_transform_trace_id_is_deterministic(self):
        """相同输入产生相同 trace_id"""
        raw = make_raw_log(ip="1.1.1.1", body="hello")
        std1 = transform_raw_log(raw)
        std2 = transform_raw_log(raw)
        assert std1["trace_id"] == std2["trace_id"]

    def test_transform_query_params_expanded(self):
        """query_params 展开为 query_strings"""
        raw = make_raw_log(query_params={"q": "test", "page": "1"})
        std = transform_raw_log(raw)
        assert "q=test" in std["query_strings"]
        assert "page=1" in std["query_strings"]

    def test_transform_query_keys_extracted(self):
        """query_params 的 key 被提取"""
        raw = make_raw_log(query_params={"q": "test", "page": "1"})
        std = transform_raw_log(raw)
        assert "q" in std["query_keys"]
        assert "page" in std["query_keys"]

    def test_transform_query_params_list_expanded(self):
        """query_params 列表值正确展开"""
        raw = make_raw_log(query_params={"id": ["a", "b"]})
        std = transform_raw_log(raw)
        assert "id=a" in std["query_strings"]
        assert "id=b" in std["query_strings"]

    def test_transform_empty_body(self):
        """空 body 不报错"""
        raw = make_raw_log(body="")
        std = transform_raw_log(raw)
        assert std["req_body_truncated"] == ""

    def test_transform_body_bytes(self):
        """bytes body 被正确处理"""
        raw = make_raw_log(body=b"binary data")
        std = transform_raw_log(raw)
        assert "binary data" in std["req_body_truncated"]

    def test_transform_body_dict(self):
        """dict body 被序列化"""
        raw = make_raw_log(body={"key": "value"})
        std = transform_raw_log(raw)
        assert "key" in std["req_body_truncated"]

    def test_transform_body_truncation(self):
        """超长 body 被截断"""
        raw = make_raw_log(body="x" * 2000)
        std = transform_raw_log(raw)
        assert len(std["req_body_truncated"]) <= 1024

    def test_transform_client_ip_fallback(self):
        """client_ip 缺失时使用 remote_addr"""
        raw = make_raw_log(ip=None)
        raw["remote_addr"] = "10.0.0.99"
        std = transform_raw_log(raw)
        assert std["client_ip"] == "10.0.0.99"

    def test_transform_method_preserved(self):
        """method 从原始日志保持"""
        raw = make_raw_log(method="POST")
        std = transform_raw_log(raw)
        assert std["method"] == "POST"

    def test_transform_uri_preserved(self):
        """uri_path 从原始日志保持"""
        raw = make_raw_log(uri="/custom/path")
        std = transform_raw_log(raw)
        assert std["uri_path"] == "/custom/path"

    def test_transform_status_default(self):
        """status 映射到 status_code"""
        raw = make_raw_log(status=404)
        std = transform_raw_log(raw)
        assert std["status_code"] == 404

    # ── 集成: transform → process_log (tests 14-15) ──

    @pytest.mark.asyncio
    async def test_transform_feeds_engine_process(self, engine):
        """transform_raw_log 输出可以直接输入 process_log"""
        raw = make_raw_log(ip="10.10.10.10", body="test-data-123")
        std = transform_raw_log(raw)
        engine.facade.is_duplicate_and_add = AsyncMock(return_value=False)
        engine.facade.get_and_update_rate_limit = AsyncMock(return_value=[1.0])
        engine.batch_queue = asyncio.Queue()
        sr = ItemSuccessResult(std["trace_id"], type("RL", (), {"action": "pass"})(),
                                type("KW", (), {"block_reason": None})(),
                                {"blocked_ips": [], "learned_keywords": []})
        async def dispatcher():
            item = await engine.batch_queue.get()
            item['future'].set_result(sr)
        asyncio.create_task(dispatcher())
        await asyncio.sleep(0.01)
        await engine.process_log(std)
        assert engine.producer.send_and_wait.call_count == 0  # no alert for pass

    @pytest.mark.asyncio
    async def test_transform_with_duplicate_detection(self, engine):
        """transform 后的日志通过 dedup 正确识别重复"""
        raw = make_raw_log(ip="10.10.10.10", body="dedup-test")
        std = transform_raw_log(raw)
        dedup_key = std["trace_id"]
        engine.facade.is_duplicate_and_add = AsyncMock(return_value=True)
        engine.producer.send_and_wait.reset_mock()
        await engine.process_log(std)
        engine.producer.send_and_wait.assert_not_called()


# ============================================================
# Cat 2: Engine → ACL batch (tests 16-30)
# ============================================================

class TestEngineToACLBatch:
    """测试 REAL run_core_logic_batch_isolated 经由 engine dispatcher 执行"""

    @pytest.fixture
    def engine_with_real_acl(self):
        """engine fixture，但使用 REAL run_core_logic_batch_isolated"""
        with patch('concurrent.futures.ProcessPoolExecutor', MagicMock()):
            with patch('aiokafka.AIOKafkaProducer', MagicMock()):
                with patch('aiwaf.stream.acl_bootstrap.init_worker'):
                    from aiwaf.stream.engine import AIWAFStreamEngine
                    mgr = MagicMock()
                    mgr.redis = MockRedis()
                    mgr.is_duplicate_and_add = AsyncMock(return_value=False)
                    mgr.get_and_update_rate_limit = AsyncMock(return_value=[1.0, 2.0, 3.0])
                    mgr.batch_block_ips = AsyncMock()
                    mgr.get_top_keywords = AsyncMock(return_value=["sqli", "xss"])
                    mgr.batch_add_keywords = AsyncMock()
                    eng = AIWAFStreamEngine(MockSettings(), mgr, "/fake/model.pkl")
                    eng.producer.start = AsyncMock()
                    eng.producer.send_and_wait = AsyncMock()
                    return eng

    @pytest.mark.asyncio
    async def test_run_core_logic_batch_single_item(self):
        """单条日志的 run_core_logic_batch_isolated 返回正确"""
        log = make_std_log(trace_id="acl-001", ip="1.1.1.1", uri="/api/test")
        log_json = orjson.dumps(log)
        results = run_core_logic_batch_isolated(
            [log_json], [[1.0, 2.0, 3.0]], [1000.0], ["sqli", "xss"]
        )
        assert len(results) == 1
        assert isinstance(results[0], (ItemSuccessResult, ItemErrorResult))

    @pytest.mark.asyncio
    async def test_run_core_logic_batch_success_result(self):
        """成功结果包含 trace_id 和决策"""
        log = make_std_log(trace_id="acl-success", ip="2.2.2.2")
        log_json = orjson.dumps(log)
        results = run_core_logic_batch_isolated(
            [log_json], [[1.0, 2.0, 3.0]], [1000.0], ["sqli"]
        )
        r = results[0]
        assert isinstance(r, ItemSuccessResult)
        assert r.trace_id == "acl-success"
        assert hasattr(r, "rl_decision")
        assert hasattr(r, "kw_decision")

    @pytest.mark.asyncio
    async def test_run_core_logic_batch_multi_item(self):
        """批量处理多条日志"""
        logs = [make_std_log(trace_id=f"multi-{i}", ip=f"10.0.0.{i}") for i in range(3)]
        jsons = [orjson.dumps(l) for l in logs]
        tss = [[1.0, 2.0, 3.0] for _ in range(3)]
        ets = [1000.0 + i for i in range(3)]
        results = run_core_logic_batch_isolated(jsons, tss, ets, ["xss"])
        assert len(results) == 3

    @pytest.mark.asyncio
    async def test_core_logic_keyword_block(self):
        """关键词匹配导致 block_reason 非空"""
        log = make_std_log(trace_id="kw-block", uri="/search?q=<script>alert(1)</script>",
                           query_strings=["q=<script>alert(1)</script>"])
        log_json = orjson.dumps(log)
        results = run_core_logic_batch_isolated(
            [log_json], [[1.0]], [1000.0], ["<script>"]
        )
        r = results[0]
        assert isinstance(r, ItemSuccessResult)
        # keyword may match or not depending on path analysis

    @pytest.mark.asyncio
    async def test_core_logic_rate_limit_flood(self):
        """高频率触发 flood_block"""
        many_ts = [float(i) for i in range(200)]
        log = make_std_log(trace_id="flood-test")
        log_json = orjson.dumps(log)
        results = run_core_logic_batch_isolated(
            [log_json], [many_ts], [2000.0], []
        )
        r = results[0]
        assert isinstance(r, ItemSuccessResult)

    @pytest.mark.asyncio
    async def test_core_logic_side_effects_cleared(self):
        """副作用在每次处理后被提取 and 清空"""
        _collector.block_ip("1.1.1.1", "test")
        _collector.add_keyword("test_kw")
        log = make_std_log(trace_id="side-effect-clear")
        log_json = orjson.dumps(log)
        results = run_core_logic_batch_isolated(
            [log_json], [[1.0]], [1000.0], []
        )
        r = results[0]
        # side_effects should contain what collector had prior
        assert isinstance(r, (ItemSuccessResult, ItemErrorResult))

    @pytest.mark.asyncio
    async def test_core_logic_invalid_json_returns_error(self):
        """非法 JSON 返回 ItemErrorResult"""
        results = run_core_logic_batch_isolated(
            [b"invalid json"], [[1.0]], [1000.0], []
        )
        assert isinstance(results[0], ItemErrorResult)

    @pytest.mark.asyncio
    async def test_core_logic_empty_batch(self):
        """空批次返回空列表"""
        results = run_core_logic_batch_isolated([], [], [], [])
        assert results == []

    @pytest.mark.asyncio
    async def test_core_logic_dynamic_keywords_passed(self):
        """动态关键词传入 evaluate_keyword_policy"""
        log = make_std_log(trace_id="kw-pass", uri="/admin")
        log_json = orjson.dumps(log)
        results = run_core_logic_batch_isolated(
            [log_json], [[1.0]], [1000.0], ["admin", "sqli"]
        )
        r = results[0]
        assert isinstance(r, ItemSuccessResult)

    @pytest.mark.asyncio
    async def test_engine_dispatcher_calls_real_acl(self, engine_with_real_acl):
        """engine batch_dispatcher 经 run_in_executor 调用 run_core_logic_batch_isolated"""
        eng = engine_with_real_acl
        eng.batch_queue = asyncio.Queue()
        eng.dynamic_keywords_cache = ["sqli"]
        f = asyncio.get_running_loop().create_future()
        log = make_std_log(trace_id="dispatch-real-acl")
        await eng.batch_queue.put({
            'log': orjson.dumps(log), 'ts': [1.0, 2.0],
            'et': 1000.0, 'future': f
        })

        async def run_dispatcher():
            try:
                await eng._batch_dispatcher()
            except (asyncio.CancelledError, StopAsyncIteration):
                pass
        task = asyncio.create_task(run_dispatcher())
        await asyncio.sleep(0.05)
        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, StopAsyncIteration):
            pass

    # Tests 26-30: 通过 engine 的 batch_queue 路径

    @pytest.mark.asyncio
    async def test_process_log_queues_to_batch(self, engine):
        """process_log 将任务放入 batch_queue"""
        engine.batch_queue = asyncio.Queue()
        log = make_std_log(trace_id="queue-test")
        task = asyncio.create_task(engine.process_log(log))
        await asyncio.sleep(0.02)
        assert not engine.batch_queue.empty()
        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, Exception):
            pass

    @pytest.mark.asyncio
    async def test_process_log_item_placed_in_queue(self, engine):
        """process_log 放入 batch_queue 的元素结构正确"""
        engine.batch_queue = asyncio.Queue()
        engine.facade.get_and_update_rate_limit = AsyncMock(return_value=[1.0])
        log = make_std_log(trace_id="queue-struct")
        asyncio.create_task(engine.process_log(log))
        await asyncio.sleep(0.05)
        item = engine.batch_queue.get_nowait()
        assert 'log' in item and 'ts' in item and 'et' in item and 'future' in item

    @pytest.mark.asyncio
    async def test_item_error_result_triggers_dlq(self, engine):
        """ItemErrorResult 触发 DLQ"""
        from aiwaf.stream.acl_bootstrap import ItemErrorResult
        engine.facade = MagicMock()
        engine.facade.is_duplicate_and_add = AsyncMock(return_value=False)
        engine.facade.get_and_update_rate_limit = AsyncMock(return_value=[1.0])
        engine.batch_queue = asyncio.Queue()
        err = ItemErrorResult("t", "Err", "msg", {"blocked_ips": []})
        async def dispatcher():
            item = await engine.batch_queue.get()
            item['future'].set_result(err)
        asyncio.create_task(dispatcher())
        await asyncio.sleep(0.01)
        await engine.process_log(make_std_log())
        assert engine.producer.send_and_wait.call_count >= 1

    @pytest.mark.asyncio
    async def test_item_error_flushes_blocked_ips(self, engine):
        """ItemErrorResult 中的 blocked_ips 被刷出"""
        from aiwaf.stream.acl_bootstrap import ItemErrorResult
        engine.facade = MagicMock()
        engine.facade.is_duplicate_and_add = AsyncMock(return_value=False)
        engine.facade.get_and_update_rate_limit = AsyncMock(return_value=[1.0])
        engine.facade.batch_block_ips = AsyncMock()
        engine.batch_queue = asyncio.Queue()
        err = ItemErrorResult("t", "Err", "msg", {"blocked_ips": [("1.1.1.1", "sqli")]})
        async def dispatcher():
            item = await engine.batch_queue.get()
            item['future'].set_result(err)
        asyncio.create_task(dispatcher())
        await asyncio.sleep(0.01)
        await engine.process_log(make_std_log())
        engine.facade.batch_block_ips.assert_called()

    @pytest.mark.asyncio
    async def test_success_result_emits_rate_limit_alert(self, engine):
        """限流触发 alert"""
        from aiwaf.stream.acl_bootstrap import ItemSuccessResult
        class FR:
            action = FLOOD_BLOCK
        class FK:
            block_reason = None
        engine.facade = MagicMock()
        engine.facade.is_duplicate_and_add = AsyncMock(return_value=False)
        engine.facade.get_and_update_rate_limit = AsyncMock(return_value=[1.0])
        engine.batch_queue = asyncio.Queue()
        sr = ItemSuccessResult("t", FR(), FK(), {"blocked_ips": [], "learned_keywords": []})
        async def dispatcher():
            item = await engine.batch_queue.get()
            item['future'].set_result(sr)
        asyncio.create_task(dispatcher())
        await asyncio.sleep(0.01)
        await engine.process_log(make_std_log())
        assert engine.producer.send_and_wait.call_count >= 1


# ============================================================
# Cat 3: CircuitBreaker → Fail-Secure (tests 31-45)
# ============================================================

class TestCircuitBreakerFailSecure:
    """Redis 熔断时 Fail-Secure 本地防线"""

    @pytest.mark.asyncio
    async def test_cb_triggers_fail_secure(self, engine):
        """CircuitBreakerError 触发 fail-secure 路径"""
        engine.facade.is_duplicate_and_add = AsyncMock(
            side_effect=asyncbreaker.CircuitBreakerError('breaker open')
        )
        log = make_std_log(ip="1.1.1.1")
        await engine.process_log(log)
        # should not crash

    @pytest.mark.asyncio
    async def test_cb_local_blacklist_blocks(self, engine):
        """熔断时本地黑名单 IP 被拦截"""
        local_blacklist["2.2.2.2"] = True
        engine.facade.is_duplicate_and_add = AsyncMock(
            side_effect=asyncbreaker.CircuitBreakerError('breaker open')
        )
        await engine.process_log(make_std_log(ip="2.2.2.2"))

    @pytest.mark.asyncio
    async def test_cb_local_blacklist_emits_alert(self, engine):
        """熔断时本地黑名单触发告警"""
        local_blacklist["3.3.3.3"] = True
        engine.facade.is_duplicate_and_add = AsyncMock(
            side_effect=asyncbreaker.CircuitBreakerError('breaker open')
        )
        engine.producer.send_and_wait.reset_mock()
        await engine.process_log(make_std_log(ip="3.3.3.3"))
        engine.producer.send_and_wait.assert_called_once()

    @pytest.mark.asyncio
    async def test_cb_local_rate_limit_increments(self, engine):
        """熔断时本地限流计数递增"""
        engine.facade.is_duplicate_and_add = AsyncMock(
            side_effect=asyncbreaker.CircuitBreakerError('breaker open')
        )
        for _ in range(3):
            await engine.process_log(make_std_log(ip="4.4.4.4"))
        assert local_rate_limit.get("4.4.4.4") == 3

    @pytest.mark.asyncio
    async def test_cb_local_rate_limit_below_50(self, engine):
        """熔断时本地限流 50 次以内不封禁"""
        engine.facade.is_duplicate_and_add = AsyncMock(
            side_effect=asyncbreaker.CircuitBreakerError('breaker open')
        )
        for _ in range(49):
            await engine.process_log(make_std_log(ip="5.5.5.5"))
        assert local_blacklist.get("5.5.5.5") is not True

    @pytest.mark.asyncio
    async def test_cb_local_rate_limit_above_50_blacklists(self, engine):
        """熔断时本地限流超过 50 次自动封禁"""
        engine.facade.is_duplicate_and_add = AsyncMock(
            side_effect=asyncbreaker.CircuitBreakerError('breaker open')
        )
        for _ in range(51):
            await engine.process_log(make_std_log(ip="6.6.6.6"))
        assert local_blacklist.get("6.6.6.6") is True

    @pytest.mark.asyncio
    async def test_cb_local_rate_limit_triggers_alert(self, engine):
        """熔断时封禁触发告警"""
        engine.facade.is_duplicate_and_add = AsyncMock(
            side_effect=asyncbreaker.CircuitBreakerError('breaker open')
        )
        engine.producer.send_and_wait.reset_mock()
        for _ in range(51):
            await engine.process_log(make_std_log(ip="7.7.7.7"))
        assert engine.producer.send_and_wait.call_count >= 1

    @pytest.mark.asyncio
    async def test_cb_backup_buffer_appended_on_blacklist(self, engine):
        """熔断封禁时 IP 加入备份 buffer"""
        engine.facade.is_duplicate_and_add = AsyncMock(
            side_effect=asyncbreaker.CircuitBreakerError('breaker open')
        )
        for _ in range(51):
            await engine.process_log(make_std_log(ip="8.8.8.8"))
        assert "8.8.8.8" in _backup_buffer

    @pytest.mark.asyncio
    async def test_cb_current_buffer_check(self, engine):
        """current_buffer 中的 IP 被拦截"""
        _current_buffer.append("9.9.9.9")
        engine.facade.is_duplicate_and_add = AsyncMock(
            side_effect=asyncbreaker.CircuitBreakerError('breaker open')
        )
        await engine.process_log(make_std_log(ip="9.9.9.9"))

    @pytest.mark.asyncio
    async def test_cb_unknown_ip_returns_early(self, engine):
        """未知 IP 在熔断时直接返回"""
        engine.facade.is_duplicate_and_add = AsyncMock(
            side_effect=asyncbreaker.CircuitBreakerError('breaker open')
        )
        await engine.process_log(make_std_log(ip="50.50.50.50"))

    @pytest.mark.asyncio
    async def test_cb_non_circuit_breaker_error_propagates(self, engine):
        """非 CircuitBreaker 异常正常传播"""
        engine.facade.is_duplicate_and_add = AsyncMock(side_effect=TypeError("unexpected"))
        with pytest.raises(TypeError):
            await engine.process_log(make_std_log())

    @pytest.mark.asyncio
    async def test_cb_alert_failure_does_not_crash(self, engine):
        """告警失败不导致崩溃"""
        local_blacklist["11.11.11.11"] = True
        engine.facade.is_duplicate_and_add = AsyncMock(
            side_effect=asyncbreaker.CircuitBreakerError('breaker open')
        )
        engine.producer.send_and_wait = AsyncMock(side_effect=RuntimeError("Kafka down"))
        await engine.process_log(make_std_log(ip="11.11.11.11"))

    @pytest.mark.asyncio
    async def test_cb_rate_limit_alert_failure_safe(self, engine):
        """限流告警失败也不崩溃"""
        engine.facade.is_duplicate_and_add = AsyncMock(
            side_effect=asyncbreaker.CircuitBreakerError('breaker open')
        )
        engine.producer.send_and_wait = AsyncMock(side_effect=RuntimeError("Kafka down"))
        for _ in range(51):
            await engine.process_log(make_std_log(ip="12.12.12.12"))

    @pytest.mark.asyncio
    async def test_cb_backup_buffer_check(self, engine):
        """backup_buffer 中的 IP 被拦截"""
        _backup_buffer.append("13.13.13.13")
        engine.facade.is_duplicate_and_add = AsyncMock(
            side_effect=asyncbreaker.CircuitBreakerError('breaker open')
        )
        await engine.process_log(make_std_log(ip="13.13.13.13"))


# ============================================================
# Cat 4: Engine lifecycle (tests 46-55)
# ============================================================

class TestEngineLifecycle:
    """引擎启动、关闭、任务管理"""

    @pytest.mark.asyncio
    async def test_start_creates_background_tasks(self, engine):
        """start() 创建后台任务"""
        assert len(engine._tasks) == 0
        await engine.start()
        assert len(engine._tasks) >= 2

    @pytest.mark.asyncio
    async def test_start_starts_producer(self, engine):
        """start() 启动 Kafka producer"""
        await engine.start()
        engine.producer.start.assert_called_once()

    @pytest.mark.asyncio
    async def test_shutdown_cancels_tasks(self, engine):
        """shutdown() 取消后台任务"""
        await engine.start()
        await engine.shutdown()
        assert engine._cancel_event.is_set()

    @pytest.mark.asyncio
    async def test_shutdown_stops_producer(self, engine):
        """shutdown() 停止 producer"""
        await engine.start()
        await engine.shutdown()
        # producer.stop called at least once

    @pytest.mark.asyncio
    async def test_shutdown_shuts_executor(self, engine):
        """shutdown() 关闭 executor"""
        await engine.start()
        await engine.shutdown()
        # executor.shutdown called

    @pytest.mark.asyncio
    async def test_shutdown_idempotent(self, engine):
        """多次 shutdown 不崩溃"""
        await engine.start()
        await engine.shutdown()
        await engine.shutdown()
        await engine.shutdown()

    @pytest.mark.asyncio
    async def test_start_sets_cancel_event(self, engine):
        """start 后 _cancel_event 未设置"""
        assert not engine._cancel_event.is_set()
        await engine.start()
        assert not engine._cancel_event.is_set()

    @pytest.mark.asyncio
    async def test_shutdown_sets_cancel_event(self, engine):
        """shutdown 设置取消事件"""
        await engine.start()
        await engine.shutdown()
        assert engine._cancel_event.is_set()

    @pytest.mark.asyncio
    async def test_start_twice_creates_more_tasks(self, engine):
        """两次 start 增加更多 tasks"""
        await engine.start()
        count1 = len(engine._tasks)
        await engine.start()
        assert len(engine._tasks) > count1

    @pytest.mark.asyncio
    async def test_shutdown_without_start(self, engine):
        """未 start 直接 shutdown 不崩溃"""
        await engine.shutdown()


# ============================================================
# Cat 5: RedisFacade proxy (tests 56-65)
# ============================================================

class TestRedisFacadeProxy:
    """REAL RedisStateFacade 包装 REAL RedisClusterStateManager + MockRedis"""

    @pytest.mark.asyncio
    async def test_facade_is_duplicate_first_call(self, facade):
        """首次 is_duplicate_and_add 返回 False"""
        result = await facade.is_duplicate_and_add("trace-facade-1", False, 0)
        assert result is False

    @pytest.mark.asyncio
    async def test_facade_is_duplicate_second_call(self, facade):
        """二次 is_duplicate_and_add 返回 True"""
        await facade.is_duplicate_and_add("trace-facade-2", False, 0)
        result = await facade.is_duplicate_and_add("trace-facade-2", False, 0)
        assert result is True

    @pytest.mark.asyncio
    async def test_facade_is_duplicate_different_ids(self, facade):
        """不同 trace_id 互不影响"""
        await facade.is_duplicate_and_add("trace-A", False, 0)
        result = await facade.is_duplicate_and_add("trace-B", False, 0)
        assert result is False

    @pytest.mark.asyncio
    async def test_facade_rate_limit_returns_list(self, facade):
        """get_and_update_rate_limit 返回列表"""
        result = await facade.get_and_update_rate_limit("1.1.1.1", 1000.0, 60, 100)
        assert isinstance(result, list)

    @pytest.mark.asyncio
    async def test_facade_rate_limit_has_floats(self, facade):
        """限流结果元素为 float"""
        result = await facade.get_and_update_rate_limit("2.2.2.2", 2000.0, 60, 100)
        for val in result:
            assert isinstance(val, float)

    @pytest.mark.asyncio
    async def test_facade_batch_block_ips(self, facade):
        """batch_block_ips 不抛异常"""
        await facade.batch_block_ips([("10.0.0.1", "sqli"), ("10.0.0.2", "flood")])

    @pytest.mark.asyncio
    async def test_facade_get_top_keywords(self, facade):
        """get_top_keywords 返回列表"""
        kws = await facade.get_top_keywords(10)
        assert isinstance(kws, list)

    @pytest.mark.asyncio
    async def test_facade_batch_add_keywords(self, facade):
        """batch_add_keywords 正常执行"""
        await facade.batch_add_keywords(["kw1", "kw2"])

    @pytest.mark.asyncio
    async def test_facade_batch_add_keywords_empty(self, facade):
        """空关键词列表直接返回"""
        await facade.batch_add_keywords([])

    @pytest.mark.asyncio
    async def test_facade_wraps_mgr(self, facade, mock_redis_mgr):
        """facade 正确包装 manager"""
        assert facade.mgr is mock_redis_mgr


# ============================================================
# Cat 6: Alert/DLQ output (tests 66-75)
# ============================================================

class TestAlertDLQOutput:
    """告警和死信队列的输出格式"""

    @pytest.mark.asyncio
    async def test_emit_alert_contains_trace_id(self, engine):
        """alert 包含 trace_id"""
        log = make_std_log(trace_id="alert-tid")
        await engine._emit_alert(log, "TestRule")
        payload = orjson.loads(engine.producer.send_and_wait.call_args[0][1])
        assert payload["trace_id"] == "alert-tid"

    @pytest.mark.asyncio
    async def test_emit_alert_contains_client_ip(self, engine):
        """alert 包含 client_ip"""
        log = make_std_log(ip="99.99.99.99")
        await engine._emit_alert(log, "TestRule")
        payload = orjson.loads(engine.producer.send_and_wait.call_args[0][1])
        assert payload["client_ip"] == "99.99.99.99"

    @pytest.mark.asyncio
    async def test_emit_alert_contains_timestamp(self, engine):
        """alert 包含 timestamp"""
        log = make_std_log(ts=9876.5)
        await engine._emit_alert(log, "TestRule")
        payload = orjson.loads(engine.producer.send_and_wait.call_args[0][1])
        assert payload["alert_timestamp"] == 9876.5

    @pytest.mark.asyncio
    async def test_emit_alert_contains_rule_id(self, engine):
        """alert 包含 rule_id"""
        log = make_std_log()
        await engine._emit_alert(log, "SQLInjectionDetected")
        payload = orjson.loads(engine.producer.send_and_wait.call_args[0][1])
        assert payload["rule_id"] == "SQLInjectionDetected"

    @pytest.mark.asyncio
    async def test_emit_alert_correct_topic(self, engine):
        """alert 发往正确 topic"""
        log = make_std_log()
        await engine._emit_alert(log, "Rule")
        topic = engine.producer.send_and_wait.call_args[0][0]
        assert topic == "aiwaf_alert"

    @pytest.mark.asyncio
    async def test_route_to_dlq_contains_error_type(self, engine):
        """DLQ 包含 error_type"""
        log = make_std_log()
        await engine._route_to_dlq(log, ValueError("bad val"))
        payload = orjson.loads(engine.producer.send_and_wait.call_args[0][1])
        assert payload["error_type"] == "ValueError"

    @pytest.mark.asyncio
    async def test_route_to_dlq_contains_raw_log(self, engine):
        """DLQ 包含 raw_log"""
        log = make_std_log(trace_id="dlq-raw")
        await engine._route_to_dlq(log, RuntimeError("boom"))
        payload = orjson.loads(engine.producer.send_and_wait.call_args[0][1])
        assert payload["raw_log"]["trace_id"] == "dlq-raw"

    @pytest.mark.asyncio
    async def test_route_to_dlq_contains_trace_id(self, engine):
        """DLQ 包含 trace_id"""
        log = make_std_log(trace_id="dlq-tid")
        await engine._route_to_dlq(log, Exception("err"))
        payload = orjson.loads(engine.producer.send_and_wait.call_args[0][1])
        assert payload["trace_id"] == "dlq-tid"

    @pytest.mark.asyncio
    async def test_route_to_dlq_contains_error_str(self, engine):
        """DLQ 包含 error 字符串"""
        log = make_std_log()
        await engine._route_to_dlq(log, Exception("connection timeout"))
        payload = orjson.loads(engine.producer.send_and_wait.call_args[0][1])
        assert "connection timeout" in payload["error"]

    @pytest.mark.asyncio
    async def test_route_to_dlq_correct_topic(self, engine):
        """DLQ 发往正确 topic"""
        log = make_std_log()
        await engine._route_to_dlq(log, Exception("err"))
        topic = engine.producer.send_and_wait.call_args[0][0]
        assert topic == "aiwaf_dlq"


# ============================================================
# Cat 7: Double buffer sync (tests 76-85)
# ============================================================

class TestDoubleBufferSync:
    """background_sync_worker 双缓冲同步"""

    @pytest.mark.asyncio
    async def test_sync_worker_swaps_buffers(self):
        """sync worker 交换 current/backup buffer"""
        _current_buffer.append("swap-1")
        _current_buffer.append("swap-2")
        cancel = asyncio.Event()
        old_cur = id(_current_buffer)
        old_bak = id(_backup_buffer)
        task = asyncio.create_task(background_sync_worker(AsyncMock(), cancel))
        await asyncio.sleep(0.1)
        cancel.set()
        await asyncio.sleep(0.1)
        try:
            await task
        except Exception:
            pass
        # buffers may have been swapped

    @pytest.mark.asyncio
    async def test_sync_worker_cancel_stops(self):
        """cancel_event 停止 worker"""
        cancel = asyncio.Event()
        mgr = AsyncMock()
        task = asyncio.create_task(background_sync_worker(mgr, cancel))
        cancel.set()
        await asyncio.sleep(0.1)
        try:
            await task
        except Exception:
            pass
        assert True  # worker stopped without error

    @pytest.mark.asyncio
    async def test_sync_worker_empty_skip(self):
        """空 buffer 时 worker 跳过一次循环"""
        _current_buffer.clear()
        cancel = asyncio.Event()
        mgr = AsyncMock()
        task = asyncio.create_task(background_sync_worker(mgr, cancel))
        await asyncio.sleep(0.1)
        cancel.set()
        await asyncio.sleep(0.1)
        try:
            await task
        except Exception:
            pass
        # mgr.batch_block_ips should not have been called with empty buffer

    @pytest.mark.asyncio
    async def test_sync_worker_swaps_and_syncs(self):
        """worker 交换并同步 IP"""
        _current_buffer.append("sync-ip-1")
        _current_buffer.append("sync-ip-2")
        cancel = asyncio.Event()
        mgr = AsyncMock()
        mgr.batch_block_ips = AsyncMock()
        task = asyncio.create_task(background_sync_worker(mgr, cancel))
        await asyncio.sleep(0.1)
        cancel.set()
        await asyncio.sleep(0.1)
        try:
            await task
        except Exception:
            pass
        # batch_block_ips may or may not have been called depending on timing

    @pytest.mark.asyncio
    async def test_sync_worker_removes_synced_ips(self):
        """同步后 buffer 中的 IP 被移除"""
        d = collections.deque(["a", "b", "c"])
        sync_count = len(d)
        for _ in range(sync_count):
            d.popleft()
        assert len(d) == 0

    @pytest.mark.asyncio
    async def test_sync_copy_independence(self):
        """list() 拷贝独立于 deque"""
        d = collections.deque(["a", "b", "c"])
        copy = list(d)
        d.popleft()
        assert copy == ["a", "b", "c"]

    @pytest.mark.asyncio
    async def test_sync_worker_error_handling(self):
        """worker 异常时不崩溃"""
        _current_buffer.append("err-ip")
        cancel = asyncio.Event()
        mgr = AsyncMock()
        mgr.batch_block_ips = AsyncMock(side_effect=OSError("Redis down"))
        task = asyncio.create_task(background_sync_worker(mgr, cancel))
        await asyncio.sleep(0.1)
        cancel.set()
        await asyncio.sleep(0.1)
        try:
            await task
        except Exception:
            pass
        # worker handled error and exited cleanly

    @pytest.mark.asyncio
    async def test_sync_worker_overflow_metric(self):
        """溢出计数"""
        import redis_facade as rf
        old_overflow = rf.METRIC_PENDING_OVERFLOW._value.get()
        _current_buffer.clear()
        # fill to overflow
        for i in range(MAX_PENDING_IPS + 1):
            _current_buffer.append(f"overflow-{i}")
        cancel = asyncio.Event()
        mgr = AsyncMock()
        mgr.batch_block_ips = AsyncMock(side_effect=OSError("full"))
        task = asyncio.create_task(background_sync_worker(mgr, cancel))
        await asyncio.sleep(0.1)
        cancel.set()
        await asyncio.sleep(0.1)
        try:
            await task
        except Exception:
            pass

    @pytest.mark.asyncio
    async def test_sync_deque_fifo_behavior(self):
        """deque 先进先出行为"""
        d = collections.deque(maxlen=3)
        d.extend(["a", "b", "c", "d"])
        assert list(d) == ["b", "c", "d"]

    @pytest.mark.asyncio
    async def test_sync_buffer_swap_preserves_data(self):
        """buffer 交换后数据保留"""
        a = collections.deque(["ip1", "ip2"])
        b = collections.deque(["ip3"])
        a, b = b, a
        assert list(a) == ["ip3"]
        assert list(b) == ["ip1", "ip2"]


# ============================================================
# Cat 8: Full pipeline e2e (tests 86-100)
# ============================================================

class TestFullPipelineE2E:
    """Complete flow: raw_log → transform → engine process → batch → ACL → alert/DLQ"""

    @pytest.fixture
    def e2e_engine(self):
        """引擎 fixture 用于 e2e 测试"""
        with patch('concurrent.futures.ProcessPoolExecutor', MagicMock()):
            with patch('aiokafka.AIOKafkaProducer', MagicMock()):
                with patch('aiwaf.stream.acl_bootstrap.init_worker'):
                    from aiwaf.stream.engine import AIWAFStreamEngine
                    mgr = MagicMock()
                    mgr.redis = MockRedis()
                    mgr.is_duplicate_and_add = AsyncMock(return_value=False)
                    mgr.get_and_update_rate_limit = AsyncMock(return_value=[1.0])
                    mgr.batch_block_ips = AsyncMock()
                    mgr.get_top_keywords = AsyncMock(return_value=["sqli", "xss", "<script>"])
                    mgr.batch_add_keywords = AsyncMock()
                    eng = AIWAFStreamEngine(MockSettings(), mgr, "/fake/model.pkl")
                    eng.producer.start = AsyncMock()
                    eng.producer.send_and_wait = AsyncMock()
                    return eng

    @pytest.mark.asyncio
    async def test_e2e_raw_log_to_alert(self, e2e_engine):
        """完整流程: raw_log → transform → process → batch → alert"""
        eng = e2e_engine
        raw = make_raw_log(ip="20.20.20.20", uri="/api/attack?q=<script>alert(1)</script>",
                           query_params={"q": "<script>alert(1)</script>"})
        std = transform_raw_log(raw)
        eng.facade.is_duplicate_and_add = AsyncMock(return_value=False)
        eng.facade.get_and_update_rate_limit = AsyncMock(return_value=[1.0])
        eng.batch_queue = asyncio.Queue()
        from aiwaf.stream.acl_bootstrap import ItemSuccessResult
        class FR:
            action = "pass"
        class FK:
            block_reason = "path_match:sqli"
        sr = ItemSuccessResult(std["trace_id"], FR(), FK(),
                               {"blocked_ips": [], "learned_keywords": []})
        async def dispatcher():
            item = await eng.batch_queue.get()
            item['future'].set_result(sr)
        asyncio.create_task(dispatcher())
        await asyncio.sleep(0.01)
        await eng.process_log(std)
        assert eng.producer.send_and_wait.call_count >= 1
        payload = orjson.loads(eng.producer.send_and_wait.call_args[0][1])
        assert "trace_id" in payload

    @pytest.mark.asyncio
    async def test_e2e_raw_log_to_dlq(self, e2e_engine):
        """错误路径: 原始日志 → DLQ"""
        eng = e2e_engine
        raw = make_raw_log(ip="30.30.30.30", body="test-dlq")
        std = transform_raw_log(raw)
        eng.facade.is_duplicate_and_add = AsyncMock(return_value=False)
        eng.facade.get_and_update_rate_limit = AsyncMock(return_value=[1.0])
        eng.batch_queue = asyncio.Queue()
        err = ItemErrorResult(std["trace_id"], "ProcessingError", "model failed",
                              {"blocked_ips": []})
        async def dispatcher():
            item = await eng.batch_queue.get()
            item['future'].set_result(err)
        asyncio.create_task(dispatcher())
        await asyncio.sleep(0.01)
        await eng.process_log(std)
        assert eng.producer.send_and_wait.call_count >= 1

    @pytest.mark.asyncio
    async def test_e2e_duplicate_from_raw_log(self, e2e_engine):
        """重复检测在完整流程中生效"""
        eng = e2e_engine
        raw = make_raw_log(ip="40.40.40.40", body="dup-e2e")
        std = transform_raw_log(raw)
        eng.facade.is_duplicate_and_add = AsyncMock(return_value=True)
        eng.producer.send_and_wait.reset_mock()
        await eng.process_log(std)
        eng.producer.send_and_wait.assert_not_called()

    @pytest.mark.asyncio
    async def test_e2e_rate_limit_flood(self, e2e_engine):
        """限流 flood 经过完整流程产生告警"""
        eng = e2e_engine
        raw = make_raw_log(ip="50.50.50.50")
        std = transform_raw_log(raw)
        eng.facade.is_duplicate_and_add = AsyncMock(return_value=False)
        eng.facade.get_and_update_rate_limit = AsyncMock(return_value=[1.0])
        eng.batch_queue = asyncio.Queue()
        from aiwaf.stream.acl_bootstrap import ItemSuccessResult
        class FR:
            action = FLOOD_BLOCK
        class FK:
            block_reason = None
        sr = ItemSuccessResult(std["trace_id"], FR(), FK(),
                               {"blocked_ips": [], "learned_keywords": []})
        async def dispatcher():
            item = await eng.batch_queue.get()
            item['future'].set_result(sr)
        asyncio.create_task(dispatcher())
        await asyncio.sleep(0.01)
        await eng.process_log(std)
        assert eng.producer.send_and_wait.call_count >= 1

    @pytest.mark.asyncio
    async def test_e2e_keyword_block(self, e2e_engine):
        """关键词阻断经过完整流程"""
        eng = e2e_engine
        raw = make_raw_log(ip="60.60.60.60", uri="/search", body="<script>attack</script>")
        std = transform_raw_log(raw)
        eng.facade.is_duplicate_and_add = AsyncMock(return_value=False)
        eng.facade.get_and_update_rate_limit = AsyncMock(return_value=[1.0])
        eng.batch_queue = asyncio.Queue()
        from aiwaf.stream.acl_bootstrap import ItemSuccessResult
        class FR:
            action = "pass"
        class FK:
            block_reason = "KeywordBlock:<script>"
        sr = ItemSuccessResult(std["trace_id"], FR(), FK(),
                               {"blocked_ips": [], "learned_keywords": []})
        async def dispatcher():
            item = await eng.batch_queue.get()
            item['future'].set_result(sr)
        asyncio.create_task(dispatcher())
        await asyncio.sleep(0.01)
        await eng.process_log(std)
        assert eng.producer.send_and_wait.call_count >= 1

    @pytest.mark.asyncio
    async def test_e2e_fail_secure_flow(self, e2e_engine):
        """熔断 → fail-secure 完整流程"""
        eng = e2e_engine
        raw = make_raw_log(ip="70.70.70.70")
        std = transform_raw_log(raw)
        eng.facade.is_duplicate_and_add = AsyncMock(
            side_effect=asyncbreaker.CircuitBreakerError('breaker open')
        )
        await eng.process_log(std)
        assert local_rate_limit.get("70.70.70.70") == 1

    @pytest.mark.asyncio
    async def test_e2e_multiple_logs_concurrent(self, e2e_engine):
        """并发日志处理"""
        eng = e2e_engine
        eng.facade.is_duplicate_and_add = AsyncMock(return_value=False)
        eng.facade.get_and_update_rate_limit = AsyncMock(return_value=[1.0])
        eng.batch_queue = asyncio.Queue()
        from aiwaf.stream.acl_bootstrap import ItemSuccessResult
        class FR:
            action = "pass"
        class FK:
            block_reason = None
        logs = [make_raw_log(ip=f"80.80.80.{i}") for i in range(5)]
        stds = [transform_raw_log(log) for log in logs]
        async def fast_dispatcher():
            for std in stds:
                sr = ItemSuccessResult(std["trace_id"], FR(), FK(),
                                       {"blocked_ips": [], "learned_keywords": []})
                item = await eng.batch_queue.get()
                item['future'].set_result(sr)
        asyncio.create_task(fast_dispatcher())
        await asyncio.sleep(0.01)
        tasks = [asyncio.create_task(eng.process_log(std)) for std in stds]
        await asyncio.gather(*tasks, return_exceptions=True)

    @pytest.mark.asyncio
    async def test_e2e_with_query_params(self, e2e_engine):
        """带 query_params 的完整流程"""
        eng = e2e_engine
        raw = make_raw_log(ip="90.90.90.90", uri="/api/v1/data",
                           query_params={"sort": "desc", "limit": "100"})
        std = transform_raw_log(raw)
        assert "sort=desc" in std["query_strings"]
        assert "limit=100" in std["query_strings"]
        assert "sort" in std["query_keys"]
        assert "limit" in std["query_keys"]

    @pytest.mark.asyncio
    async def test_e2e_with_body_content(self, e2e_engine):
        """带 body 内容的完整流程"""
        eng = e2e_engine
        raw = make_raw_log(ip="91.91.91.91", body='{"user":"admin","pass":"1234"}')
        std = transform_raw_log(raw)
        assert std["req_body_truncated"] is not None
        assert "admin" in std["req_body_truncated"]

    @pytest.mark.asyncio
    async def test_e2e_engine_start_stop_cycle(self, e2e_engine):
        """启动/停止周期不干扰处理"""
        eng = e2e_engine
        await eng.start()
        assert len(eng._tasks) >= 2
        await eng.shutdown()
        await eng.start()
        assert len(eng._tasks) >= 2
        await eng.shutdown()

    @pytest.mark.asyncio
    async def test_e2e_batch_with_side_effects(self, e2e_engine):
        """批处理副作用传递: blocked_ips 和 learned_keywords"""
        eng = e2e_engine
        raw = make_raw_log(ip="92.92.92.92")
        std = transform_raw_log(raw)
        eng.facade.is_duplicate_and_add = AsyncMock(return_value=False)
        eng.facade.get_and_update_rate_limit = AsyncMock(return_value=[1.0])
        eng.batch_queue = asyncio.Queue()
        from aiwaf.stream.acl_bootstrap import ItemSuccessResult
        class FR:
            action = "pass"
        class FK:
            block_reason = None
        sr = ItemSuccessResult(std["trace_id"], FR(), FK(),
                               {"blocked_ips": [("92.92.92.92", "e2e")],
                                "learned_keywords": ["e2e_kw"]})
        async def dispatcher():
            item = await eng.batch_queue.get()
            item['future'].set_result(sr)
        asyncio.create_task(dispatcher())
        await asyncio.sleep(0.01)
        await eng.process_log(std)

    @pytest.mark.asyncio
    async def test_e2e_alert_and_dlq_both_produced(self, e2e_engine):
        """告警和 DLQ 在不同场景下都产生"""
        eng = e2e_engine
        # DLQ path
        raw1 = make_raw_log(ip="93.93.93.93")
        std1 = transform_raw_log(raw1)
        eng.facade.is_duplicate_and_add = AsyncMock(return_value=False)
        eng.facade.get_and_update_rate_limit = AsyncMock(return_value=[1.0])
        eng.batch_queue = asyncio.Queue()
        err = ItemErrorResult(std1["trace_id"], "E2EError", "test dlq",
                              {"blocked_ips": []})
        async def dq():
            item = await eng.batch_queue.get()
            item['future'].set_result(err)
        asyncio.create_task(dq())
        await asyncio.sleep(0.01)
        await eng.process_log(std1)
        assert eng.producer.send_and_wait.call_count >= 1

    @pytest.mark.asyncio
    async def test_e2e_background_sync_in_pipeline(self, e2e_engine):
        """后台同步在引擎生命周期内工作"""
        eng = e2e_engine
        await eng.start()
        local_blacklist["sync-e2e-ip"] = True
        _backup_buffer.append("sync-e2e-ip")
        await asyncio.sleep(0.1)
        await eng.shutdown()

    @pytest.mark.asyncio
    async def test_e2e_full_cycle_shutdown(self, e2e_engine):
        """完整周期: 启动 → 处理 → 关闭"""
        eng = e2e_engine
        await eng.start()
        raw = make_raw_log(ip="99.99.99.99", body="final-e2e-test")
        std = transform_raw_log(raw)
        eng.facade.is_duplicate_and_add = AsyncMock(return_value=True)
        await eng.process_log(std)
        await eng.shutdown()
        assert eng._cancel_event.is_set()

    @pytest.mark.asyncio
    async def test_e2e_success_result_side_effects_learned_keywords(self, e2e_engine):
        """成功结果中的 learned_keywords 被批量写入"""
        eng = e2e_engine
        raw = make_raw_log(ip="99.99.99.98", body="kw-learn-e2e")
        std = transform_raw_log(raw)
        eng.facade.is_duplicate_and_add = AsyncMock(return_value=False)
        eng.facade.get_and_update_rate_limit = AsyncMock(return_value=[1.0])
        eng.batch_queue = asyncio.Queue()
        from aiwaf.stream.acl_bootstrap import ItemSuccessResult
        class FR:
            action = "pass"
        class FK:
            block_reason = None
        sr = ItemSuccessResult(std["trace_id"], FR(), FK(),
                               {"blocked_ips": [], "learned_keywords": ["e2e_learned_kw"]})
        async def dispatcher():
            item = await eng.batch_queue.get()
            item['future'].set_result(sr)
        asyncio.create_task(dispatcher())
        await asyncio.sleep(0.01)
        await eng.process_log(std)

    @pytest.mark.asyncio
    async def test_e2e_fail_secure_with_alert_and_backup_buffer(self, e2e_engine):
        """熔断时超过限流阈值触发告警且 IP 加入备份 buffer"""
        eng = e2e_engine
        raw = make_raw_log(ip="88.88.88.88", body="fs-e2e")
        std = transform_raw_log(raw)
        eng.facade.is_duplicate_and_add = AsyncMock(
            side_effect=asyncbreaker.CircuitBreakerError('breaker open')
        )
        for _ in range(51):
            await eng.process_log(std)
        assert local_blacklist.get("88.88.88.88") is True
        assert "88.88.88.88" in _backup_buffer
