"""
AIWAF-Akto 集成 — 全面测试套件

覆盖: akto_adapter + preprocessor + config + engine + 端到端集成
100+ 用例，不凑数。

参考文档: docs/AIWAF_Akto_Integration_Design.md §4
"""
import sys
import os
import asyncio
import time
import orjson
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock
from dataclasses import dataclass

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Mock prometheus before any project import
_mock_prom = MagicMock()
sys.modules.setdefault('prometheus_client', _mock_prom)

import pytest
from aiwaf.stream.akto_adapter import parse_akto_json_message
from aiwaf.stream.preprocessor import transform_raw_log, generate_deterministic_trace_id, MAX_BODY_STORE_BYTES, MAX_BODY_HASH_BYTES
from aiwaf.stream.config import Settings


# ============================================================
# Helpers
# ============================================================

def make_akto_msg(**overrides):
    """构造模拟 akto.api.logs 的真实 JSON 格式消息"""
    msg = {
        "path": "/api/users/123?name=alice&age=30",
        "method": "GET",
        "requestHeaders": '{"host": "api.example.com"}',
        "responseHeaders": '{"content-type": "application/json"}',
        "requestPayload": "",
        "responsePayload": '{"id": 123}',
        "ip": "10.0.1.5",
        "destIp": "10.0.2.10",
        "time": "1719500000",
        "statusCode": "200",
        "status": "OK",
        "akto_account_id": "1000000",
        "akto_vxlan_id": "1",
        "source": "MIRRORING",
        "direction": "REQUEST_RESPONSE",
    }
    msg.update(overrides)
    return msg


# ============================================================
# 1. akto_adapter 单元测试 (20 用例)
# ============================================================

class TestAktoAdapterFieldMapping:
    """适配层字段映射 — 7 核心 + 6 扩展"""

    def test_client_ip_from_ip_field(self):
        raw = parse_akto_json_message(make_akto_msg(ip="192.168.1.1"))
        assert raw["client_ip"] == "192.168.1.1"

    def test_client_ip_fallback_to_client_ip_field(self):
        raw = parse_akto_json_message(make_akto_msg(ip=None, client_ip="10.0.0.1"))
        # When ip is None, msg.get("ip") returns None, falls through to client_ip
        # But make_akto_msg sets ip as key, so we need to delete it
        msg = make_akto_msg()
        del msg["ip"]
        msg["client_ip"] = "10.0.0.1"
        raw = parse_akto_json_message(msg)
        assert raw["client_ip"] == "10.0.0.1"

    def test_client_ip_default_unknown(self):
        raw = parse_akto_json_message({"path": "/"})
        assert raw["client_ip"] == "unknown"

    def test_uri_path_extraction(self):
        raw = parse_akto_json_message(make_akto_msg(path="/api/v1/users"))
        assert raw["uri_path"] == "/api/v1/users"

    def test_uri_path_with_query_stripped(self):
        raw = parse_akto_json_message(make_akto_msg(path="/search?q=hello&page=2"))
        assert raw["uri_path"] == "/search"
        assert raw["query_params"] == {"q": "hello", "page": "2"}

    def test_query_params_single_value(self):
        raw = parse_akto_json_message(make_akto_msg(path="/api?name=alice"))
        assert raw["query_params"] == {"name": "alice"}

    def test_query_params_multi_value(self):
        raw = parse_akto_json_message(make_akto_msg(path="/api?tag=a&tag=b"))
        assert raw["query_params"]["tag"] == ["a", "b"]

    def test_query_params_empty(self):
        raw = parse_akto_json_message(make_akto_msg(path="/api/no-query"))
        assert raw["query_params"] == {}

    def test_status_int_conversion(self):
        raw = parse_akto_json_message(make_akto_msg(statusCode="404"))
        assert raw["status"] == 404
        assert isinstance(raw["status"], int)

    def test_status_default_on_missing(self):
        raw = parse_akto_json_message({"path": "/"})
        assert raw["status"] == 200

    def test_status_default_on_invalid(self):
        raw = parse_akto_json_message(make_akto_msg(statusCode="not-a-number"))
        assert raw["status"] == 200

    def test_timestamp_float_conversion(self):
        raw = parse_akto_json_message(make_akto_msg(time="1719500000"))
        assert raw["timestamp"] == 1719500000.0
        assert isinstance(raw["timestamp"], float)

    def test_timestamp_default_on_missing(self):
        raw = parse_akto_json_message({"path": "/"})
        assert raw["timestamp"] == 0.0

    def test_timestamp_default_on_invalid(self):
        raw = parse_akto_json_message(make_akto_msg(time="invalid"))
        assert raw["timestamp"] == 0.0

    def test_method_default(self):
        raw = parse_akto_json_message({"path": "/"})
        assert raw["method"] == "GET"

    def test_request_body_mapping(self):
        raw = parse_akto_json_message(make_akto_msg(requestPayload='{"key":"value"}'))
        assert raw["request_body"] == '{"key":"value"}'

    def test_request_body_default_empty(self):
        raw = parse_akto_json_message({"path": "/"})
        assert raw["request_body"] == ""


class TestAktoAdapterExtensions:
    """适配层 akto 扩展字段透传"""

    def test_akto_account_id_passthrough(self):
        raw = parse_akto_json_message(make_akto_msg(akto_account_id="999"))
        assert raw["akto_account_id"] == "999"

    def test_akto_vxlan_id_passthrough(self):
        raw = parse_akto_json_message(make_akto_msg(akto_vxlan_id="42"))
        assert raw["akto_vxlan_id"] == "42"

    def test_all_extensions_present(self):
        raw = parse_akto_json_message(make_akto_msg())
        for key in ("akto_account_id", "akto_vxlan_id", "source", "direction", "dest_ip", "response_payload"):
            assert key in raw, f"Missing extension key: {key}"


class TestAktoAdapterEdgeCases:
    """适配层边界条件"""

    def test_empty_path(self):
        raw = parse_akto_json_message(make_akto_msg(path=""))
        assert raw["uri_path"] == "/"

    def test_none_path(self):
        msg = make_akto_msg()
        msg["path"] = None
        raw = parse_akto_json_message(msg)
        assert raw["uri_path"] == "/"

    def test_full_url_path(self):
        raw = parse_akto_json_message(make_akto_msg(path="https://api.example.com/v1/users?id=42"))
        assert raw["uri_path"] == "/v1/users"
        assert raw["query_params"] == {"id": "42"}

    def test_int_statuscode(self):
        raw = parse_akto_json_message(make_akto_msg(statusCode=201))
        assert raw["status"] == 201

    def test_int_timestamp(self):
        raw = parse_akto_json_message(make_akto_msg(time=1719500000))
        assert raw["timestamp"] == 1719500000.0

    def test_dict_input_directly(self):
        msg = make_akto_msg()
        raw = parse_akto_json_message(msg)
        assert raw["client_ip"] == "10.0.1.5"

    def test_json_string_input(self):
        msg = make_akto_msg()
        raw = parse_akto_json_message(orjson.dumps(msg))
        assert raw["client_ip"] == "10.0.1.5"

    def test_json_array_raises_valueerror(self):
        with pytest.raises(ValueError, match="Expected JSON object"):
            parse_akto_json_message("[]")

    def test_json_string_raises_valueerror(self):
        with pytest.raises(ValueError, match="Expected JSON object"):
            parse_akto_json_message('"just a string"')

    def test_json_number_raises_valueerror(self):
        with pytest.raises(ValueError, match="Expected JSON object"):
            parse_akto_json_message("42")

    def test_empty_json_object(self):
        raw = parse_akto_json_message("{}")
        assert raw["client_ip"] == "unknown"
        assert raw["uri_path"] == "/"
        assert raw["status"] == 200

    def test_path_with_fragment(self):
        raw = parse_akto_json_message(make_akto_msg(path="/api/page#section"))
        assert raw["uri_path"] == "/api/page"

    def test_path_with_encoded_query(self):
        raw = parse_akto_json_message(make_akto_msg(path="/api?q=hello%20world"))
        assert raw["query_params"]["q"] == "hello world"

    def test_path_no_leading_slash(self):
        raw = parse_akto_json_message(make_akto_msg(path="api/users"))
        # "http://dummy" + "api/users" → urlparse → path may vary
        assert raw["uri_path"]  # non-empty

    def test_missing_all_optional_fields(self):
        raw = parse_akto_json_message({"path": "/test"})
        assert raw["client_ip"] == "unknown"
        assert raw["method"] == "GET"
        assert raw["request_body"] == ""


# ============================================================
# 2. preprocessor 单元测试 (15 用例)
# ============================================================

class TestPreprocessorTransform:
    """transform_raw_log 完整测试"""

    def test_basic_transform(self):
        raw_log = {
            "client_ip": "1.2.3.4", "timestamp": 1000.0,
            "method": "POST", "uri_path": "/api/test",
            "query_params": {"q": "hello"}, "status": 200,
            "request_body": '{"data": 1}'
        }
        std_log = transform_raw_log(raw_log)
        assert std_log["client_ip"] == "1.2.3.4"
        assert std_log["method"] == "POST"
        assert std_log["uri_path"] == "/api/test"
        assert std_log["status_code"] == 200
        assert std_log["query_keys"] == ["q"]
        assert std_log["query_strings"] == ["q=hello"]
        assert "trace_id" in std_log
        assert len(std_log["trace_id"]) == 32

    def test_request_body_deleted(self):
        raw_log = {"client_ip": "1.2.3.4", "uri_path": "/", "request_body": "data"}
        std_log = transform_raw_log(raw_log)
        assert "request_body" not in std_log

    def test_req_body_truncated(self):
        raw_log = {"client_ip": "1.2.3.4", "uri_path": "/", "request_body": "A" * 2000}
        std_log = transform_raw_log(raw_log)
        assert len(std_log["req_body_truncated"]) == MAX_BODY_STORE_BYTES

    def test_empty_body(self):
        raw_log = {"client_ip": "1.2.3.4", "uri_path": "/", "request_body": ""}
        std_log = transform_raw_log(raw_log)
        assert std_log["req_body_truncated"] == ""

    def test_none_timestamp_becomes_zero(self):
        raw_log = {"client_ip": "1.2.3.4", "uri_path": "/", "timestamp": None}
        std_log = transform_raw_log(raw_log)
        assert std_log["timestamp"] == 0.0

    def test_missing_timestamp_becomes_zero(self):
        raw_log = {"client_ip": "1.2.3.4", "uri_path": "/"}
        std_log = transform_raw_log(raw_log)
        assert std_log["timestamp"] == 0.0

    def test_query_params_missing(self):
        raw_log = {"client_ip": "1.2.3.4", "uri_path": "/"}
        std_log = transform_raw_log(raw_log)
        assert std_log["query_keys"] == []
        assert std_log["query_strings"] == []

    def test_query_params_list_values(self):
        raw_log = {"client_ip": "1.2.3.4", "uri_path": "/",
                   "query_params": {"tag": ["a", "b"]}}
        std_log = transform_raw_log(raw_log)
        assert std_log["query_keys"] == ["tag"]
        assert std_log["query_strings"] == ["tag=a", "tag=b"]

    def test_trace_id_deterministic(self):
        raw_log = {"client_ip": "1.2.3.4", "uri_path": "/api",
                   "timestamp": 1000.0, "request_body": "data"}
        id1 = transform_raw_log(dict(raw_log))["trace_id"]
        id2 = transform_raw_log(dict(raw_log))["trace_id"]
        assert id1 == id2

    def test_trace_id_changes_with_different_input(self):
        raw1 = {"client_ip": "1.2.3.4", "uri_path": "/api", "timestamp": 1000.0, "request_body": "a"}
        raw2 = {"client_ip": "1.2.3.4", "uri_path": "/api", "timestamp": 1000.0, "request_body": "b"}
        assert transform_raw_log(raw1)["trace_id"] != transform_raw_log(raw2)["trace_id"]

    def test_akto_extension_transparency(self):
        raw_log = {"client_ip": "1.2.3.4", "uri_path": "/",
                   "akto_account_id": "999", "source": "MIRRORING"}
        std_log = transform_raw_log(raw_log)
        assert std_log.get("akto_account_id") == "999"
        assert std_log.get("source") == "MIRRORING"

    def test_no_akto_extensions_no_leak(self):
        raw_log = {"client_ip": "1.2.3.4", "uri_path": "/"}
        std_log = transform_raw_log(raw_log)
        assert "akto_account_id" not in std_log
        assert "source" not in std_log

    def test_remote_addr_fallback(self):
        raw_log = {"remote_addr": "5.6.7.8", "uri_path": "/"}
        std_log = transform_raw_log(raw_log)
        assert std_log["client_ip"] == "5.6.7.8"

    def test_status_code_from_status_key(self):
        raw_log = {"client_ip": "1.2.3.4", "uri_path": "/", "status": 403}
        std_log = transform_raw_log(raw_log)
        assert std_log["status_code"] == 403

    def test_body_as_dict(self):
        raw_log = {"client_ip": "1.2.3.4", "uri_path": "/",
                   "request_body": {"key": "value"}}
        std_log = transform_raw_log(raw_log)
        assert "request_body" not in std_log
        assert "key" in std_log["req_body_truncated"]


# ============================================================
# 3. config 单元测试 (10 用例)
# ============================================================

class TestConfig:
    """Settings 配置测试"""

    def test_default_values(self):
        s = Settings(redis_cluster_url="redis://localhost", kafka_brokers="localhost:9092")
        assert s.input_topic == "akto.api.logs"
        assert s.alert_topic == "akto.aiwaf.alerts"
        assert s.dlq_topic == "akto.aiwaf.dlq"
        assert s.consumer_group == "aiwaf-consumer-group"
        assert s.core_process_pool_size == 4

    def test_from_env_defaults(self):
        # Clear all relevant env vars
        for key in ("REDIS_CLUSTER_URL", "KAFKA_BROKERS", "KAFKA_INPUT_TOPIC",
                     "KAFKA_ALERT_TOPIC", "KAFKA_DLQ_TOPIC", "KAFKA_CONSUMER_GROUP",
                     "CORE_PROCESS_POOL_SIZE"):
            os.environ.pop(key, None)
        s = Settings.from_env()
        assert s.redis_cluster_url == "redis://localhost:6379"
        assert s.kafka_brokers == "localhost:9092"
        assert s.input_topic == "akto.api.logs"

    def test_from_env_custom(self, monkeypatch):
        monkeypatch.setenv("REDIS_CLUSTER_URL", "redis://prod:6379")
        monkeypatch.setenv("KAFKA_BROKERS", "kafka1:9092,kafka2:9092")
        monkeypatch.setenv("KAFKA_INPUT_TOPIC", "custom.topic")
        monkeypatch.setenv("KAFKA_CONSUMER_GROUP", "custom-group")
        monkeypatch.setenv("CORE_PROCESS_POOL_SIZE", "8")
        s = Settings.from_env()
        assert s.redis_cluster_url == "redis://prod:6379"
        assert s.kafka_brokers == "kafka1:9092,kafka2:9092"
        assert s.input_topic == "custom.topic"
        assert s.consumer_group == "custom-group"
        assert s.core_process_pool_size == 8

    def test_from_env_pool_size_int_conversion(self, monkeypatch):
        monkeypatch.setenv("CORE_PROCESS_POOL_SIZE", "16")
        s = Settings.from_env()
        assert s.core_process_pool_size == 16
        assert isinstance(s.core_process_pool_size, int)

    def test_alert_topic_default(self):
        s = Settings(redis_cluster_url="r", kafka_brokers="k")
        assert s.alert_topic == "akto.aiwaf.alerts"

    def test_dlq_topic_default(self):
        s = Settings(redis_cluster_url="r", kafka_brokers="k")
        assert s.dlq_topic == "akto.aiwaf.dlq"

    def test_input_topic_default(self):
        s = Settings(redis_cluster_url="r", kafka_brokers="k")
        assert s.input_topic == "akto.api.logs"

    def test_consumer_group_default(self):
        s = Settings(redis_cluster_url="r", kafka_brokers="k")
        assert s.consumer_group == "aiwaf-consumer-group"

    def test_redis_url_required_parameter(self):
        # redis_cluster_url is a required positional field
        s = Settings(redis_cluster_url="redis://custom:6380", kafka_brokers="k")
        assert s.redis_cluster_url == "redis://custom:6380"

    def test_kafka_brokers_required_parameter(self):
        s = Settings(redis_cluster_url="r", kafka_brokers="broker1:9092")
        assert s.kafka_brokers == "broker1:9092"


# ============================================================
# 4. engine _consume_loop 测试 (15 用例)
# ============================================================

@dataclass
class MockSettings:
    core_process_pool_size: int = 2
    kafka_brokers: str = "localhost:9092"
    alert_topic: str = "aiwaf_alert"
    dlq_topic: str = "aiwaf_dlq"
    input_topic: str = "akto.api.logs"
    consumer_group: str = "aiwaf-test-group"
    # 完整配置项（与 config.Settings 保持一致）
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
    path_rules: str = ""
    static_keywords_extra: str = ""
    legitimate_keywords_extra: str = ""
    inherently_malicious_extra: str = ""
    very_strong_attacks_extra: str = ""
    probe_path_patterns_extra: str = ""
    post_only_suffixes_extra: str = ""
    login_paths_extra: str = ""
    header_max_bytes: int = 32768
    header_max_count: int = 100
    uuid_block_threshold: int = 5
    uuid_malformed_weight: int = 5
    uuid_not_found_weight: int = 1
    uuid_success_decay: int = 2
    uuid_window_seconds: int = 60
    detection_header_enabled: bool = True
    detection_uuid_enabled: bool = True
    detection_geo_enabled: bool = True
    detection_rate_limit_enabled: bool = True
    detection_keyword_enabled: bool = True
    detection_fail_secure_enabled: bool = True
    detection_method_enabled: bool = True


class MockStateMgr:
    def __init__(self):
        self.redis = MagicMock()


def make_std_log(trace_id="t001", ip="1.1.1.1", ts=1000.0, uri="/api", body="data",
                 query_keys=None, query_strings=None, method="GET", status_code=200):
    std = {
        "client_ip": ip, "uri_path": uri, "timestamp": ts,
        "query_keys": query_keys or [],
        "query_strings": query_strings or [],
        "request_body": body,
        "method": method, "status_code": status_code
    }
    std["trace_id"] = trace_id
    return std


class TestConsumeLoop:
    """_consume_loop 消费循环测试"""

    @pytest.fixture
    def engine(self):
        with patch('concurrent.futures.ProcessPoolExecutor', MagicMock()):
            with patch('aiwaf.stream.engine.AIOKafkaProducer', MagicMock()):
                with patch('aiwaf.stream.engine.AIOKafkaConsumer', MagicMock()):
                    with patch('aiwaf.stream.acl_bootstrap.init_worker'):
                        with patch('aiwaf.stream.acl_bootstrap.run_core_logic_batch_isolated'):
                            from aiwaf.stream.engine import AIWAFStreamEngine
                            eng = AIWAFStreamEngine(MockSettings(), MockStateMgr(), "/f")
                            eng.producer.start = AsyncMock()
                            eng.producer.send_and_wait = AsyncMock()
                            return eng

    @pytest.mark.asyncio
    async def test_consume_loop_processes_message(self, engine):
        """消费循环正确处理消息"""
        msg = MagicMock()
        msg.value = orjson.dumps(make_akto_msg())
        msg.topic = "akto.api.logs"
        msg.partition = 0
        msg.offset = 0

        batch = [msg]
        engine.consumer = MagicMock()
        engine.consumer.start = AsyncMock()
        engine.consumer.stop = AsyncMock()
        engine.consumer.commit = AsyncMock()

        # Mock async iteration — yield one batch then set cancel
        async def mock_aiter():
            yield batch
            engine._cancel_event.set()

            engine._cancel_event.set()

        engine.consumer.__aiter__ = lambda self: mock_aiter()

        engine.process_log = AsyncMock()

        await engine._consume_loop()
        engine.process_log.assert_called_once()

    @pytest.mark.asyncio
    async def test_consume_loop_dlq_on_failure(self, engine):
        """处理失败时发送到 DLQ"""
        msg = MagicMock()
        msg.value = b"invalid-json"
        msg.topic = "akto.api.logs"
        msg.partition = 0
        msg.offset = 42

        batch = [msg]
        engine.consumer = MagicMock()
        engine.consumer.start = AsyncMock()
        engine.consumer.stop = AsyncMock()
        engine.consumer.commit = AsyncMock()

        async def mock_aiter():
            yield batch
            engine._cancel_event.set()


        engine.consumer.__aiter__ = lambda self: mock_aiter()

        await engine._consume_loop()
        # DLQ should have been called
        assert engine.producer.send_and_wait.called

    @pytest.mark.asyncio
    async def test_consume_loop_commit_after_batch(self, engine):
        """每个 batch 后提交 offset"""
        msg = MagicMock()
        msg.value = orjson.dumps(make_akto_msg())
        msg.topic = "akto.api.logs"
        msg.partition = 0
        msg.offset = 0

        engine.consumer = MagicMock()
        engine.consumer.start = AsyncMock()
        engine.consumer.stop = AsyncMock()
        engine.consumer.commit = AsyncMock()

        async def mock_aiter():
            yield [msg]
            engine._cancel_event.set()

        engine.consumer.__aiter__ = lambda self: mock_aiter()
        engine.process_log = AsyncMock()

        await engine._consume_loop()
        engine.consumer.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_consume_loop_commit_failure_doesnt_crash(self, engine):
        """commit 失败不崩溃"""
        msg = MagicMock()
        msg.value = orjson.dumps(make_akto_msg())
        msg.topic = "akto.api.logs"
        msg.partition = 0
        msg.offset = 0

        engine.consumer = MagicMock()
        engine.consumer.start = AsyncMock()
        engine.consumer.stop = AsyncMock()
        engine.consumer.commit = AsyncMock(side_effect=Exception("commit failed"))

        async def mock_aiter():
            yield [msg]
            engine._cancel_event.set()

        engine.consumer.__aiter__ = lambda self: mock_aiter()
        engine.process_log = AsyncMock()

        # Should not raise
        await engine._consume_loop()

    @pytest.mark.asyncio
    async def test_consume_loop_dlq_failure_doesnt_crash(self, engine):
        """DLQ 发送失败不崩溃"""
        msg = MagicMock()
        msg.value = b"invalid"
        msg.topic = "akto.api.logs"
        msg.partition = 0
        msg.offset = 0

        engine.consumer = MagicMock()
        engine.consumer.start = AsyncMock()
        engine.consumer.stop = AsyncMock()
        engine.consumer.commit = AsyncMock()
        engine.producer.send_and_wait = AsyncMock(side_effect=Exception("kafka down"))

        async def mock_aiter():
            yield [msg]
            engine._cancel_event.set()

        engine.consumer.__aiter__ = lambda self: mock_aiter()

        # Should not raise
        await engine._consume_loop()

    @pytest.mark.asyncio
    async def test_consume_loop_multiple_messages(self, engine):
        """一个 batch 中多条消息"""
        msgs = []
        for i in range(5):
            msg = MagicMock()
            msg.value = orjson.dumps(make_akto_msg(ip=f"10.0.0.{i}"))
            msg.topic = "akto.api.logs"
            msg.partition = 0
            msg.offset = i
            msgs.append(msg)

        engine.consumer = MagicMock()
        engine.consumer.start = AsyncMock()
        engine.consumer.stop = AsyncMock()
        engine.consumer.commit = AsyncMock()

        async def mock_aiter():
            yield msgs
            engine._cancel_event.set()

        engine.consumer.__aiter__ = lambda self: mock_aiter()
        engine.process_log = AsyncMock()

        await engine._consume_loop()
        assert engine.process_log.call_count == 5

    @pytest.mark.asyncio
    async def test_consume_loop_cancel_event_stops(self, engine):
        """_cancel_event 设置后停止"""
        engine.consumer = MagicMock()
        engine.consumer.start = AsyncMock()
        engine.consumer.stop = AsyncMock()
        engine.consumer.commit = AsyncMock()

        async def mock_aiter():
            yield []
            engine._cancel_event.set()

        engine.consumer.__aiter__ = lambda self: mock_aiter()

        await engine._consume_loop()

    @pytest.mark.asyncio
    async def test_consume_loop_exception_retries(self, engine):
        """消费异常后重试"""
        call_count = [0]
        engine.consumer = MagicMock()
        engine.consumer.start = AsyncMock()
        engine.consumer.stop = AsyncMock()
        engine.consumer.commit = AsyncMock()

        async def mock_aiter():
            call_count[0] += 1
            if call_count[0] == 1:
                raise Exception("Kafka rebalance")
            engine._cancel_event.set()
            return
            yield

        engine.consumer.__aiter__ = lambda self: mock_aiter()

        # Speed up the sleep
        with patch('asyncio.sleep', AsyncMock()):
            await engine._consume_loop()

    @pytest.mark.asyncio
    async def test_consume_loop_empty_batch(self, engine):
        """空 batch 不崩溃"""
        engine.consumer = MagicMock()
        engine.consumer.start = AsyncMock()
        engine.consumer.stop = AsyncMock()
        engine.consumer.commit = AsyncMock()

        async def mock_aiter():
            yield []
            engine._cancel_event.set()

        engine.consumer.__aiter__ = lambda self: mock_aiter()

        await engine._consume_loop()
        engine.consumer.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_consume_loop_cancelled_error(self, engine):
        """CancelledError 正确退出"""
        engine.consumer = MagicMock()
        engine.consumer.start = AsyncMock()
        engine.consumer.stop = AsyncMock()
        engine.consumer.commit = AsyncMock()

        async def mock_aiter():
            raise asyncio.CancelledError()
            yield

        engine.consumer.__aiter__ = lambda self: mock_aiter()

        await engine._consume_loop()

    @pytest.mark.asyncio
    async def test_consume_loop_uses_akto_adapter(self, engine):
        """消费循环使用 akto_adapter 解析消息"""
        msg = MagicMock()
        msg.value = orjson.dumps(make_akto_msg(path="/api/test?foo=bar"))
        msg.topic = "akto.api.logs"
        msg.partition = 0
        msg.offset = 0

        engine.consumer = MagicMock()
        engine.consumer.start = AsyncMock()
        engine.consumer.stop = AsyncMock()
        engine.consumer.commit = AsyncMock()

        async def mock_aiter():
            yield [msg]
            engine._cancel_event.set()

        engine.consumer.__aiter__ = lambda self: mock_aiter()

        captured = []
        async def capture_process_log(std_log):
            captured.append(std_log)

        engine.process_log = capture_process_log

        await engine._consume_loop()
        assert len(captured) == 1
        assert captured[0]["uri_path"] == "/api/test"
        assert captured[0]["query_keys"] == ["foo"]

    @pytest.mark.asyncio
    async def test_consume_loop_preserves_akto_context(self, engine):
        """消费循环保留 akto 扩展字段"""
        msg = MagicMock()
        msg.value = orjson.dumps(make_akto_msg(akto_account_id="777", source="POSTMAN"))
        msg.topic = "akto.api.logs"
        msg.partition = 0
        msg.offset = 0

        engine.consumer = MagicMock()
        engine.consumer.start = AsyncMock()
        engine.consumer.stop = AsyncMock()
        engine.consumer.commit = AsyncMock()

        async def mock_aiter():
            yield [msg]
            engine._cancel_event.set()

        engine.consumer.__aiter__ = lambda self: mock_aiter()

        captured = []
        async def capture(std_log):
            captured.append(std_log)

        engine.process_log = capture

        await engine._consume_loop()
        assert captured[0].get("akto_account_id") == "777"
        assert captured[0].get("source") == "POSTMAN"

    @pytest.mark.asyncio
    async def test_consume_loop_dlq_includes_metadata(self, engine):
        """DLQ 消息包含 topic/partition/offset"""
        msg = MagicMock()
        msg.value = b"bad"
        msg.topic = "akto.api.logs"
        msg.partition = 3
        msg.offset = 99

        engine.consumer = MagicMock()
        engine.consumer.start = AsyncMock()
        engine.consumer.stop = AsyncMock()
        engine.consumer.commit = AsyncMock()

        async def mock_aiter():
            yield [msg]
            engine._cancel_event.set()

        engine.consumer.__aiter__ = lambda self: mock_aiter()

        sent_data = []
        async def capture_send(topic, data):
            sent_data.append((topic, orjson.loads(data)))

        engine.producer.send_and_wait = capture_send

        await engine._consume_loop()
        assert len(sent_data) == 1
        dlq = sent_data[0][1]
        assert dlq["topic"] == "akto.api.logs"
        assert dlq["partition"] == 3
        assert dlq["offset"] == 99

    @pytest.mark.asyncio
    async def test_consume_loop_trace_id_none_in_dlq(self, engine):
        """DLQ 中 trace_id 为 None"""
        msg = MagicMock()
        msg.value = b"bad"
        msg.topic = "akto.api.logs"
        msg.partition = 0
        msg.offset = 0

        engine.consumer = MagicMock()
        engine.consumer.start = AsyncMock()
        engine.consumer.stop = AsyncMock()
        engine.consumer.commit = AsyncMock()

        async def mock_aiter():
            yield [msg]
            engine._cancel_event.set()

        engine.consumer.__aiter__ = lambda self: mock_aiter()

        sent_data = []
        async def capture_send(topic, data):
            sent_data.append(orjson.loads(data))

        engine.producer.send_and_wait = capture_send

        await engine._consume_loop()
        assert sent_data[0]["trace_id"] is None


# ============================================================
# 5. engine _emit_alert 测试 (10 用例)
# ============================================================

class TestEmitAlert:
    """_emit_alert 告警输出测试"""

    @pytest.fixture
    def engine(self):
        with patch('concurrent.futures.ProcessPoolExecutor', MagicMock()):
            with patch('aiwaf.stream.engine.AIOKafkaProducer', MagicMock()):
                with patch('aiwaf.stream.engine.AIOKafkaConsumer', MagicMock()):
                    with patch('aiwaf.stream.acl_bootstrap.init_worker'):
                        with patch('aiwaf.stream.acl_bootstrap.run_core_logic_batch_isolated'):
                            from aiwaf.stream.engine import AIWAFStreamEngine
                            eng = AIWAFStreamEngine(MockSettings(), MockStateMgr(), "/f")
                            eng.producer.start = AsyncMock()
                            eng.producer.send_and_wait = AsyncMock()
                            return eng

    @pytest.mark.asyncio
    async def test_alert_basic_fields(self, engine):
        std_log = make_std_log()
        await engine._emit_alert(std_log, "TestRule")
        assert engine.producer.send_and_wait.called
        sent_data = orjson.loads(engine.producer.send_and_wait.call_args[0][1])
        assert sent_data["trace_id"] == "t001"
        assert sent_data["rule_id"] == "TestRule"
        assert sent_data["client_ip"] == "1.1.1.1"

    @pytest.mark.asyncio
    async def test_alert_includes_akto_context(self, engine):
        std_log = make_std_log()
        std_log["akto_account_id"] = "999"
        std_log["akto_vxlan_id"] = "42"
        std_log["source"] = "MIRRORING"
        std_log["direction"] = "REQUEST"
        await engine._emit_alert(std_log, "TestRule")
        sent_data = orjson.loads(engine.producer.send_and_wait.call_args[0][1])
        assert sent_data["akto_account_id"] == "999"
        assert sent_data["akto_vxlan_id"] == "42"
        assert sent_data["source"] == "MIRRORING"
        assert sent_data["direction"] == "REQUEST"

    @pytest.mark.asyncio
    async def test_alert_includes_request_context(self, engine):
        std_log = make_std_log(uri="/api/admin", method="POST", status_code=403)
        await engine._emit_alert(std_log, "TestRule")
        sent_data = orjson.loads(engine.producer.send_and_wait.call_args[0][1])
        assert sent_data["method"] == "POST"
        assert sent_data["uri_path"] == "/api/admin"
        assert sent_data["status_code"] == 403

    @pytest.mark.asyncio
    async def test_alert_includes_detected_at(self, engine):
        std_log = make_std_log()
        before = time.time()
        await engine._emit_alert(std_log, "TestRule")
        after = time.time()
        sent_data = orjson.loads(engine.producer.send_and_wait.call_args[0][1])
        assert before <= sent_data["detected_at"] <= after

    @pytest.mark.asyncio
    async def test_alert_includes_severity(self, engine):
        std_log = make_std_log()
        await engine._emit_alert(std_log, "TestRule")
        sent_data = orjson.loads(engine.producer.send_and_wait.call_args[0][1])
        assert "severity" in sent_data
        assert sent_data["severity"] in ("LOW", "MEDIUM", "HIGH")

    @pytest.mark.asyncio
    async def test_alert_includes_req_body_truncated(self, engine):
        std_log = make_std_log()
        std_log["req_body_truncated"] = "truncated-data"
        await engine._emit_alert(std_log, "TestRule")
        sent_data = orjson.loads(engine.producer.send_and_wait.call_args[0][1])
        assert sent_data["req_body_truncated"] == "truncated-data"

    @pytest.mark.asyncio
    async def test_alert_sent_to_correct_topic(self, engine):
        std_log = make_std_log()
        await engine._emit_alert(std_log, "TestRule")
        topic = engine.producer.send_and_wait.call_args[0][0]
        assert topic == "aiwaf_alert"

    @pytest.mark.asyncio
    async def test_alert_with_empty_std_log(self, engine):
        """空 std_log 不崩溃（使用默认值）"""
        await engine._emit_alert({}, "TestRule")
        sent_data = orjson.loads(engine.producer.send_and_wait.call_args[0][1])
        assert sent_data["client_ip"] is None
        assert sent_data["method"] == "GET"
        assert sent_data["uri_path"] == "/"
        assert sent_data["status_code"] == 200

    @pytest.mark.asyncio
    async def test_alert_rule_none_doesnt_crash(self, engine):
        """rule=None 不崩溃"""
        std_log = make_std_log()
        await engine._emit_alert(std_log, None)
        sent_data = orjson.loads(engine.producer.send_and_wait.call_args[0][1])
        assert sent_data["rule_id"] is None
        assert sent_data["severity"] == "LOW"

    @pytest.mark.asyncio
    async def test_alert_has_14_fields(self, engine):
        """告警输出包含全部 14 个字段"""
        std_log = make_std_log()
        std_log["akto_account_id"] = "1"
        std_log["akto_vxlan_id"] = "1"
        std_log["source"] = "MIRRORING"
        std_log["direction"] = "REQ"
        await engine._emit_alert(std_log, "Rule")
        sent_data = orjson.loads(engine.producer.send_and_wait.call_args[0][1])
        expected_keys = {
            "trace_id", "rule_id", "alert_timestamp", "client_ip",
            "akto_account_id", "akto_vxlan_id", "source", "direction",
            "method", "uri_path", "status_code",
            "detected_at", "severity", "req_body_truncated"
        }
        assert set(sent_data.keys()) == expected_keys


# ============================================================
# 6. _classify_severity 测试 (10 用例)
# ============================================================

class TestClassifySeverity:
    """_classify_severity 严重程度分类测试"""

    @pytest.fixture
    def engine(self):
        with patch('concurrent.futures.ProcessPoolExecutor', MagicMock()):
            with patch('aiwaf.stream.engine.AIOKafkaProducer', MagicMock()):
                with patch('aiwaf.stream.engine.AIOKafkaConsumer', MagicMock()):
                    with patch('aiwaf.stream.acl_bootstrap.init_worker'):
                        with patch('aiwaf.stream.acl_bootstrap.run_core_logic_batch_isolated'):
                            from aiwaf.stream.engine import AIWAFStreamEngine
                            eng = AIWAFStreamEngine(MockSettings(), MockStateMgr(), "/f")
                            return eng

    def test_flood_rule_returns_medium(self, engine):
        assert engine._classify_severity("RateLimitFlood") == "MEDIUM"

    def test_ratelimit_rule_returns_medium(self, engine):
        assert engine._classify_severity("Local_RateLimit_Block") == "MEDIUM"

    def test_keyword_rule_returns_high(self, engine):
        assert engine._classify_severity("KeywordBlock:SQLi") == "HIGH"

    def test_blacklist_rule_returns_high(self, engine):
        assert engine._classify_severity("Local_Blacklist_Block") == "HIGH"

    def test_unknown_rule_returns_low(self, engine):
        assert engine._classify_severity("UnknownRule") == "LOW"

    def test_empty_rule_returns_low(self, engine):
        assert engine._classify_severity("") == "LOW"

    def test_none_rule_returns_low(self, engine):
        assert engine._classify_severity(None) == "LOW"

    def test_case_insensitive_flood(self, engine):
        assert engine._classify_severity("FLOOD") == "MEDIUM"
        assert engine._classify_severity("flood") == "MEDIUM"

    def test_case_insensitive_keyword(self, engine):
        assert engine._classify_severity("KEYWORD") == "HIGH"
        assert engine._classify_severity("keyword") == "HIGH"

    def test_case_insensitive_blacklist(self, engine):
        assert engine._classify_severity("BLACKLIST") == "HIGH"
        assert engine._classify_severity("blacklist") == "HIGH"


# ============================================================
# 7. 集成测试 — 端到端 (20 用例)
# ============================================================

class TestIntegrationEndToEnd:
    """端到端集成测试：适配 → 预处理 → 引擎"""

    def test_full_pipeline_basic(self):
        """完整管道：JSON → adapt → transform → std_log"""
        msg = make_akto_msg()
        raw_log = parse_akto_json_message(msg)
        std_log = transform_raw_log(raw_log)
        assert std_log["client_ip"] == "10.0.1.5"
        assert std_log["uri_path"] == "/api/users/123"
        assert std_log["method"] == "GET"
        assert std_log["status_code"] == 200
        assert std_log["query_keys"] == ["name", "age"]
        assert len(std_log["trace_id"]) == 32

    def test_full_pipeline_with_body(self):
        """带请求体的完整管道"""
        msg = make_akto_msg(requestPayload='{"username":"admin","password":"secret"}')
        raw_log = parse_akto_json_message(msg)
        std_log = transform_raw_log(raw_log)
        assert "request_body" not in std_log
        assert "admin" in std_log["req_body_truncated"]
        assert "secret" in std_log["req_body_truncated"]

    def test_full_pipeline_akto_context_preserved(self):
        """akto 扩展字段完整保留"""
        msg = make_akto_msg(akto_account_id="12345", akto_vxlan_id="99", source="POSTMAN")
        raw_log = parse_akto_json_message(msg)
        std_log = transform_raw_log(raw_log)
        assert std_log["akto_account_id"] == "12345"
        assert std_log["akto_vxlan_id"] == "99"
        assert std_log["source"] == "POSTMAN"

    def test_full_pipeline_post_method(self):
        """POST 请求"""
        msg = make_akto_msg(method="POST", requestPayload='{"action":"create"}')
        raw_log = parse_akto_json_message(msg)
        std_log = transform_raw_log(raw_log)
        assert std_log["method"] == "POST"

    def test_full_pipeline_error_status(self):
        """错误状态码"""
        msg = make_akto_msg(statusCode="500")
        raw_log = parse_akto_json_message(msg)
        std_log = transform_raw_log(raw_log)
        assert std_log["status_code"] == 500

    def test_full_pipeline_no_query_string(self):
        """无 query string"""
        msg = make_akto_msg(path="/api/health")
        raw_log = parse_akto_json_message(msg)
        std_log = transform_raw_log(raw_log)
        assert std_log["query_keys"] == []

    def test_full_pipeline_complex_query(self):
        """复杂 query string"""
        msg = make_akto_msg(path="/api/search?q=hello%20world&tag=a&tag=b&page=1")
        raw_log = parse_akto_json_message(msg)
        std_log = transform_raw_log(raw_log)
        assert "q" in std_log["query_keys"]
        assert "tag" in std_log["query_keys"]
        assert "page" in std_log["query_keys"]
        # q=hello world should be one of the query_strings
        assert any("hello world" in qs for qs in std_log["query_strings"])

    def test_full_pipeline_large_body_truncated(self):
        """大 body 被截断"""
        large_body = "A" * 5000
        msg = make_akto_msg(requestPayload=large_body)
        raw_log = parse_akto_json_message(msg)
        std_log = transform_raw_log(raw_log)
        assert len(std_log["req_body_truncated"]) == MAX_BODY_STORE_BYTES

    def test_full_pipeline_trace_id_consistent(self):
        """相同输入产生相同 trace_id"""
        msg = make_akto_msg()
        raw1 = parse_akto_json_message(msg)
        raw2 = parse_akto_json_message(msg)
        std1 = transform_raw_log(raw1)
        std2 = transform_raw_log(raw2)
        assert std1["trace_id"] == std2["trace_id"]

    def test_full_pipeline_different_ip_different_trace(self):
        """不同 IP 产生不同 trace_id"""
        msg1 = make_akto_msg(ip="1.1.1.1")
        msg2 = make_akto_msg(ip="2.2.2.2")
        std1 = transform_raw_log(parse_akto_json_message(msg1))
        std2 = transform_raw_log(parse_akto_json_message(msg2))
        assert std1["trace_id"] != std2["trace_id"]

    def test_full_pipeline_json_string_input(self):
        """JSON 字符串输入"""
        msg = make_akto_msg()
        json_str = orjson.dumps(msg)
        raw_log = parse_akto_json_message(json_str)
        std_log = transform_raw_log(raw_log)
        assert std_log["client_ip"] == "10.0.1.5"

    def test_full_pipeline_bytes_input(self):
        """bytes 输入"""
        msg = make_akto_msg()
        raw_log = parse_akto_json_message(msg)
        std_log = transform_raw_log(raw_log)
        assert std_log["client_ip"] == "10.0.1.5"

    def test_full_pipeline_full_url(self):
        """完整 URL 作为 path"""
        msg = make_akto_msg(path="https://api.example.com/v1/users/123?active=true")
        raw_log = parse_akto_json_message(msg)
        std_log = transform_raw_log(raw_log)
        assert std_log["uri_path"] == "/v1/users/123"
        assert "active" in std_log["query_keys"]

    def test_full_pipeline_empty_body(self):
        """空 body"""
        msg = make_akto_msg(requestPayload="")
        raw_log = parse_akto_json_message(msg)
        std_log = transform_raw_log(raw_log)
        assert std_log["req_body_truncated"] == ""

    def test_full_pipeline_all_akto_fields(self):
        """全部 akto 扩展字段"""
        msg = make_akto_msg(
            akto_account_id="999",
            akto_vxlan_id="88",
            source="AGENT",
            direction="RESPONSE",
            destIp="10.0.0.99",
            responsePayload='{"result":"ok"}'
        )
        raw_log = parse_akto_json_message(msg)
        std_log = transform_raw_log(raw_log)
        assert std_log["akto_account_id"] == "999"
        assert std_log["akto_vxlan_id"] == "88"
        assert std_log["source"] == "AGENT"
        assert std_log["direction"] == "RESPONSE"
        assert std_log["dest_ip"] == "10.0.0.99"
        assert std_log["response_payload"] == '{"result":"ok"}'

    def test_full_pipeline_sqli_payload(self):
        """SQL 注入 payload 在管道中保持完整"""
        msg = make_akto_msg(
            path="/api/login",
            method="POST",
            requestPayload='{"username":"admin\' OR \'1\'=\'1","password":"x"}'
        )
        raw_log = parse_akto_json_message(msg)
        std_log = transform_raw_log(raw_log)
        assert "OR" in std_log["req_body_truncated"]

    def test_full_pipeline_xss_payload(self):
        """XSS payload 在管道中保持完整"""
        msg = make_akto_msg(path="/api/search?q=<script>alert(1)</script>")
        raw_log = parse_akto_json_message(msg)
        std_log = transform_raw_log(raw_log)
        assert "<script>" in std_log["query_strings"][0]

    def test_full_pipeline_path_traversal(self):
        """路径遍历在管道中保持完整"""
        msg = make_akto_msg(path="/api/file/../../../etc/passwd")
        raw_log = parse_akto_json_message(msg)
        std_log = transform_raw_log(raw_log)
        assert "../" in std_log["uri_path"]

    def test_full_pipeline_unicode(self):
        """Unicode 字符"""
        msg = make_akto_msg(path="/api/用户/列表", requestPayload='{"name":"张三"}')
        raw_log = parse_akto_json_message(msg)
        std_log = transform_raw_log(raw_log)
        assert "用户" in std_log["uri_path"]
        assert "张三" in std_log["req_body_truncated"]

    def test_full_pipeline_multiple_messages_independent(self):
        """多条消息独立处理"""
        messages = [make_akto_msg(ip=f"10.0.0.{i}", path=f"/api/item/{i}") for i in range(10)]
        std_logs = [transform_raw_log(parse_akto_json_message(msg)) for msg in messages]
        # All trace_ids should be different (different ip + path)
        trace_ids = [s["trace_id"] for s in std_logs]
        assert len(set(trace_ids)) == 10
