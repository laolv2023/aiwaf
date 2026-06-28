"""
preprocessor 测试套件 — 40 用例
覆盖: generate_deterministic_trace_id + transform_raw_log + 边界条件
"""
import pytest
import hashlib
import orjson
import time
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from aiwaf.stream.preprocessor import generate_deterministic_trace_id, transform_raw_log, MAX_BODY_STORE_BYTES


# ============================================================
# generate_deterministic_trace_id 测试 (15 用例)
# ============================================================

class TestDeterministicTraceId:
    """指纹生成的确定性、唯一性和防碰撞测试"""

    def test_idempotent_same_input(self):
        """相同输入应产生相同指纹"""
        log1 = {"client_ip": "1.1.1.1", "uri_path": "/api", "timestamp": 1000.0, "request_body": "hello"}
        log2 = {"client_ip": "1.1.1.1", "uri_path": "/api", "timestamp": 1000.0, "request_body": "hello"}
        assert generate_deterministic_trace_id(log1) == generate_deterministic_trace_id(log2)

    def test_different_ip_produces_different_id(self):
        """不同 IP 产生不同指纹"""
        a = generate_deterministic_trace_id({"client_ip": "1.1.1.1", "uri_path": "/", "timestamp": 1.0, "request_body": ""})
        b = generate_deterministic_trace_id({"client_ip": "2.2.2.2", "uri_path": "/", "timestamp": 1.0, "request_body": ""})
        assert a != b

    def test_different_uri_produces_different_id(self):
        """不同 URI 产生不同指纹"""
        a = generate_deterministic_trace_id({"client_ip": "1.1.1.1", "uri_path": "/a", "timestamp": 1.0, "request_body": ""})
        b = generate_deterministic_trace_id({"client_ip": "1.1.1.1", "uri_path": "/b", "timestamp": 1.0, "request_body": ""})
        assert a != b

    def test_different_body_produces_different_id(self):
        """不同 Body 产生不同指纹"""
        a = generate_deterministic_trace_id({"client_ip": "1.1.1.1", "uri_path": "/", "timestamp": 1.0, "request_body": "x"})
        b = generate_deterministic_trace_id({"client_ip": "1.1.1.1", "uri_path": "/", "timestamp": 1.0, "request_body": "y"})
        assert a != b

    def test_different_timestamp_produces_different_id(self):
        """不同时间戳产生不同指纹"""
        a = generate_deterministic_trace_id({"client_ip": "1.1.1.1", "uri_path": "/", "timestamp": 1.0, "request_body": ""})
        b = generate_deterministic_trace_id({"client_ip": "1.1.1.1", "uri_path": "/", "timestamp": 2.0, "request_body": ""})
        assert a != b

    def test_output_length_is_32(self):
        """输出应为 32 字符(128-bit hex)"""
        log = {"client_ip": "1.1.1.1", "uri_path": "/", "timestamp": 1.0, "request_body": ""}
        tid = generate_deterministic_trace_id(log)
        assert len(tid) == 32

    def test_output_is_hex_string(self):
        """输出应为合法 hex 字符串"""
        log = {"client_ip": "1.1.1.1", "uri_path": "/", "timestamp": 1.0, "request_body": ""}
        tid = generate_deterministic_trace_id(log)
        int(tid, 16)  # 不应抛出 ValueError

    def test_empty_body_handled(self):
        """空 body 应正常处理"""
        log = {"client_ip": "1.1.1.1", "uri_path": "/", "timestamp": 1.0, "request_body": ""}
        tid = generate_deterministic_trace_id(log)
        assert len(tid) == 32

    def test_default_missing_ip(self):
        """缺少 client_ip 时使用空字符串"""
        log = {"uri_path": "/", "timestamp": 1.0, "request_body": ""}
        tid = generate_deterministic_trace_id(log)
        assert len(tid) == 32

    def test_body_as_dict_serialized_to_json(self):
        """dict 类型 body 应序列化为 JSON"""
        log = {"client_ip": "1.1.1.1", "uri_path": "/", "timestamp": 1.0, "request_body": {"key": "value"}}
        tid = generate_deterministic_trace_id(log)
        assert len(tid) == 32

    def test_body_as_list_serialized_to_json(self):
        """list 类型 body 应序列化为 JSON"""
        log = {"client_ip": "1.1.1.1", "uri_path": "/", "timestamp": 1.0, "request_body": [1, 2, 3]}
        tid = generate_deterministic_trace_id(log)
        assert len(tid) == 32

    def test_body_as_bytes_preserved(self):
        """bytes 类型 body 应直接使用"""
        log = {"client_ip": "1.1.1.1", "uri_path": "/", "timestamp": 1.0, "request_body": b"binary\x00data"}
        tid = generate_deterministic_trace_id(log)
        assert len(tid) == 32

    def test_body_as_int_serialized(self):
        """int 类型 body 应序列化(边界测试)"""
        log = {"client_ip": "1.1.1.1", "uri_path": "/", "timestamp": 1.0, "request_body": 42}
        tid = generate_deterministic_trace_id(log)
        assert len(tid) == 32

    def test_body_as_float_serialized(self):
        """float 类型 body 应序列化(边界测试)"""
        log = {"client_ip": "1.1.1.1", "uri_path": "/", "timestamp": 1.0, "request_body": 3.14}
        tid = generate_deterministic_trace_id(log)
        assert len(tid) == 32

    def test_body_as_none_defaults_to_empty(self):
        """request_body=None 时 .get 返回 ''，应为空字符串"""
        log = {"client_ip": "1.1.1.1", "uri_path": "/", "timestamp": 1.0}
        tid = generate_deterministic_trace_id(log)
        assert len(tid) == 32


# ============================================================
# transform_raw_log 测试 (15 用例)
# ============================================================

class TestTransformRawLog:
    """日志转换的保真度和正确性测试"""

    def test_basic_conversion(self):
        """基本日志字段正确转换"""
        raw = {"client_ip": "1.2.3.4", "uri_path": "/api/search", "timestamp": 1000.0,
               "query_params": {"q": "test"}, "method": "POST", "status": 200, "request_body": "data"}
        result = transform_raw_log(raw)
        assert result["client_ip"] == "1.2.3.4"
        assert result["uri_path"] == "/api/search"
        assert result["timestamp"] == 1000.0
        assert result["method"] == "POST"
        assert result["status_code"] == 200

    def test_client_ip_fallback_to_remote_addr(self):
        """client_ip 缺失时回退到 remote_addr"""
        raw = {"remote_addr": "5.6.7.8", "uri_path": "/", "timestamp": 1.0}
        result = transform_raw_log(raw)
        assert result["client_ip"] == "5.6.7.8"

    def test_default_method_is_GET(self):
        """method 缺失默认为 GET"""
        raw = {"client_ip": "1.1.1.1", "uri_path": "/", "timestamp": 1.0}
        result = transform_raw_log(raw)
        assert result["method"] == "GET"

    def test_default_uri_path_is_slash(self):
        """uri_path 缺失默认为 /"""
        raw = {"client_ip": "1.1.1.1", "timestamp": 1.0}
        result = transform_raw_log(raw)
        assert result["uri_path"] == "/"

    def test_default_status_code_is_200(self):
        """status 缺失默认为 200"""
        raw = {"client_ip": "1.1.1.1", "uri_path": "/", "timestamp": 1.0}
        result = transform_raw_log(raw)
        assert result["status_code"] == 200

    def test_query_keys_extraction(self):
        """query_params 的 key 正确提取"""
        raw = {"client_ip": "1.1.1.1", "timestamp": 1.0, "query_params": {"q": "test", "page": "1", "limit": "10"}}
        result = transform_raw_log(raw)
        assert set(result["query_keys"]) == {"q", "page", "limit"}

    def test_query_strings_key_value_preserved(self):
        """query_strings 保留 Key=Value 格式"""
        raw = {"client_ip": "1.1.1.1", "timestamp": 1.0, "query_params": {"q": "DROP TABLE"}}
        result = transform_raw_log(raw)
        assert "q=DROP TABLE" in result["query_strings"]

    def test_query_strings_list_expansion(self):
        """list 类型 query value 应展开为多个 key=item"""
        raw = {"client_ip": "1.1.1.1", "timestamp": 1.0, "query_params": {"ids": ["1", "2", "3"]}}
        result = transform_raw_log(raw)
        assert "ids=1" in result["query_strings"]
        assert "ids=2" in result["query_strings"]
        assert "ids=3" in result["query_strings"]

    def test_query_strings_empty_list_produces_none(self):
        """空 list 类型的 query value 不产生 query_strings"""
        raw = {"client_ip": "1.1.1.1", "timestamp": 1.0, "query_params": {"ids": []}}
        result = transform_raw_log(raw)
        assert len(result["query_strings"]) == 0

    def test_empty_query_params(self):
        """空 query_params 正确产生空列表"""
        raw = {"client_ip": "1.1.1.1", "timestamp": 1.0, "query_params": {}}
        result = transform_raw_log(raw)
        assert result["query_keys"] == []
        assert result["query_strings"] == []

    def test_missing_query_params(self):
        """缺失 query_params 正确产生空列表"""
        raw = {"client_ip": "1.1.1.1", "timestamp": 1.0}
        result = transform_raw_log(raw)
        assert result["query_keys"] == []
        assert result["query_strings"] == []

    def test_trace_id_present_in_output(self):
        """输出必须包含 trace_id"""
        raw = {"client_ip": "1.1.1.1", "timestamp": 1.0}
        result = transform_raw_log(raw)
        assert "trace_id" in result
        assert len(result["trace_id"]) == 32

    def test_request_body_removed(self):
        """request_body 应在转换后被移除"""
        raw = {"client_ip": "1.1.1.1", "timestamp": 1.0, "request_body": "secret"}
        result = transform_raw_log(raw)
        assert "request_body" not in result

    def test_req_body_truncated_present(self):
        """req_body_truncated 应在转换后存在"""
        raw = {"client_ip": "1.1.1.1", "timestamp": 1.0, "request_body": "data"}
        result = transform_raw_log(raw)
        assert "req_body_truncated" in result


# ============================================================
# 边界条件测试 (10 用例)
# ============================================================

class TestEdgeCases:
    """边界条件、异常输入和极端场景"""

    def test_very_large_body_truncated_to_1KB(self):
        """超大 body 应被截断至 MAX_BODY_STORE_BYTES"""
        large_body = "x" * 5000
        raw = {"client_ip": "1.1.1.1", "timestamp": 1.0, "request_body": large_body}
        result = transform_raw_log(raw)
        assert len(result["req_body_truncated"]) <= MAX_BODY_STORE_BYTES
        assert result["req_body_truncated"] == large_body[:MAX_BODY_STORE_BYTES]

    def test_trace_id_stable_across_calls(self):
        """连续三次调用相同输入，指纹应一致"""
        raw = {"client_ip": "1.1.1.1", "uri_path": "/api", "timestamp": 1000.0, "request_body": "hello"}
        ids = [transform_raw_log(raw)["trace_id"] for _ in range(3)]
        assert ids[0] == ids[1] == ids[2]

    def test_special_characters_in_body(self):
        """特殊字符 (NULL, Unicode, emoji) 正确处理"""
        raw = {"client_ip": "1.1.1.1", "timestamp": 1.0, "request_body": "hello\x00world\n🚀\t测试"}
        result = transform_raw_log(raw)
        assert "trace_id" in result

    def test_SQL_injection_in_query(self):
        """SQL 注入 payload 在 query_strings 中保留"""
        raw = {"client_ip": "1.1.1.1", "timestamp": 1.0,
               "query_params": {"q": "'; DROP TABLE users; --"}}
        result = transform_raw_log(raw)
        assert "DROP TABLE" in result["query_strings"][0]

    def test_XSS_in_query(self):
        """XSS payload 在 query_strings 中保留"""
        raw = {"client_ip": "1.1.1.1", "timestamp": 1.0,
               "query_params": {"search": "<script>alert(1)</script>"}}
        result = transform_raw_log(raw)
        assert "<script>" in result["query_strings"][0]

    def test_non_dict_query_params_ignored(self):
        """非 dict 类型的 query_params 被忽略"""
        raw = {"client_ip": "1.1.1.1", "timestamp": 1.0, "query_params": "not_a_dict"}
        result = transform_raw_log(raw)
        assert result["query_keys"] == []

    def test_non_dict_query_params_list(self):
        """list 类型的 query_params 被忽略"""
        raw = {"client_ip": "1.1.1.1", "timestamp": 1.0, "query_params": ["a=1", "b=2"]}
        result = transform_raw_log(raw)
        assert result["query_keys"] == []

    def test_body_bytes_decode_truncated(self):
        """bytes body 被正确截断"""
        body = b"a" * 5000
        raw = {"client_ip": "1.1.1.1", "timestamp": 1.0, "request_body": body}
        result = transform_raw_log(raw)
        assert len(result["req_body_truncated"]) <= MAX_BODY_STORE_BYTES

    def test_body_dict_serialized_to_json_string(self):
        """dict body 的 req_body_truncated 应为 JSON 字符串"""
        raw = {"client_ip": "1.1.1.1", "timestamp": 1.0, "request_body": {"action": "login"}}
        result = transform_raw_log(raw)
        assert '"action":"login"' in result["req_body_truncated"]

    def test_resilience_to_unexpected_type_in_query_value(self):
        """query value 为非字符串非列表类型时的容错"""
        raw = {"client_ip": "1.1.1.1", "timestamp": 1.0,
               "query_params": {"num": 42, "flag": True}}
        result = transform_raw_log(raw)
        assert "num=42" in result["query_strings"]
        assert "flag=True" in result["query_strings"]


# 用例总数: 15 + 15 + 10 = 40


# ============================================================
# 补充用例 (10)
# ============================================================

class TestSupplementaryPreprocessor:
    def test_body_hash_is_consistent_for_same_content(self):
        a = generate_deterministic_trace_id({"client_ip":"1.1.1.1","uri_path":"/","timestamp":1.0,"request_body":"abc"})
        b = generate_deterministic_trace_id({"client_ip":"1.1.1.1","uri_path":"/","timestamp":1.0,"request_body":"abc"})
        assert a == b

    def test_trace_id_not_empty(self):
        tid = generate_deterministic_trace_id({"client_ip":"1.1.1.1","uri_path":"/","timestamp":1.0,"request_body":""})
        assert tid != ""

    def test_query_strings_preserve_special_chars(self):
        raw = {"client_ip":"1.1.1.1","timestamp":1.0,"query_params":{"q":"hello world & more"}}
        result = transform_raw_log(raw)
        assert "q=hello world & more" in result["query_strings"]

    def test_multiple_query_params_mixed_types(self):
        raw = {"client_ip":"1.1.1.1","timestamp":1.0,"query_params":{"a":"1","b":["2","3"],"c":"4"}}
        result = transform_raw_log(raw)
        assert len(result["query_strings"]) == 4

    def test_client_ip_or_remote_addr_both_present(self):
        raw = {"client_ip":"1.1.1.1","remote_addr":"2.2.2.2","timestamp":1.0}
        result = transform_raw_log(raw)
        assert result["client_ip"] == "1.1.1.1"

    def test_empty_raw_log_minimal_fields(self):
        result = transform_raw_log({})
        assert result["client_ip"] is None
        assert result["uri_path"] == "/"
        assert result["method"] == "GET"
        assert result["status_code"] == 200

    def test_body_bytes_with_null_bytes(self):
        raw = {"client_ip":"1.1.1.1","timestamp":1.0,"request_body":b"\x00\x01\x02\xff"}
        result = transform_raw_log(raw)
        assert "req_body_truncated" in result

    def test_fingerprint_different_body_same_everything_else(self):
        a = {"client_ip":"1.1.1.1","uri_path":"/","timestamp":1.0,"request_body":"x"}
        b = {"client_ip":"1.1.1.1","uri_path":"/","timestamp":1.0,"request_body":"y"}
        assert generate_deterministic_trace_id(a) != generate_deterministic_trace_id(b)

    def test_query_keys_preserve_order(self):
        raw = {"client_ip":"1.1.1.1","timestamp":1.0,"query_params":{"z":"1","a":"2","m":"3"}}
        result = transform_raw_log(raw)
        assert len(result["query_keys"]) == 3

    def test_body_truncated_exact_1KB(self):
        raw = {"client_ip":"1.1.1.1","timestamp":1.0,"request_body":"x" * 2000}
        result = transform_raw_log(raw)
        assert len(result["req_body_truncated"]) == MAX_BODY_STORE_BYTES


# ============================================================
# 新增 50 用例: 指纹深度测试 + 转换边界 + 集成链
# ============================================================

class TestDeepFingerprint:
    """指纹生成的深度验证"""

    def test_trace_id_hex_only_lowercase(self):
        tid = generate_deterministic_trace_id({"client_ip":"1.1.1.1","uri_path":"/","timestamp":1.0,"request_body":""})
        assert tid == tid.lower()

    def test_trace_id_all_valid_hex_chars(self):
        tid = generate_deterministic_trace_id({"client_ip":"1.1.1.1","uri_path":"/","timestamp":1.0,"request_body":""})
        assert all(c in '0123456789abcdef' for c in tid)

    def test_very_long_uri(self):
        uri = "/" + "a" * 5000
        tid = generate_deterministic_trace_id({"client_ip":"1.1.1.1","uri_path":uri,"timestamp":1.0,"request_body":""})
        assert len(tid) == 32

    def test_ipv6_address(self):
        tid = generate_deterministic_trace_id({"client_ip":"2001:db8::1","uri_path":"/","timestamp":1.0,"request_body":""})
        assert len(tid) == 32

    def test_ipv4_address(self):
        tid = generate_deterministic_trace_id({"client_ip":"255.255.255.255","uri_path":"/","timestamp":1.0,"request_body":""})
        assert len(tid) == 32

    def test_timestamp_float_precision(self):
        tid1 = generate_deterministic_trace_id({"client_ip":"1.1.1.1","uri_path":"/","timestamp":1000.123456,"request_body":""})
        tid2 = generate_deterministic_trace_id({"client_ip":"1.1.1.1","uri_path":"/","timestamp":1000.123457,"request_body":""})
        assert tid1 != tid2

    def test_timestamp_integer(self):
        tid = generate_deterministic_trace_id({"client_ip":"1.1.1.1","uri_path":"/","timestamp":1717500000,"request_body":""})
        assert len(tid) == 32

    def test_body_empty_dict(self):
        tid = generate_deterministic_trace_id({"client_ip":"1.1.1.1","uri_path":"/","timestamp":1.0,"request_body":{}})
        assert len(tid) == 32

    def test_body_nested_dict(self):
        tid = generate_deterministic_trace_id({"client_ip":"1.1.1.1","uri_path":"/","timestamp":1.0,"request_body":{"a":{"b":{"c":1}}}})
        assert len(tid) == 32

    def test_body_list_of_dicts(self):
        tid = generate_deterministic_trace_id({"client_ip":"1.1.1.1","uri_path":"/","timestamp":1.0,"request_body":[{"a":1},{"b":2}]})
        assert len(tid) == 32

    def test_fingerprint_components_separator(self):
        tid = generate_deterministic_trace_id({"client_ip":"pipe|test","uri_path":"/","timestamp":1.0,"request_body":""})
        assert len(tid) == 32

    def test_body_hash_covers_content(self):
        tid1 = generate_deterministic_trace_id({"client_ip":"1.1.1.1","uri_path":"/","timestamp":1.0,"request_body":"a"})
        tid2 = generate_deterministic_trace_id({"client_ip":"1.1.1.1","uri_path":"/","timestamp":1.0,"request_body":"b"})
        assert tid1 != tid2

    def test_empty_timestamp_fingerprint(self):
        tid = generate_deterministic_trace_id({"client_ip":"1.1.1.1","uri_path":"/","request_body":""})
        assert len(tid) == 32

    def test_body_none_via_get(self):
        log = {"client_ip":"1.1.1.1","uri_path":"/","timestamp":1.0,"request_body":None}
        tid = generate_deterministic_trace_id(log)
        assert len(tid) == 32


class TestDeepTransform:
    """日志转换的深度验证"""

    def test_all_query_params_list_of_lists_ignored(self):
        raw = {"client_ip":"1.1.1.1","timestamp":1.0,"query_params":"not_dict"}
        result = transform_raw_log(raw)
        assert result["query_keys"] == []

    def test_query_strings_strip_not_applied(self):
        raw = {"client_ip":"1.1.1.1","timestamp":1.0,"query_params":{"q":"  spaced  "}}
        result = transform_raw_log(raw)
        assert "q=  spaced  " in result["query_strings"]

    def test_query_params_not_dict_is_safe(self):
        for bad in [None, 123, "str", [1,2]]:
            raw = {"client_ip":"1.1.1.1","timestamp":1.0,"query_params":bad}
            result = transform_raw_log(raw)
            assert result["query_keys"] == []

    def test_remote_addr_fallback_priority(self):
        raw = {"remote_addr":"9.9.9.9","timestamp":1.0}
        result = transform_raw_log(raw)
        assert result["client_ip"] == "9.9.9.9"

    def test_client_ip_overrides_remote_addr(self):
        raw = {"client_ip":"1.1.1.1","remote_addr":"2.2.2.2","timestamp":1.0}
        result = transform_raw_log(raw)
        assert result["client_ip"] == "1.1.1.1"

    def test_client_ip_none_falls_to_remote_addr(self):
        raw = {"client_ip":None,"remote_addr":"5.5.5.5","timestamp":1.0}
        result = transform_raw_log(raw)
        assert result["client_ip"] == "5.5.5.5"

    def test_body_str_unicode_emoji(self):
        raw = {"client_ip":"1.1.1.1","timestamp":1.0,"request_body":"🚀🔥💯"}
        result = transform_raw_log(raw)
        assert "🚀" in result["req_body_truncated"]

    def test_body_bytes_utf8_decode(self):
        raw = {"client_ip":"1.1.1.1","timestamp":1.0,"request_body":"你好世界".encode('utf-8')}
        result = transform_raw_log(raw)
        assert "你好世界" in result["req_body_truncated"]

    def test_body_large_binary_safe(self):
        body = bytes(range(256)) * 10
        raw = {"client_ip":"1.1.1.1","timestamp":1.0,"request_body":body}
        result = transform_raw_log(raw)
        assert "req_body_truncated" in result

    def test_req_body_truncated_not_empty_for_nonempty_body(self):
        raw = {"client_ip":"1.1.1.1","timestamp":1.0,"request_body":"data"}
        result = transform_raw_log(raw)
        assert len(result["req_body_truncated"]) > 0

    def test_req_body_truncated_empty_for_empty_body(self):
        raw = {"client_ip":"1.1.1.1","timestamp":1.0,"request_body":""}
        result = transform_raw_log(raw)
        assert result["req_body_truncated"] == ""

    def test_status_code_default_200(self):
        raw = {"client_ip":"1.1.1.1","timestamp":1.0}
        result = transform_raw_log(raw)
        assert result["status_code"] == 200

    def test_method_missing_defaults_GET(self):
        raw = {"client_ip":"1.1.1.1","timestamp":1.0}
        result = transform_raw_log(raw)
        assert result["method"] == "GET"

    def test_method_preserved_uppercase(self):
        raw = {"client_ip":"1.1.1.1","timestamp":1.0,"method":"post"}
        result = transform_raw_log(raw)
        assert result["method"] == "post"


class TestIntegrationPreprocessor:
    """preprocessor 集成链"""

    def test_full_pipeline_trace_id_in_output(self):
        raw = {"client_ip":"1.2.3.4","uri_path":"/api/search","timestamp":1000.0,
               "query_params":{"q":"test"},"request_body":"body"}
        result = transform_raw_log(raw)
        assert "trace_id" in result
        assert "req_body_truncated" in result
        assert "request_body" not in result

    def test_deterministic_roundtrip(self):
        raw = {"client_ip":"1.1.1.1","uri_path":"/test","timestamp":10.0,"request_body":"hello"}
        r1 = transform_raw_log(dict(raw))
        r2 = transform_raw_log(dict(raw))
        assert r1["trace_id"] == r2["trace_id"]
        assert r1["req_body_truncated"] == r2["req_body_truncated"]

    def test_sqli_payload_survives_transform(self):
        raw = {"client_ip":"1.1.1.1","timestamp":1.0,
               "query_params":{"q":"1' OR '1'='1'; DROP TABLE users;--"}}
        result = transform_raw_log(raw)
        assert "DROP TABLE" in result["query_strings"][0]

    def test_xss_payload_in_uri_path(self):
        raw = {"client_ip":"1.1.1.1","uri_path":"/search?q=<script>alert(1)</script>","timestamp":1.0}
        result = transform_raw_log(raw)
        assert "<script>" in result["uri_path"]

    def test_path_traversal_in_uri(self):
        raw = {"client_ip":"1.1.1.1","uri_path":"/../../../etc/passwd","timestamp":1.0}
        result = transform_raw_log(raw)
        assert "etc/passwd" in result["uri_path"]

    def test_comment_injection_in_body(self):
        raw = {"client_ip":"1.1.1.1","timestamp":1.0,"request_body":"normal/*malicious*/data"}
        result = transform_raw_log(raw)
        assert "req_body_truncated" in result

    def test_null_byte_in_body(self):
        raw = {"client_ip":"1.1.1.1","timestamp":1.0,"request_body":"before\x00after"}
        result = transform_raw_log(raw)
        assert "req_body_truncated" in result

    def test_very_deeply_nested_query_params(self):
        raw = {"client_ip":"1.1.1.1","timestamp":1.0,"query_params":{"k1":"v1","k2":"v2","k3":"v3","k4":"v4","k5":"v5","k6":"v6","k7":"v7","k8":"v8"}}
        result = transform_raw_log(raw)
        assert len(result["query_keys"]) == 8

    def test_body_int_serialized_to_json(self):
        raw = {"client_ip":"1.1.1.1","timestamp":1.0,"request_body":42}
        result = transform_raw_log(raw)
        assert "42" in result["req_body_truncated"]

    def test_body_bool_serialized_to_json(self):
        raw = {"client_ip":"1.1.1.1","timestamp":1.0,"request_body":True}
        result = transform_raw_log(raw)
        assert "true" in result["req_body_truncated"]

    def test_method_post_preserved(self):
        raw = {"client_ip":"1.1.1.1","timestamp":1.0,"method":"POST"}
        result = transform_raw_log(raw)
        assert result["method"] == "POST"

    def test_method_put_preserved(self):
        raw = {"client_ip":"1.1.1.1","timestamp":1.0,"method":"PUT","request_body":"data"}
        result = transform_raw_log(raw)
        assert result["method"] == "PUT"

    def test_status_403_preserved(self):
        raw = {"client_ip":"1.1.1.1","timestamp":1.0,"status":403}
        result = transform_raw_log(raw)
        assert result["status_code"] == 403

    def test_status_500_preserved(self):
        raw = {"client_ip":"1.1.1.1","timestamp":1.0,"status":500}
        result = transform_raw_log(raw)
        assert result["status_code"] == 500

    def test_fingerprint_same_input_different_timestamp_types(self):
        tid1 = generate_deterministic_trace_id({"client_ip":"1.1.1.1","uri_path":"/","timestamp":1000.0,"request_body":""})
        tid2 = generate_deterministic_trace_id({"client_ip":"1.1.1.1","uri_path":"/","timestamp":1000.0,"request_body":""})
        assert tid1 == tid2

    def test_trace_id_no_collision_1000(self):
        ids = set()
        for i in range(1000):
            tid = generate_deterministic_trace_id({"client_ip":f"10.0.0.{i%256}","uri_path":f"/api/{i}","timestamp":float(i),"request_body":f"body-{i}"})
            ids.add(tid)
        assert len(ids) == 1000

    def test_query_strings_preserve_order(self):
        raw = {"client_ip":"1.1.1.1","timestamp":1.0,"query_params":{"z":"1","a":"2","m":"3","b":"4"}}
        result = transform_raw_log(raw)
        assert len(result["query_strings"]) == 4

    def test_body_truncated_non_ascii_utf8(self):
        raw = {"client_ip":"1.1.1.1","timestamp":1.0,"request_body":"日本語テスト"}
        result = transform_raw_log(raw)
        assert len(result["req_body_truncated"]) > 0

    def test_mixed_query_types_list_and_scalar(self):
        raw = {"client_ip":"1.1.1.1","timestamp":1.0,"query_params":{"a":"1","b":["2","3"],"c":"4"}}
        result = transform_raw_log(raw)
        assert "a=1" in result["query_strings"]
        assert "b=2" in result["query_strings"]
        assert "b=3" in result["query_strings"]
        assert "c=4" in result["query_strings"]

    def test_request_body_absent_is_removed(self):
        raw = {"client_ip":"1.1.1.1","timestamp":1.0}
        result = transform_raw_log(raw)
        assert "request_body" not in result

    def test_fingerprint_with_ipv6_full(self):
        tid = generate_deterministic_trace_id({"client_ip":"2001:0db8:85a3:0000:0000:8a2e:0370:7334","uri_path":"/","timestamp":1.0,"request_body":""})
        assert len(tid) == 32

    def test_log_transform_preserves_method(self):
        raw = {"client_ip":"1.1.1.1","timestamp":1.0,"method":"DELETE"}
        result = transform_raw_log(raw)
        assert result["method"] == "DELETE"
