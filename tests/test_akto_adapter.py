"""
akto_adapter 单元测试

验证 Akto JSON 消息 → adapt → transform_raw_log 不崩溃，字段完整。

参考文档: docs/AIWAF_Akto_Integration_Design.md §4.1
"""
import sys
import os
import json
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from akto_adapter import parse_akto_json_message
from preprocessor import transform_raw_log, generate_deterministic_trace_id


def make_akto_msg(**overrides):
    """构造模拟 akto.api.logs 的真实 JSON 格式"""
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
    return json.dumps(msg)


class TestFieldMapping:
    """验证适配层输出符合 transform_raw_log 的输入预期"""

    def test_field_mapping(self):
        """完整字段映射验证"""
        raw_log = parse_akto_json_message(make_akto_msg())

        # 适配层输出字段
        assert raw_log["client_ip"] == "10.0.1.5"
        assert raw_log["uri_path"] == "/api/users/123"
        assert raw_log["method"] == "GET"
        assert raw_log["status"] == 200
        assert raw_log["timestamp"] == 1719500000.0
        assert "query_params" in raw_log
        assert raw_log["query_params"] == {"name": "alice", "age": "30"}
        assert raw_log["request_body"] == ""

    def test_status_is_int(self):
        """statusCode String → int 转换"""
        raw_log = parse_akto_json_message(make_akto_msg(statusCode="404"))
        assert raw_log["status"] == 404
        assert isinstance(raw_log["status"], int)

    def test_timestamp_is_float(self):
        """time String → float 转换"""
        raw_log = parse_akto_json_message(make_akto_msg(time="1719500000"))
        assert raw_log["timestamp"] == 1719500000.0
        assert isinstance(raw_log["timestamp"], float)

    def test_akto_extensions(self):
        """akto 扩展字段透传"""
        raw_log = parse_akto_json_message(make_akto_msg())
        assert raw_log["akto_account_id"] == "1000000"
        assert raw_log["akto_vxlan_id"] == "1"
        assert raw_log["source"] == "MIRRORING"
        assert raw_log["direction"] == "REQUEST_RESPONSE"
        assert raw_log["dest_ip"] == "10.0.2.10"
        assert raw_log["response_payload"] == '{"id": 123}'


class TestTransformRawLog:
    """验证 adapt → transform_raw_log 不崩溃，std_log 字段完整"""

    def test_transform_complete(self):
        """完整流程: adapt → transform_raw_log → 验证 std_log"""
        raw_log = parse_akto_json_message(make_akto_msg())
        std_log = transform_raw_log(raw_log)

        # std_log 固定字段
        assert std_log["client_ip"] == "10.0.1.5"
        assert std_log["uri_path"] == "/api/users/123"
        assert std_log["method"] == "GET"
        assert std_log["status_code"] == 200
        assert std_log["timestamp"] == 1719500000.0
        assert std_log["trace_id"]                    # 非空
        assert len(std_log["trace_id"]) == 32         # SHA256 截断 32 字符
        assert std_log["query_keys"] == ["name", "age"]
        assert std_log["query_strings"] == ["name=alice", "age=30"]
        assert "request_body" not in std_log          # 已被 del
        assert std_log["req_body_truncated"] == ""

    def test_transform_akto_transparency(self):
        """akto 扩展字段经 transform_raw_log 透传后仍存在"""
        raw_log = parse_akto_json_message(make_akto_msg())
        std_log = transform_raw_log(raw_log)

        assert std_log.get("akto_account_id") == "1000000"
        assert std_log.get("akto_vxlan_id") == "1"
        assert std_log.get("source") == "MIRRORING"
        assert std_log.get("direction") == "REQUEST_RESPONSE"


class TestEdgeCases:
    """边界条件测试"""

    def test_empty_path(self):
        """空 path 不崩溃"""
        akto_msg = make_akto_msg(path="")
        raw_log = parse_akto_json_message(akto_msg)
        std_log = transform_raw_log(raw_log)
        assert std_log["uri_path"] == "/"

    def test_no_query_string(self):
        """无 query string 的 path"""
        akto_msg = make_akto_msg(path="/api/health")
        raw_log = parse_akto_json_message(akto_msg)
        assert raw_log["query_params"] == {}
        std_log = transform_raw_log(raw_log)
        assert std_log["query_keys"] == []
        assert std_log["query_strings"] == []

    def test_string_statuscode(self):
        """Akto 的 statusCode 是 String 类型"""
        akto_msg = make_akto_msg(statusCode="404")
        raw_log = parse_akto_json_message(akto_msg)
        assert raw_log["status"] == 404

    def test_int_statuscode(self):
        """statusCode 可能已经是 int"""
        akto_msg = make_akto_msg(statusCode=500)
        raw_log = parse_akto_json_message(akto_msg)
        assert raw_log["status"] == 500

    def test_invalid_statuscode(self):
        """无效 statusCode 降级为 200"""
        akto_msg = make_akto_msg(statusCode="not-a-number")
        raw_log = parse_akto_json_message(akto_msg)
        assert raw_log["status"] == 200

    def test_full_url_path(self):
        """path 是完整 URL"""
        akto_msg = make_akto_msg(path="https://api.example.com/v1/users?id=42")
        raw_log = parse_akto_json_message(akto_msg)
        assert raw_log["uri_path"] == "/v1/users"
        assert raw_log["query_params"] == {"id": "42"}

    def test_missing_fields(self):
        """缺少字段时使用默认值"""
        raw_log = parse_akto_json_message('{"path": "/test"}')
        assert raw_log["client_ip"] == "unknown"
        assert raw_log["method"] == "GET"
        assert raw_log["status"] == 200
        assert raw_log["timestamp"] == 0.0
        assert raw_log["request_body"] == ""

    def test_dict_input(self):
        """传入 dict 而非 JSON 字符串"""
        msg = {"path": "/api/test", "method": "POST", "ip": "1.2.3.4",
               "statusCode": "201", "time": "1000"}
        raw_log = parse_akto_json_message(msg)
        assert raw_log["client_ip"] == "1.2.3.4"
        assert raw_log["method"] == "POST"
        assert raw_log["status"] == 201
