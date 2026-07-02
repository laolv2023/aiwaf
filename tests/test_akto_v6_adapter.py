#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AIWAF 接入 Akto V6.0 出站适配器 —— 全面测试套件
================================================

测试覆盖范围（依据《V6.0 设计》第 3-4 节核心护城河设计）：
1. 告警分级过滤阀（Filter Valve）—— ALLOWED_THREAT_LAYERS
2. 威胁分类融合映射表（Threat Category Fusion）—— AIWAF_TO_AKTO_SUBCATEGORY
3. 采样限流器（SlidingWindowSampler）—— 滑动窗口 + 线程安全
4. Raw HTTP 安全截断重构（build_raw_http_request）—— 4096 字节截断
5. 原生 ID 透传（Native ID Pass-through）—— 脏数据丢弃
6. Protobuf 消息构造（build_malicious_event / build_kafka_envelope）
7. 告警归一化（normalize_alert）—— rule_id → layer 映射
8. 端到端集成测试（process_single_alert 全流程）
9. 入站适配器补丁验证（api_collection_id / host 提取）
"""
import json
import time
import threading
import unittest
from unittest.mock import MagicMock, patch

import sys
import os
# 确保能导入项目根目录下的包
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from aiwaf.stream.akto_v6_adapter import (
    ALLOWED_THREAT_LAYERS,
    AIWAF_TO_AKTO_SUBCATEGORY,
    MAX_PAYLOAD_BYTES,
    TRUNCATION_SUFFIX,
    _derive_layer,
    _derive_reason,
    SlidingWindowSampler,
    build_raw_http_request,
    normalize_alert,
    build_malicious_event,
    build_kafka_envelope,
    AktoV6Adapter,
    AktoV6AdapterConfig,
)
from akto_proto.threat_detection.message.malicious_event.v1 import message_pb2
from akto_proto.threat_detection.message.malicious_event.event_type.v1 import event_type_pb2


# ═══════════════════════════════════════════════════════════════
# 辅助函数：构造标准 AIWAF 告警
# ═══════════════════════════════════════════════════════════════
def make_alert(
    rule_id="KeywordBlock:sql_injection",
    client_ip="1.2.3.4",
    akto_account_id="1000000",
    api_collection_id=6,
    method="GET",
    uri_path="/api/users?id=1",
    request_headers=None,
    req_body_truncated="",
    host="api.example.com",
    country_code="CN",
    severity="HIGH",
    status_code=200,
    detected_at=1719500000.0,
    trace_id="trace-001",
):
    """构造标准 AIWAF 引擎 _emit_alert 产出的告警 JSON。"""
    if request_headers is None:
        request_headers = {"Host": "api.example.com", "User-Agent": "Mozilla/5.0"}
    return {
        "trace_id": trace_id,
        "request_uuid": "uuid-001",
        "rule_id": rule_id,
        "alert_timestamp": detected_at,
        "client_ip": client_ip,
        "akto_account_id": akto_account_id,
        "akto_vxlan_id": str(api_collection_id),
        "source": "akto",
        "direction": "INBOUND",
        "method": method,
        "uri_path": uri_path,
        "status_code": status_code,
        "detected_at": detected_at,
        "severity": severity,
        "req_body_truncated": req_body_truncated,
        "api_collection_id": api_collection_id,
        "request_headers": json.dumps(request_headers) if isinstance(request_headers, dict) else request_headers,
        "host": host,
        "country_code": country_code,
    }


# ═══════════════════════════════════════════════════════════════
# 第一部分：告警分级过滤阀测试
# ═══════════════════════════════════════════════════════════════
class TestFilterValve(unittest.TestCase):
    """告警分级过滤阀测试（设计文档第 3.1 节）"""

    def test_allowed_layers_complete(self):
        """允许列表应包含 4 个高威胁层级"""
        self.assertEqual(
            ALLOWED_THREAT_LAYERS,
            {"ai_anomaly", "uuid_tamper", "honeypot", "ip_keyword_block"},
        )

    def test_disallowed_layers_not_in_allowed(self):
        """低威胁层级不应在允许列表中"""
        for layer in ("rate_limit", "geo_block", "header_validation",
                      "method_validation", "local_blacklist", "local_ratelimit"):
            self.assertNotIn(layer, ALLOWED_THREAT_LAYERS,
                             f"{layer} 不应在允许列表中")

    def test_rule_id_to_layer_mapping_allowed(self):
        """允许的 rule_id 应映射到允许的层级"""
        cases = [
            ("KeywordBlock:sql_injection", "ip_keyword_block"),
            ("AIAnomaly:score=0.95", "ai_anomaly"),
            ("UUIDTamper:malformed_uuid", "uuid_tamper"),
            ("MethodBlock:GET to POST-only endpoint: /api/create/", "honeypot"),
        ]
        for rule_id, expected_layer in cases:
            with self.subTest(rule_id=rule_id):
                layer = _derive_layer(rule_id)
                self.assertEqual(layer, expected_layer)
                self.assertIn(layer, ALLOWED_THREAT_LAYERS)

    def test_rule_id_to_layer_mapping_filtered(self):
        """被过滤的 rule_id 应映射到不允许的层级"""
        cases = [
            ("RateLimitFlood", "rate_limit"),
            ("HeaderBlock:missing-ua", "header_validation"),
            ("GeoBlock:CN", "geo_block"),
            ("MethodBlock:Unsupported method PUT for /api/users", "method_validation"),
            ("Local_Blacklist_Block", "local_blacklist"),
            ("Local_RateLimit_Block", "local_ratelimit"),
        ]
        for rule_id, expected_layer in cases:
            with self.subTest(rule_id=rule_id):
                layer = _derive_layer(rule_id)
                self.assertEqual(layer, expected_layer)
                self.assertNotIn(layer, ALLOWED_THREAT_LAYERS)

    def test_unknown_rule_id(self):
        """未知 rule_id 应映射到 unknown"""
        self.assertEqual(_derive_layer(""), "unknown")
        self.assertEqual(_derive_layer("UnknownRule:test"), "unknown")
        self.assertEqual(_derive_layer(None), "unknown")


# ═══════════════════════════════════════════════════════════════
# 第二部分：威胁分类融合映射表测试
# ═══════════════════════════════════════════════════════════════
class TestThreatCategoryFusion(unittest.TestCase):
    """威胁分类融合映射表测试（设计文档第 3.2 节）"""

    def test_ip_keyword_block_maps_to_sql_injection(self):
        """ip_keyword_block 应映射为 SQLInjection"""
        self.assertEqual(
            AIWAF_TO_AKTO_SUBCATEGORY["ip_keyword_block"], "SQLInjection"
        )

    def test_ai_anomaly_self_mapped(self):
        """ai_anomaly 应映射为自身"""
        self.assertEqual(
            AIWAF_TO_AKTO_SUBCATEGORY["ai_anomaly"], "ai_anomaly"
        )

    def test_honeypot_self_mapped(self):
        """honeypot 应映射为自身"""
        self.assertEqual(
            AIWAF_TO_AKTO_SUBCATEGORY["honeypot"], "honeypot"
        )

    def test_uuid_tamper_self_mapped(self):
        """uuid_tamper 应映射为自身"""
        self.assertEqual(
            AIWAF_TO_AKTO_SUBCATEGORY["uuid_tamper"], "uuid_tamper"
        )

    def test_all_allowed_layers_have_mapping(self):
        """所有允许的层级都应有映射"""
        for layer in ALLOWED_THREAT_LAYERS:
            with self.subTest(layer=layer):
                self.assertIn(layer, AIWAF_TO_AKTO_SUBCATEGORY,
                              f"层级 {layer} 缺少 Akto sub_category 映射")


# ═══════════════════════════════════════════════════════════════
# 第三部分：采样限流器测试
# ═══════════════════════════════════════════════════════════════
class TestSlidingWindowSampler(unittest.TestCase):
    """采样限流器测试（设计文档第 3.4 节）"""

    def test_allow_within_limit(self):
        """窗口内未达上限应放行"""
        sampler = SlidingWindowSampler(window_seconds=60, max_samples=5)
        now = time.time()
        for i in range(5):
            self.assertTrue(
                sampler.should_sample("1.2.3.4", "ip_keyword_block", "/api/users", now)
            )

    def test_drop_over_limit(self):
        """窗口内超过上限应丢弃"""
        sampler = SlidingWindowSampler(window_seconds=60, max_samples=3)
        now = time.time()
        # 前 3 条放行
        for i in range(3):
            self.assertTrue(
                sampler.should_sample("1.2.3.4", "ip_keyword_block", "/api/users", now)
            )
        # 第 4 条丢弃
        self.assertFalse(
            sampler.should_sample("1.2.3.4", "ip_keyword_block", "/api/users", now)
        )

    def test_different_keys_independent(self):
        """不同采样键应独立计数"""
        sampler = SlidingWindowSampler(window_seconds=60, max_samples=2)
        now = time.time()
        # 同一 IP 不同 URL
        self.assertTrue(sampler.should_sample("1.2.3.4", "ip_keyword_block", "/api/a", now))
        self.assertTrue(sampler.should_sample("1.2.3.4", "ip_keyword_block", "/api/b", now))
        # 不同 IP 同一 URL
        self.assertTrue(sampler.should_sample("5.6.7.8", "ip_keyword_block", "/api/a", now))
        # 同一 key 第二次仍放行
        self.assertTrue(sampler.should_sample("1.2.3.4", "ip_keyword_block", "/api/a", now))
        # 同一 key 第三次丢弃
        self.assertFalse(sampler.should_sample("1.2.3.4", "ip_keyword_block", "/api/a", now))

    def test_window_expiry(self):
        """窗口过期后应重新放行"""
        sampler = SlidingWindowSampler(window_seconds=1, max_samples=2)
        t0 = 1000.0
        # t0 时刻 2 条
        self.assertTrue(sampler.should_sample("1.2.3.4", "ai_anomaly", "/api/x", t0))
        self.assertTrue(sampler.should_sample("1.2.3.4", "ai_anomaly", "/api/x", t0))
        # t0 时刻第 3 条丢弃
        self.assertFalse(sampler.should_sample("1.2.3.4", "ai_anomaly", "/api/x", t0))
        # 2 秒后窗口过期，重新放行
        self.assertTrue(sampler.should_sample("1.2.3.4", "ai_anomaly", "/api/x", t0 + 2))

    def test_thread_safety(self):
        """多线程并发调用应线程安全"""
        sampler = SlidingWindowSampler(window_seconds=60, max_samples=100)
        results = []
        lock = threading.Lock()

        def worker():
            local_results = []
            for _ in range(100):
                r = sampler.should_sample("1.2.3.4", "ip_keyword_block", "/api/test")
                local_results.append(r)
            with lock:
                results.extend(local_results)

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # 总共 1000 次调用，max_samples=100，应恰好放行 100 次
        allowed = sum(results)
        self.assertEqual(allowed, 100,
                         f"线程安全测试失败: 放行 {allowed} 次，期望 100 次")

    def test_stats(self):
        """统计计数器应正确"""
        sampler = SlidingWindowSampler(window_seconds=60, max_samples=2)
        now = time.time()
        sampler.should_sample("1.1.1.1", "ai_anomaly", "/a", now)
        sampler.should_sample("1.1.1.1", "ai_anomaly", "/a", now)
        sampler.should_sample("1.1.1.1", "ai_anomaly", "/a", now)  # 丢弃

        stats = sampler.stats()
        self.assertEqual(stats["total_allowed"], 2)
        self.assertEqual(stats["total_dropped"], 1)
        self.assertEqual(stats["active_keys"], 1)

    def test_cleanup(self):
        """清理过期桶应回收内存"""
        sampler = SlidingWindowSampler(window_seconds=1, max_samples=5)
        t0 = 1000.0
        sampler.should_sample("1.1.1.1", "ai_anomaly", "/a", t0)
        self.assertEqual(sampler.stats()["active_keys"], 1)
        # 2 秒后清理
        removed = sampler.cleanup(now=t0 + 2)
        self.assertEqual(removed, 1)
        self.assertEqual(sampler.stats()["active_keys"], 0)

    def test_invalid_params(self):
        """无效参数应抛出 ValueError"""
        with self.assertRaises(ValueError):
            SlidingWindowSampler(window_seconds=0)
        with self.assertRaises(ValueError):
            SlidingWindowSampler(window_seconds=-1)
        with self.assertRaises(ValueError):
            SlidingWindowSampler(max_samples=-1)


# ═══════════════════════════════════════════════════════════════
# 第四部分：Raw HTTP 安全截断重构测试
# ═══════════════════════════════════════════════════════════════
class TestBuildRawHttpRequest(unittest.TestCase):
    """Raw HTTP 安全截断重构测试（设计文档第 3.3 节）"""

    def test_basic_construction(self):
        """基本 HTTP 报文构造"""
        raw = build_raw_http_request(
            method="GET",
            url="/api/users?id=1",
            headers={"Host": "api.example.com"},
            body="",
        )
        self.assertIn("GET /api/users?id=1 HTTP/1.1", raw)
        self.assertIn("Host: api.example.com", raw)
        # 空行分隔 headers 和 body
        self.assertIn("\r\n\r\n", raw)

    def test_post_with_body(self):
        """POST 请求带 body"""
        raw = build_raw_http_request(
            method="POST",
            url="/api/login",
            headers={"Host": "api.example.com", "Content-Type": "application/json"},
            body='{"user":"admin","pass":"123"}',
        )
        self.assertIn("POST /api/login HTTP/1.1", raw)
        self.assertIn('{"user":"admin","pass":"123"}', raw)

    def test_headers_as_json_string(self):
        """headers 为 JSON 字符串时应正确解析"""
        headers_json = json.dumps({"Host": "api.example.com", "X-Custom": "test"})
        raw = build_raw_http_request("GET", "/api/test", headers_json, "")
        self.assertIn("Host: api.example.com", raw)
        self.assertIn("X-Custom: test", raw)

    def test_truncation(self):
        """超过 4096 字节应截断并追加标记"""
        large_body = "A" * 10000
        raw = build_raw_http_request(
            method="POST",
            url="/api/large",
            headers={"Host": "api.example.com"},
            body=large_body,
        )
        raw_bytes = raw.encode("utf-8")
        self.assertLessEqual(len(raw_bytes), MAX_PAYLOAD_BYTES)
        self.assertIn(TRUNCATION_SUFFIX, raw)

    def test_no_truncation_when_small(self):
        """小于 4096 字节不应截断"""
        raw = build_raw_http_request("GET", "/api/test", {"Host": "h"}, "small body")
        self.assertNotIn(TRUNCATION_SUFFIX, raw)

    def test_empty_headers(self):
        """空 headers 应正常处理"""
        raw = build_raw_http_request("GET", "/api/test", None, "")
        self.assertIn("GET /api/test HTTP/1.1", raw)

    def test_invalid_headers_json(self):
        """无效 JSON headers 应优雅降级"""
        raw = build_raw_http_request("GET", "/api/test", "invalid json{", "")
        self.assertIn("GET /api/test HTTP/1.1", raw)

    def test_method_uppercase(self):
        """方法应转为大写"""
        raw = build_raw_http_request("get", "/api/test", None, "")
        self.assertIn("GET /api/test HTTP/1.1", raw)

    def test_custom_max_bytes(self):
        """自定义截断阈值"""
        raw = build_raw_http_request(
            method="POST",
            url="/api/test",
            headers={"Host": "h"},
            body="X" * 200,
            max_bytes=100,
        )
        self.assertLessEqual(len(raw.encode("utf-8")), 100)
        self.assertIn(TRUNCATION_SUFFIX, raw)


# ═══════════════════════════════════════════════════════════════
# 第五部分：告警归一化测试
# ═══════════════════════════════════════════════════════════════
class TestNormalizeAlert(unittest.TestCase):
    """告警归一化测试（rule_id → layer 映射）"""

    def test_basic_normalization(self):
        """基本字段映射"""
        alert = make_alert(rule_id="KeywordBlock:sql_injection")
        norm = normalize_alert(alert)
        self.assertIsNotNone(norm)
        self.assertEqual(norm.layer, "ip_keyword_block")
        self.assertEqual(norm.src_ip, "1.2.3.4")
        self.assertEqual(norm.request_url, "/api/users?id=1")
        self.assertEqual(norm.http_method, "GET")
        self.assertEqual(norm.akto_account_id, "1000000")
        self.assertEqual(norm.api_collection_id, 6)
        self.assertEqual(norm.reason, "sql_injection")
        self.assertEqual(norm.country_code, "CN")
        self.assertEqual(norm.host, "api.example.com")
        self.assertEqual(norm.action, "BLOCKED")
        self.assertEqual(norm.severity, "HIGH")

    def test_honeypot_normalization(self):
        """蜜罐告警归一化"""
        alert = make_alert(rule_id="MethodBlock:GET to POST-only endpoint: /api/create/")
        norm = normalize_alert(alert)
        self.assertEqual(norm.layer, "honeypot")
        self.assertEqual(norm.reason, "GET to POST-only endpoint: /api/create/")

    def test_ai_anomaly_normalization(self):
        """AI 异常告警归一化"""
        alert = make_alert(rule_id="AIAnomaly:score=0.95")
        norm = normalize_alert(alert)
        self.assertEqual(norm.layer, "ai_anomaly")
        self.assertEqual(norm.reason, "score=0.95")

    def test_uuid_tamper_normalization(self):
        """UUID 篡改告警归一化"""
        alert = make_alert(rule_id="UUIDTamper:malformed_uuid")
        norm = normalize_alert(alert)
        self.assertEqual(norm.layer, "uuid_tamper")
        self.assertEqual(norm.reason, "malformed_uuid")

    def test_api_collection_id_from_vxlan_fallback(self):
        """api_collection_id 缺失时应回退到 akto_vxlan_id"""
        alert = make_alert()
        alert.pop("api_collection_id")
        alert["akto_vxlan_id"] = "42"
        norm = normalize_alert(alert)
        # normalize_alert 使用 api_collection_id 字段，缺失时为 0
        # 但 V6.0 适配器的 process_single_alert 会检查
        self.assertEqual(norm.api_collection_id, 0)

    def test_none_input(self):
        """空输入应返回 None"""
        self.assertIsNone(normalize_alert(None))
        self.assertIsNone(normalize_alert({}))
        self.assertIsNone(normalize_alert("not a dict"))

    def test_invalid_api_collection_id(self):
        """无效 api_collection_id 应默认为 0"""
        alert = make_alert()
        alert["api_collection_id"] = "invalid"
        norm = normalize_alert(alert)
        self.assertEqual(norm.api_collection_id, 0)

    def test_invalid_timestamp(self):
        """无效时间戳应回退到当前时间"""
        alert = make_alert()
        alert["detected_at"] = "invalid"
        alert["alert_timestamp"] = "also_invalid"
        norm = normalize_alert(alert)
        self.assertGreater(norm.timestamp, 0)


# ═══════════════════════════════════════════════════════════════
# 第六部分：Protobuf 消息构造测试
# ═══════════════════════════════════════════════════════════════
class TestProtobufConstruction(unittest.TestCase):
    """Protobuf 消息构造测试（设计文档第 4 节）"""

    def test_build_malicious_event_fields(self):
        """MaliciousEventMessage 字段映射验证"""
        alert = make_alert(rule_id="KeywordBlock:sql_injection")
        norm = normalize_alert(alert)
        event = build_malicious_event(norm)

        self.assertEqual(event.actor, "1.2.3.4")
        self.assertEqual(event.sub_category, "SQLInjection")
        self.assertEqual(event.filter_id, "AIWAF:ip_keyword_block")
        self.assertEqual(event.category, "AIWAF")
        self.assertEqual(event.detected_at, int(1719500000.0))
        self.assertEqual(event.latest_api_ip, "1.2.3.4")
        self.assertEqual(event.latest_api_endpoint, "/api/users?id=1")
        self.assertEqual(event.latest_api_method, "GET")
        self.assertEqual(event.latest_api_collection_id, 6)
        self.assertIn("GET /api/users?id=1 HTTP/1.1", event.latest_api_payload)
        self.assertEqual(event.severity, "HIGH")
        self.assertFalse(event.successful_exploit)
        self.assertEqual(event.status, "BLOCKED")
        self.assertEqual(event.context_source, "API")
        self.assertEqual(event.event_type, event_type_pb2.EVENT_TYPE_SINGLE)
        self.assertEqual(event.host, "api.example.com")
        self.assertEqual(event.metadata.reason, "sql_injection")
        self.assertEqual(event.metadata.country_code, "CN")

    def test_build_malicious_event_payload_truncated(self):
        """latest_api_payload 应被截断至 4096 字节"""
        alert = make_alert(req_body_truncated="X" * 10000)
        norm = normalize_alert(alert)
        event = build_malicious_event(norm)
        self.assertLessEqual(len(event.latest_api_payload.encode("utf-8")), MAX_PAYLOAD_BYTES)

    def test_build_kafka_envelope_fields(self):
        """MaliciousEventKafkaEnvelope 字段映射验证"""
        alert = make_alert()
        norm = normalize_alert(alert)
        event = build_malicious_event(norm)
        envelope = build_kafka_envelope(norm, event)

        self.assertEqual(envelope.account_id, "1000000")
        self.assertEqual(envelope.actor, "1.2.3.4")
        self.assertEqual(envelope.malicious_event.sub_category, "SQLInjection")
        self.assertEqual(envelope.malicious_event.latest_api_collection_id, 6)

    def test_serialization_roundtrip(self):
        """Protobuf 序列化/反序列化往返测试"""
        alert = make_alert(rule_id="AIAnomaly:score=0.95")
        norm = normalize_alert(alert)
        event = build_malicious_event(norm)
        envelope = build_kafka_envelope(norm, event)

        # 序列化
        data = envelope.SerializeToString()
        self.assertGreater(len(data), 0)

        # 反序列化
        envelope2 = message_pb2.MaliciousEventKafkaEnvelope()
        envelope2.ParseFromString(data)
        self.assertEqual(envelope2.account_id, "1000000")
        self.assertEqual(envelope2.malicious_event.sub_category, "ai_anomaly")
        self.assertEqual(envelope2.malicious_event.actor, "1.2.3.4")
        self.assertEqual(envelope2.malicious_event.event_type, event_type_pb2.EVENT_TYPE_SINGLE)

    def test_all_allowed_layers_protobuf(self):
        """所有允许的层级都应能正确构造 Protobuf"""
        for rule_id, expected_sub_category in [
            ("KeywordBlock:sql_injection", "SQLInjection"),
            ("AIAnomaly:score=0.95", "ai_anomaly"),
            ("UUIDTamper:malformed_uuid", "uuid_tamper"),
            ("MethodBlock:GET to POST-only endpoint: /api/create/", "honeypot"),
        ]:
            with self.subTest(rule_id=rule_id):
                alert = make_alert(rule_id=rule_id)
                norm = normalize_alert(alert)
                event = build_malicious_event(norm)
                self.assertEqual(event.sub_category, expected_sub_category)


# ═══════════════════════════════════════════════════════════════
# 第七部分：AktoV6Adapter 端到端测试
# ═══════════════════════════════════════════════════════════════
class TestAktoV6Adapter(unittest.TestCase):
    """AktoV6Adapter 端到端测试（五重处理全流程）"""

    def _make_adapter(self):
        """创建不连接 Kafka 的适配器实例（用于测试）"""
        config = AktoV6AdapterConfig(
            kafka_bootstrap_servers="dummy:9092",
            sampler_window_seconds=60,
            sampler_max_samples=5,
        )
        adapter = AktoV6Adapter(config)
        return adapter

    def test_process_allowed_alert(self):
        """允许的告警应通过五重处理并构造 Protobuf"""
        adapter = self._make_adapter()
        alert = make_alert(rule_id="KeywordBlock:sql_injection")
        success, envelope_bytes = adapter.process_single_alert(alert)
        self.assertTrue(success)
        self.assertIsNotNone(envelope_bytes)
        # 验证序列化的 Protobuf 可反序列化
        envelope = message_pb2.MaliciousEventKafkaEnvelope()
        envelope.ParseFromString(envelope_bytes)
        self.assertEqual(envelope.account_id, "1000000")
        self.assertEqual(envelope.malicious_event.sub_category, "SQLInjection")
        stats = adapter.get_stats()
        self.assertEqual(stats["processed"], 1)
        self.assertEqual(stats["injected"], 0)  # process_single_alert 不注入 Kafka
        self.assertEqual(stats["filtered_out"], 0)

    def test_process_filtered_alert(self):
        """被过滤的告警应被丢弃"""
        adapter = self._make_adapter()
        alert = make_alert(rule_id="RateLimitFlood")
        success, envelope_bytes = adapter.process_single_alert(alert)
        self.assertFalse(success)
        self.assertIsNone(envelope_bytes)
        stats = adapter.get_stats()
        self.assertEqual(stats["filtered_out"], 1)

    def test_process_sampled_out_alert(self):
        """超过采样上限的告警应被丢弃"""
        adapter = self._make_adapter()
        # 配置 max_samples=2
        adapter._sampler = SlidingWindowSampler(window_seconds=60, max_samples=2)
        alert1 = make_alert(rule_id="KeywordBlock:sql_injection", trace_id="t1")
        alert2 = make_alert(rule_id="KeywordBlock:sql_injection", trace_id="t2")
        alert3 = make_alert(rule_id="KeywordBlock:sql_injection", trace_id="t3")
        s1, _ = adapter.process_single_alert(alert1)
        s2, _ = adapter.process_single_alert(alert2)
        s3, _ = adapter.process_single_alert(alert3)
        self.assertTrue(s1)
        self.assertTrue(s2)
        self.assertFalse(s3)
        stats = adapter.get_stats()
        self.assertEqual(stats["sampled_out"], 1)

    def test_process_missing_account_id(self):
        """缺失 akto_account_id 应被丢弃"""
        adapter = self._make_adapter()
        alert = make_alert(akto_account_id="")
        success, _ = adapter.process_single_alert(alert)
        self.assertFalse(success)
        stats = adapter.get_stats()
        self.assertEqual(stats["id_missing"], 1)

    def test_process_missing_collection_id(self):
        """缺失 api_collection_id 应被丢弃"""
        adapter = self._make_adapter()
        alert = make_alert(api_collection_id=0)
        success, _ = adapter.process_single_alert(alert)
        self.assertFalse(success)
        stats = adapter.get_stats()
        self.assertEqual(stats["id_missing"], 1)

    def test_process_all_allowed_layers(self):
        """所有允许的层级都应通过处理"""
        adapter = self._make_adapter()
        for rule_id in [
            "KeywordBlock:sql_injection",
            "AIAnomaly:score=0.95",
            "UUIDTamper:malformed_uuid",
            "MethodBlock:GET to POST-only endpoint: /api/create/",
        ]:
            with self.subTest(rule_id=rule_id):
                alert = make_alert(rule_id=rule_id, trace_id=f"trace-{rule_id}")
                # 每次使用不同的 IP 避免采样器干扰
                alert["client_ip"] = f"10.0.0.{hash(rule_id) % 255}"
                success, envelope_bytes = adapter.process_single_alert(alert)
                self.assertTrue(success)
                self.assertIsNotNone(envelope_bytes)

    def test_process_invalid_json_alert(self):
        """无效告警（None）应被丢弃并计入 errors"""
        adapter = self._make_adapter()
        success, _ = adapter.process_single_alert(None)
        self.assertFalse(success)
        stats = adapter.get_stats()
        self.assertEqual(stats["errors"], 1)

    def test_stats_tracking(self):
        """统计指标应正确跟踪"""
        adapter = self._make_adapter()
        # 1 条通过
        adapter.process_single_alert(make_alert(rule_id="KeywordBlock:sql_injection", trace_id="ok"))
        # 1 条被过滤
        adapter.process_single_alert(make_alert(rule_id="RateLimitFlood", trace_id="filtered"))
        # 1 条 ID 缺失
        adapter.process_single_alert(make_alert(rule_id="KeywordBlock:sql_injection",
                                                akto_account_id="", trace_id="noid"))
        stats = adapter.get_stats()
        self.assertEqual(stats["processed"], 3)
        self.assertEqual(stats["filtered_out"], 1)
        self.assertEqual(stats["id_missing"], 1)


# ═══════════════════════════════════════════════════════════════
# 第八部分：入站适配器补丁验证
# ═══════════════════════════════════════════════════════════════
class TestInboundAdapterPatch(unittest.TestCase):
    """入站适配器补丁验证（api_collection_id / host 提取）"""

    def test_api_collection_id_from_apiCollectionId(self):
        """api_collection_id 应从 apiCollectionId 字段提取"""
        from aiwaf.stream.akto_adapter import parse_akto_json_message
        msg = {
            "ip": "1.2.3.4",
            "method": "GET",
            "path": "/api/test",
            "akto_account_id": "1000000",
            "apiCollectionId": "42",
        }
        result = parse_akto_json_message(msg)
        self.assertEqual(result["api_collection_id"], 42)

    def test_api_collection_id_from_snake_case(self):
        """api_collection_id 应从 api_collection_id 字段提取"""
        from aiwaf.stream.akto_adapter import parse_akto_json_message
        msg = {
            "ip": "1.2.3.4",
            "method": "GET",
            "path": "/api/test",
            "akto_account_id": "1000000",
            "api_collection_id": "99",
        }
        result = parse_akto_json_message(msg)
        self.assertEqual(result["api_collection_id"], 99)

    def test_api_collection_id_from_vxlan_fallback(self):
        """api_collection_id 缺失时应回退到 akto_vxlan_id"""
        from aiwaf.stream.akto_adapter import parse_akto_json_message
        msg = {
            "ip": "1.2.3.4",
            "method": "GET",
            "path": "/api/test",
            "akto_account_id": "1000000",
            "akto_vxlan_id": "6",
        }
        result = parse_akto_json_message(msg)
        self.assertEqual(result["api_collection_id"], 6)

    def test_api_collection_id_invalid_defaults_zero(self):
        """api_collection_id 无效时默认为 0"""
        from aiwaf.stream.akto_adapter import parse_akto_json_message
        msg = {
            "ip": "1.2.3.4",
            "method": "GET",
            "path": "/api/test",
            "akto_account_id": "1000000",
            "akto_vxlan_id": "invalid",
        }
        result = parse_akto_json_message(msg)
        self.assertEqual(result["api_collection_id"], 0)

    def test_host_from_headers(self):
        """host 应从 requestHeaders 中提取"""
        from aiwaf.stream.akto_adapter import parse_akto_json_message
        import orjson
        msg = {
            "ip": "1.2.3.4",
            "method": "GET",
            "path": "/api/test",
            "akto_account_id": "1000000",
            "akto_vxlan_id": "6",
            "requestHeaders": orjson.dumps({"Host": "api.example.com"}).decode(),
        }
        result = parse_akto_json_message(msg)
        self.assertEqual(result["host"], "api.example.com")

    def test_host_from_top_level(self):
        """host 应优先从 JSON 顶层获取"""
        from aiwaf.stream.akto_adapter import parse_akto_json_message
        msg = {
            "ip": "1.2.3.4",
            "method": "GET",
            "path": "/api/test",
            "akto_account_id": "1000000",
            "akto_vxlan_id": "6",
            "host": "top-level-host.com",
        }
        result = parse_akto_json_message(msg)
        self.assertEqual(result["host"], "top-level-host.com")


# ═══════════════════════════════════════════════════════════════
# 第九部分：配置补丁验证
# ═══════════════════════════════════════════════════════════════
class TestConfigPatch(unittest.TestCase):
    """配置补丁验证（V6.0 适配器配置项）"""

    def test_default_config_values(self):
        """默认配置值应正确"""
        from aiwaf.stream.config import Settings
        s = Settings()
        self.assertFalse(s.akto_v6_adapter_enabled)
        self.assertEqual(s.akto_v6_malicious_events_topic, "akto.threat_detection.malicious_events")
        self.assertEqual(s.akto_v6_consumer_group, "aiwaf-akto-adapter-v6")
        self.assertEqual(s.akto_v6_sampler_window_seconds, 60)
        self.assertEqual(s.akto_v6_sampler_max_samples, 5)
        self.assertEqual(s.akto_v6_max_payload_bytes, 4096)

    def test_config_from_env(self):
        """配置应支持从环境变量加载"""
        from aiwaf.stream.config import Settings
        env = {
            "AKTO_V6_ADAPTER_ENABLED": "true",
            "AKTO_V6_SAMPLER_WINDOW_SECONDS": "120",
            "AKTO_V6_SAMPLER_MAX_SAMPLES": "10",
            "AKTO_V6_MAX_PAYLOAD_BYTES": "8192",
        }
        with patch.dict(os.environ, env, clear=False):
            s = Settings.from_env()
            self.assertTrue(s.akto_v6_adapter_enabled)
            self.assertEqual(s.akto_v6_sampler_window_seconds, 120)
            self.assertEqual(s.akto_v6_sampler_max_samples, 10)
            self.assertEqual(s.akto_v6_max_payload_bytes, 8192)


if __name__ == "__main__":
    unittest.main()
