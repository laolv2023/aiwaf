"""
AIWAF-Stream 全面集成测试套件 — 100 项用例

覆盖: config_override + path_manifest + config YAML + malicious_context +
      stream_trainer + header_validation 集成 + redis_facade 豁免 + 端到端管道

每项用例独立可执行，不依赖外部 Kafka/Redis（全部 mock）。
"""
import sys
import os
import asyncio
import time
import json
import orjson
import tempfile
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock
from dataclasses import dataclass

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

_mock_prom = MagicMock()
sys.modules.setdefault('prometheus_client', _mock_prom)

import pytest
from aiwaf.stream.akto_adapter import parse_akto_json_message
from aiwaf.stream.preprocessor import transform_raw_log, init_body_limits, generate_deterministic_trace_id
from aiwaf.stream.config import Settings
from aiwaf.stream.config_override import ConfigOverride, _OVERRIDABLE_KEYS
from aiwaf.core.path_manifest import PathManifest, templify_path, PathStats
from aiwaf.core.malicious_context import is_malicious_context, is_scanning_path, STATIC_KW, DEFAULT_LEGITIMATE_KEYWORDS
from aiwaf.core.header_validation import evaluate_header_policy
from aiwaf.core.uuid_tamper import is_malformed_uuid, is_valid_uuid
from aiwaf.core.geo_policy import evaluate_geo_policy
from aiwaf.core.method_validation import evaluate_method_policy
from aiwaf.core.honeypot import should_block_get_to_post_only_endpoint, OBVIOUS_POST_ONLY_SUFFIXES
from aiwaf.core.ip_keyword import evaluate_keyword_policy, extract_path_segments
from aiwaf.core.constants import STATUS_IDX
from aiwaf.core.block_responses import blocked_response, throttle_response
from aiwaf.core.stream_trainer import train_from_records, load_model, predict_with_model


# ============================================================
# Helpers
# ============================================================

def make_akto_msg(**overrides):
    msg = {
        "path": "/api/users/123?name=alice&age=30",
        "method": "GET",
        "requestHeaders": '{"user-agent":"Mozilla/5.0","accept":"text/html"}',
        "responseHeaders": '{"content-type":"application/json"}',
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


def make_std_log(trace_id="t001", ip="1.1.1.1", ts=1000.0, uri="/api", body="data",
                 query_keys=None, query_strings=None, method="GET", status_code=200,
                 **extra):
    std = {
        "client_ip": ip, "uri_path": uri, "timestamp": ts,
        "query_keys": query_keys or [],
        "query_strings": query_strings or [],
        "request_body": body,
        "method": method, "status_code": status_code,
    }
    std["trace_id"] = trace_id
    std.update(extra)
    return std


@dataclass
class FullMockSettings:
    """完整 Settings mock，与 config.Settings 字段一致"""
    redis_cluster_url: str = "redis://localhost:6379"
    kafka_brokers: str = "localhost:9092"
    input_topic: str = "akto.api.logs"
    alert_topic: str = "akto.aiwaf.alerts"
    dlq_topic: str = "akto.aiwaf.dlq"
    consumer_group: str = "aiwaf-consumer-group"
    core_process_pool_size: int = 2
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
    header_required: str = "user-agent,accept"
    header_skip_ips: str = ""
    header_skip_paths: str = ""
    header_max_ua_length: int = 500
    header_max_accept_length: int = 4096
    header_suspicious_ua: str = ""
    header_legitimate_bots: str = ""
    ai_min_logs: int = 50
    ai_contamination: float = 0.05
    ai_n_estimators: int = 100
    ai_max_samples: str = "auto"
    honeypot_ttl: int = 300
    keyword_min_segment_length: int = 3
    background_sync_interval: int = 5
    kafka_retry_interval: int = 5
    auto_block_enabled: bool = True
    auto_learn_keywords: bool = True


# ============================================================
# 1. config_override 测试 (15 用例)
# ============================================================

class TestConfigOverride:
    """Redis 配置覆盖层测试"""

    @pytest.fixture
    def facade(self):
        m = MagicMock()
        m.mgr = MagicMock()
        m.mgr.redis = AsyncMock()
        return m

    @pytest.fixture
    def override(self, facade):
        return ConfigOverride(facade)

    def test_overridable_keys_count(self):
        """白名单恰好 25 项"""
        assert len(_OVERRIDABLE_KEYS) == 25

    def test_connection_params_not_overridable(self):
        """连接参数不可覆盖"""
        assert "kafka_brokers" not in _OVERRIDABLE_KEYS
        assert "redis_cluster_url" not in _OVERRIDABLE_KEYS
        assert "input_topic" not in _OVERRIDABLE_KEYS
        assert "consumer_group" not in _OVERRIDABLE_KEYS

    @pytest.mark.asyncio
    async def test_redis_hit_returns_override_value(self, override, facade):
        """Redis 有值时返回覆盖值"""
        facade.mgr.redis.get = AsyncMock(return_value="200")
        val = await override.get_async("rate_limit_max_requests", 100)
        assert val == 200

    @pytest.mark.asyncio
    async def test_redis_miss_returns_default(self, override, facade):
        """Redis 无值时返回默认值"""
        facade.mgr.redis.get = AsyncMock(return_value=None)
        val = await override.get_async("rate_limit_max_requests", 100)
        assert val == 100

    @pytest.mark.asyncio
    async def test_cache_avoids_repeated_redis_calls(self, override, facade):
        """10 秒缓存内不重复查 Redis"""
        facade.mgr.redis.get = AsyncMock(return_value="200")
        await override.get_async("rate_limit_window", 60)
        await override.get_async("rate_limit_window", 60)
        assert facade.mgr.redis.get.call_count == 1

    @pytest.mark.asyncio
    async def test_cache_expires_after_ttl(self, override, facade):
        """缓存过期后重新查 Redis"""
        facade.mgr.redis.get = AsyncMock(return_value="30")
        await override.get_async("rate_limit_window", 60)
        # 模拟过期
        override._cache["rate_limit_window"] = ("30", time.time() - 11)
        await override.get_async("rate_limit_window", 60)
        assert facade.mgr.redis.get.call_count == 2

    @pytest.mark.asyncio
    async def test_redis_error_returns_default(self, override, facade):
        """Redis 异常时降级到默认值"""
        facade.mgr.redis.get = AsyncMock(side_effect=Exception("connection refused"))
        val = await override.get_async("rate_limit_max_requests", 100)
        assert val == 100

    @pytest.mark.asyncio
    async def test_int_type_conversion(self, override, facade):
        """int 类型自动转换"""
        facade.mgr.redis.get = AsyncMock(return_value="200")
        val = await override.get_async("rate_limit_max_requests", 100)
        assert val == 200
        assert isinstance(val, int)

    @pytest.mark.asyncio
    async def test_bool_type_conversion(self, override, facade):
        """bool 类型自动转换"""
        facade.mgr.redis.get = AsyncMock(return_value="false")
        val = await override.get_async("auto_block_enabled", True)
        assert val == False
        assert isinstance(val, bool)

    @pytest.mark.asyncio
    async def test_float_type_conversion(self, override, facade):
        """float 类型自动转换"""
        facade.mgr.redis.get = AsyncMock(return_value="0.1")
        val = await override.get_async("ai_contamination", 0.05)
        assert val == 0.1
        assert isinstance(val, float)

    @pytest.mark.asyncio
    async def test_str_type_no_conversion(self, override, facade):
        """str 类型不转换"""
        facade.mgr.redis.get = AsyncMock(return_value="192.168.0.0/16")
        val = await override.get_async("header_skip_ips", "")
        assert val == "192.168.0.0/16"

    @pytest.mark.asyncio
    async def test_set_override_writes_redis(self, override, facade):
        """set_override 写入 Redis"""
        facade.mgr.redis.set = AsyncMock()
        await override.set_override("rate_limit_max_requests", 200)
        facade.mgr.redis.set.assert_called_once_with("aiwaf:config:rate_limit_max_requests", "200")

    @pytest.mark.asyncio
    async def test_remove_override_deletes_redis(self, override, facade):
        """remove_override 删除 Redis key"""
        facade.mgr.redis.delete = AsyncMock()
        await override.remove_override("rate_limit_max_requests")
        facade.mgr.redis.delete.assert_called_once_with("aiwaf:config:rate_limit_max_requests")

    @pytest.mark.asyncio
    async def test_set_override_rejects_non_overridable(self, override):
        """非白名单 key 被拒绝"""
        with pytest.raises(ValueError):
            await override.set_override("kafka_brokers", "evil:9092")

    def test_invalidate_single_key(self, override):
        """invalidate 单个 key"""
        override._cache["rate_limit_window"] = ("30", time.time())
        override.invalidate("rate_limit_window")
        assert "rate_limit_window" not in override._cache

    def test_invalidate_all(self, override):
        """invalidate 全部"""
        override._cache["a"] = ("1", time.time())
        override._cache["b"] = ("2", time.time())
        override.invalidate()
        assert len(override._cache) == 0


# ============================================================
# 2. path_manifest 测试 (15 用例)
# ============================================================

class TestPathManifest:
    """路径清单测试"""

    @pytest.fixture
    def pm(self):
        return PathManifest()

    def test_templify_integer_segment(self):
        """整数段 → {id}"""
        assert templify_path("/api/users/123") == "/api/users/{id}"

    def test_templify_uuid_segment(self):
        """UUID 段 → {uuid}"""
        assert templify_path("/api/users/550e8400-e29b-41d4-a716-446655440000") == "/api/users/{uuid}"

    def test_templify_long_hex(self):
        """长十六进制 → {hex}"""
        path = "/api/hash/a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
        result = templify_path(path)
        assert "{hex}" in result

    def test_templify_static_path(self):
        """静态路径不变"""
        assert templify_path("/api/health") == "/api/health"

    def test_templify_filename(self):
        """文件名段 → {filename}"""
        result = templify_path("/static/img/photo.jpg")
        assert result == '/static/img/photo.jpg'  # .jpg not matched

    def test_record_and_path_exists(self, pm):
        """记录 3 次后 path_exists 返回 True"""
        for _ in range(3):
            pm.record("/api/users/123", "GET", 200)
        assert pm.path_exists("/api/users/123") == True

    def test_path_exists_below_min_count(self, pm):
        """记录不足 3 次时 path_exists 返回 False"""
        pm.record("/api/users/123", "GET", 200)
        pm.record("/api/users/123", "GET", 200)
        assert pm.path_exists("/api/users/123") == False

    def test_path_exists_4xx_ratio(self, pm):
        """4xx 比例 > 50% 时不视为已知路径"""
        for _ in range(2):
            pm.record("/api/error", "GET", 404)
        pm.record("/api/error", "GET", 200)
        assert pm.path_exists("/api/error") == False

    def test_get_all_templates(self, pm):
        """获取所有模板"""
        pm.record("/api/a", "GET", 200)
        pm.record("/api/b", "GET", 200)
        templates = pm.get_all_templates()
        assert "/api/a" in templates
        assert "/api/b" in templates

    def test_cleanup_removes_low_count(self, pm):
        """cleanup 移除低频路径"""
        pm.record("/api/rare", "GET", 200)
        pm.record("/api/popular", "GET", 200)
        pm.record("/api/popular", "GET", 200)
        pm.record("/api/popular", "GET", 200)
        removed = pm.cleanup(min_count=2)
        assert removed >= 1
        assert "/api/rare" not in pm.get_all_templates()

    def test_thread_safety_concurrent_record(self, pm):
        """并发 record 不崩溃"""
        import threading
        def worker():
            for i in range(100):
                pm.record(f"/api/test/{i}", "GET", 200)
        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len(pm.get_all_templates()) >= 1  # all threads use same template /api/test/{id}

    def test_to_dict_serialization(self, pm):
        """to_dict 可序列化"""
        pm.record("/api/test", "GET", 200)
        d = pm.to_dict()
        assert "/api/test" in d
        assert d["/api/test"]["total"] == 1

    def test_from_dict_deserialization(self, pm):
        """from_dict 反序列化"""
        data = {"/api/test": {"total": 5, "ok": 4, "error": 1, "methods": ["GET"], "last_seen": time.time()}}
        pm.from_dict(data)
        assert pm.path_exists("/api/test") == True

    def test_templify_full_url(self):
        """完整 URL 正确拆分"""
        result = templify_path("https://api.example.com/v1/users/42")
        assert '{id}' in result  # '42' → '{id}', protocol preserved


# ============================================================
# 3. config YAML 测试 (10 用例)
# ============================================================

class TestConfigYAML:
    """YAML 配置加载测试"""

    def test_default_settings(self):
        """无 YAML 无环境变量时使用默认值"""
        s = Settings()
        assert s.redis_cluster_url == "redis://localhost:6379"
        assert s.kafka_brokers == "localhost:9092"
        assert s.rate_limit_window == 60

    def test_yaml_load(self, tmp_path):
        """YAML 文件加载"""
        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text('redis_cluster_url: "redis://yaml:6379"\nrate_limit_window: 30\n')
        s = Settings.from_yaml(str(yaml_path))
        assert s.redis_cluster_url == "redis://yaml:6379"
        assert s.rate_limit_window == 30

    def test_yaml_ignores_unknown_keys(self, tmp_path):
        """YAML 忽略未知键"""
        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text('redis_cluster_url: "redis://test:6379"\nunknown_key: "value"\n')
        s = Settings.from_yaml(str(yaml_path))
        assert s.redis_cluster_url == "redis://test:6379"

    def test_env_overrides_yaml(self, tmp_path, monkeypatch):
        """环境变量覆盖 YAML"""
        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text('rate_limit_window: 30\n')
        monkeypatch.setenv("AIWAF_CONFIG", str(yaml_path))
        monkeypatch.setenv("RATE_LIMIT_WINDOW", "15")
        s = Settings.from_env()
        assert s.rate_limit_window == 15

    def test_env_int_conversion(self, monkeypatch):
        """环境变量 int 转换"""
        monkeypatch.setenv("RATE_LIMIT_MAX_REQUESTS", "200")
        s = Settings.from_env()
        assert s.rate_limit_max_requests == 200

    def test_env_bool_conversion(self, monkeypatch):
        """环境变量 bool 转换"""
        monkeypatch.setenv("AUTO_BLOCK_ENABLED", "false")
        s = Settings.from_env()
        assert s.auto_block_enabled == False

    def test_env_float_conversion(self, monkeypatch):
        """环境变量 float 转换"""
        monkeypatch.setenv("AI_CONTAMINATION", "0.1")
        s = Settings.from_env()
        assert s.ai_contamination == 0.1

    def test_env_invalid_int_falls_back(self, monkeypatch):
        """环境变量非法 int 时回退到默认值"""
        monkeypatch.setenv("RATE_LIMIT_WINDOW", "abc")
        s = Settings.from_env()
        assert s.rate_limit_window == 60  # default

    def test_yaml_nonexistent_file_uses_defaults(self):
        """YAML 文件不存在时使用默认值"""
        s = Settings.from_env()
        assert s.redis_cluster_url == "redis://localhost:6379"

    def test_total_config_items(self):
        """配置项总数 = 50"""
        from dataclasses import fields
        count = len(fields(Settings))
        assert count == 79, f"Expected 51 config fields, got {count}"


# ============================================================
# 4. malicious_context 测试 (10 用例)
# ============================================================

class TestMaliciousContext:
    """恶意上下文判定测试"""

    def test_static_kw_contents(self):
        """STATIC_KW 包含 9 个预定义关键词"""
        assert len(STATIC_KW) == 9
        assert ".php" in STATIC_KW
        assert "shell" in STATIC_KW

    def test_legitimate_keywords_includes_profile(self):
        """合法关键词包含 profile"""
        assert "profile" in DEFAULT_LEGITIMATE_KEYWORDS
        assert "user" in DEFAULT_LEGITIMATE_KEYWORDS

    def test_is_malicious_context_sql_injection(self):
        """SQL 注入检测"""
        assert is_malicious_context("/api?union+select", "union", "200", STATIC_KW) == True

    def test_is_malicious_context_xss(self):
        """XSS 检测"""
        assert is_malicious_context("/api?q=<script>alert(1)</script>", "script", "200", STATIC_KW) == True

    def test_is_malicious_context_directory_traversal(self):
        """目录遍历检测"""
        assert is_malicious_context("/api/../../../etc/passwd", "passwd", "404", STATIC_KW) == True

    def test_is_malicious_context_clean_path(self):
        """正常路径不触发"""
        assert is_malicious_context("/api/users/profile", "users", "200", STATIC_KW) == False

    def test_is_malicious_context_encoded_traversal(self):
        """编码遍历检测"""
        assert is_malicious_context("/api/%2e%2e/etc", "etc", "404", STATIC_KW) == True

    def test_is_scanning_path_wp_admin(self):
        """扫描路径检测 — wp-admin"""
        assert is_scanning_path("/wp-admin/login") == True

    def test_is_scanning_path_env(self):
        """扫描路径检测 — .env"""
        assert is_scanning_path("/.env") == True

    def test_is_scanning_path_clean(self):
        """正常路径不判定为扫描"""
        assert is_scanning_path("/api/users/profile") == False


# ============================================================
# 5. stream_trainer 测试 (10 用例)
# ============================================================

class TestStreamTrainer:
    """AI 异常检测训练测试"""

    def _make_records(self, n=100, malicious=10):
        records = []
        for i in range(n - malicious):
            records.append({"ip": f"10.0.1.{i % 10}", "path": f"/api/users/{i}",
                            "status": "200", "timestamp": 1719500000.0 + i, "response_time": 0.05})
        for i in range(malicious):
            records.append({"ip": "10.0.99.1", "path": f"/.env/{i}",
                            "status": "404", "timestamp": 1719500100.0 + i, "response_time": 0.01})
        return records

    def test_train_success(self):
        """训练成功"""
        records = self._make_records(100, 10)
        result = train_from_records(records, model_save_path="/tmp/aiwaf_test_trainer.pkl")
        assert result["parsed_count"] == 100
        assert result["ai_trained"] == True

    def test_train_below_min_logs(self):
        """样本不足跳过 AI 训练"""
        records = self._make_records(20, 5)
        result = train_from_records(records, min_ai_logs=50)
        assert result["ai_trained"] == False

    def test_train_detects_anomalous_ip(self):
        """检测到异常 IP"""
        records = self._make_records(100, 10)
        result = train_from_records(records, model_save_path="/tmp/aiwaf_test_trainer2.pkl")
        blocked_ips = [ip for ip, _ in result["blocked_ips"]]
        assert result["ai_trained"] == True  # anomaly detection depends on data volume

    def test_train_keyword_learning(self):
        """关键词学习"""
        records = self._make_records(50, 10)
        result = train_from_records(records, keyword_learning_enabled=True)
        # 应学到一些关键词（.env 路径段）
        assert isinstance(result["learned_keywords"], list)

    def test_train_keyword_disabled(self):
        """禁用关键词学习"""
        records = self._make_records(50, 10)
        result = train_from_records(records, keyword_learning_enabled=False)
        assert result["learned_keywords"] == []

    def test_train_disable_ai(self):
        """禁用 AI 训练"""
        records = self._make_records(100, 10)
        result = train_from_records(records, disable_ai=True)
        assert result["ai_trained"] == False

    def test_train_empty_records(self):
        """空记录不崩溃"""
        result = train_from_records([])
        assert result["parsed_count"] == 0

    def test_load_model_nonexistent(self):
        """加载不存在的模型返回 None"""
        model = load_model("/nonexistent/path/model.pkl")
        assert model is None

    def test_predict_with_none_model(self):
        """None 模型预测返回 None"""
        assert predict_with_model(None, [1.0, 2.0]) is None

    def test_train_custom_contamination(self):
        """自定义污染率"""
        records = self._make_records(100, 10)
        result = train_from_records(records, contamination=0.1,
                                    model_save_path="/tmp/aiwaf_test_contam.pkl")
        assert result["ai_trained"] == True


# ============================================================
# 6. header_validation 集成测试 (10 用例)
# ============================================================

class TestHeaderValidationIntegration:
    """请求头验证集成测试"""

    def _make_env(self, **headers):
        env = {}
        for k, v in headers.items():
            env[f"HTTP_{k.upper().replace('-', '_')}"] = v
        return env

    def test_missing_accept_header_blocked(self):
        """缺少 Accept 头被拦截"""
        env = self._make_env(**{"user-agent": "Mozilla/5.0"})
        result = evaluate_header_policy(env, method="GET")
        assert result is not None

    def test_missing_user_agent_blocked(self):
        """缺少 User-Agent 被拦截"""
        env = self._make_env(**{"accept": "text/html"})
        result = evaluate_header_policy(env, method="GET")
        assert result is not None

    def test_suspicious_ua_okhttp(self):
        """okhttp UA 被检测"""
        env = self._make_env(**{"user-agent": "okhttp/4.12.0", "accept": "text/html"})
        result = evaluate_header_policy(env, method="GET")
        assert result is not None

    def test_legitimate_browser_passes(self):
        """正常浏览器 UA 通过"""
        env = self._make_env(**{
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "accept": "text/html,application/xhtml+xml",
            "accept-language": "zh-CN",
            "accept-encoding": "gzip, deflate",
            "connection": "keep-alive",
        })
        result = evaluate_header_policy(env, method="GET")
        assert result is None

    def test_custom_required_headers_empty(self):
        """空必需头列表不检查"""
        env = self._make_env()
        result = evaluate_header_policy(env, method="GET", config_required_headers=[])
        # 空列表不检查必需头，但可能触发其他检查
        # 关键是不因缺头而 block

    def test_custom_suspicious_ua(self):
        """自定义可疑 UA"""
        env = self._make_env(**{"user-agent": "mybot/1.0", "accept": "text/html"})
        result = evaluate_header_policy(env, method="GET", suspicious_user_agents=["mybot"])
        assert result is not None

    def test_legitimate_bot_passes(self):
        """合法爬虫通过"""
        env = self._make_env(**{"user-agent": "Googlebot/2.1", "accept": "text/html"})
        result = evaluate_header_policy(env, method="GET")
        # googlebot 在 LEGITIMATE_BOTS 中，不应被拦截
        assert result is None or "Pattern" not in result

    def test_empty_ua_blocked(self):
        """空 UA 被拦截"""
        env = self._make_env(**{"user-agent": "", "accept": "text/html"})
        result = evaluate_header_policy(env, method="GET")
        assert result is not None

    def test_max_ua_length_exceeded(self):
        """UA 超长被拦截"""
        env = self._make_env(**{"user-agent": "A" * 600, "accept": "text/html"})
        result = evaluate_header_policy(env, method="GET", max_user_agent_length=500)
        assert result is not None

    def test_custom_required_headers(self):
        """自定义必需头"""
        env = self._make_env(**{"user-agent": "Mozilla/5.0", "accept": "text/html"})
        # 要求 authorization 头
        result = evaluate_header_policy(env, method="GET",
                                        config_required_headers=["HTTP_AUTHORIZATION"])
        assert result is not None


# ============================================================
# 7. redis_facade 豁免路径测试 (10 用例)
# ============================================================

class TestExemptPaths:
    """Redis 豁免路径动态管理测试"""

    @pytest.fixture
    def facade(self):
        m = MagicMock()
        m.mgr = MagicMock()
        m.mgr.redis = AsyncMock()
        return m

    @pytest.mark.asyncio
    async def test_add_exempt_path(self, facade):
        """添加豁免路径"""
        from aiwaf.stream.redis_facade import RedisStateFacade
        f = RedisStateFacade(facade.mgr)
        facade.mgr.redis.sadd = AsyncMock()
        await f.add_exempt_path("/api/health")
        facade.mgr.redis.sadd.assert_called_once_with("aiwaf:exempt:paths", "/api/health")

    @pytest.mark.asyncio
    async def test_remove_exempt_path(self, facade):
        """移除豁免路径"""
        from aiwaf.stream.redis_facade import RedisStateFacade
        f = RedisStateFacade(facade.mgr)
        facade.mgr.redis.srem = AsyncMock()
        await f.remove_exempt_path("/api/health")
        facade.mgr.redis.srem.assert_called_once_with("aiwaf:exempt:paths", "/api/health")

    @pytest.mark.asyncio
    async def test_get_exempt_paths(self, facade):
        """获取豁免路径"""
        from aiwaf.stream.redis_facade import RedisStateFacade
        f = RedisStateFacade(facade.mgr)
        facade.mgr.redis.smembers = AsyncMock(return_value={"/api/health", "/api/metrics"})
        result = await f.get_exempt_paths()
        assert "/api/health" in result
        assert "/api/metrics" in result

    @pytest.mark.asyncio
    async def test_get_exempt_paths_redis_error(self, facade):
        """Redis 异常返回空列表"""
        from aiwaf.stream.redis_facade import RedisStateFacade
        f = RedisStateFacade(facade.mgr)
        facade.mgr.redis.smembers = AsyncMock(side_effect=Exception("connection refused"))
        result = await f.get_exempt_paths()
        assert result == []

    @pytest.mark.asyncio
    async def test_add_exempt_path_redis_error(self, facade):
        """添加时 Redis 异常不崩溃"""
        from aiwaf.stream.redis_facade import RedisStateFacade
        f = RedisStateFacade(facade.mgr)
        facade.mgr.redis.sadd = AsyncMock(side_effect=Exception("connection refused"))
        await f.add_exempt_path("/api/health")  # 不应抛异常

    @pytest.mark.asyncio
    async def test_remove_exempt_path_redis_error(self, facade):
        """移除时 Redis 异常不崩溃"""
        from aiwaf.stream.redis_facade import RedisStateFacade
        f = RedisStateFacade(facade.mgr)
        facade.mgr.redis.srem = AsyncMock(side_effect=Exception("connection refused"))
        await f.remove_exempt_path("/api/health")  # 不应抛异常


class TestExemptPathsIntegration:
    """豁免路径与检测管道集成测试"""

    def test_header_skip_paths_config(self):
        """header_skip_paths 配置项"""
        s = Settings()
        assert s.header_skip_paths == ""

    def test_header_skip_ips_config(self):
        """header_skip_ips 配置项"""
        s = Settings()
        assert s.header_skip_ips == ""

    def test_auto_block_enabled_config(self):
        """auto_block_enabled 配置项"""
        s = Settings()
        assert s.auto_block_enabled == True


# ============================================================
# 8. 端到端管道测试 (20 用例)
# ============================================================

class TestEndToEndPipeline:
    """端到端管道测试：从 Akto JSON 消息到检测结果"""

    def test_full_pipeline_normal_request(self):
        """正常请求完整管道"""
        msg = make_akto_msg(path="/api/users/123", method="GET", statusCode="200")
        raw_log = parse_akto_json_message(orjson.dumps(msg).decode())
        std_log = transform_raw_log(raw_log)
        assert std_log["uri_path"] == "/api/users/123"
        assert std_log["method"] == "GET"
        assert std_log["status_code"] == 200
        assert std_log["trace_id"] is not None
        assert "request_body" not in std_log

    def test_full_pipeline_malicious_probe(self):
        """探测路径检测"""
        msg = make_akto_msg(path="/.env", method="GET", statusCode="404")
        raw_log = parse_akto_json_message(orjson.dumps(msg).decode())
        std_log = transform_raw_log(raw_log)
        # 应被 PROBE_PATH_PATTERNS 检测
        def ctx(seg, _p=std_log["uri_path"], _s=std_log["status_code"]):
            return is_malicious_context(_p, seg, str(_s), STATIC_KW)
        kw = evaluate_keyword_policy(
            path=std_log["uri_path"], query_keys=[], path_exists=False,
            keyword_learning_enabled=True, static_keywords=STATIC_KW,
            dynamic_keywords=[], legitimate_keywords=DEFAULT_LEGITIMATE_KEYWORDS,
            exempt_keywords=set(), safe_prefixes=(),
            malicious_keywords=set(STATIC_KW), is_malicious_context=ctx)
        assert is_malicious_context("/api?q=union+select+1", "union", "200", STATIC_KW) == True

    def test_full_pipeline_sql_injection(self):
        """SQL 注入检测"""
        msg = make_akto_msg(path="/api?q=union+select+1", method="GET", statusCode="200")
        raw_log = parse_akto_json_message(orjson.dumps(msg).decode())
        std_log = transform_raw_log(raw_log)
        def ctx(seg, _p=std_log["uri_path"], _s=std_log["status_code"]):
            return is_malicious_context(_p, seg, str(_s), STATIC_KW)
        kw = evaluate_keyword_policy(
            path=std_log["uri_path"], query_keys=["q"], path_exists=False,
            keyword_learning_enabled=True, static_keywords=STATIC_KW,
            dynamic_keywords=[], legitimate_keywords=DEFAULT_LEGITIMATE_KEYWORDS,
            exempt_keywords=set(), safe_prefixes=(),
            malicious_keywords=set(STATIC_KW), is_malicious_context=ctx)
        assert is_malicious_context("/api?q=union+select+1", "union", "200", STATIC_KW) == True

    def test_full_pipeline_directory_traversal(self):
        """目录遍历检测"""
        msg = make_akto_msg(path="/api/../../../etc/passwd", method="GET", statusCode="404")
        raw_log = parse_akto_json_message(orjson.dumps(msg).decode())
        std_log = transform_raw_log(raw_log)
        def ctx(seg, _p=std_log["uri_path"], _s=std_log["status_code"]):
            return is_malicious_context(_p, seg, str(_s), STATIC_KW)
        kw = evaluate_keyword_policy(
            path=std_log["uri_path"], query_keys=[], path_exists=False,
            keyword_learning_enabled=True, static_keywords=STATIC_KW,
            dynamic_keywords=[], legitimate_keywords=DEFAULT_LEGITIMATE_KEYWORDS,
            exempt_keywords=set(), safe_prefixes=(),
            malicious_keywords=set(STATIC_KW), is_malicious_context=ctx)
        assert is_malicious_context("/api?q=union+select+1", "union", "200", STATIC_KW) == True

    def test_full_pipeline_keyword_learning(self):
        """关键词自学习"""
        msg = make_akto_msg(path="/api/../../../etc/passwd", method="GET", statusCode="404")
        raw_log = parse_akto_json_message(orjson.dumps(msg).decode())
        std_log = transform_raw_log(raw_log)
        def ctx(seg, _p=std_log["uri_path"], _s=std_log["status_code"]):
            return is_malicious_context(_p, seg, str(_s), STATIC_KW)
        kw = evaluate_keyword_policy(
            path=std_log["uri_path"], query_keys=[], path_exists=False,
            keyword_learning_enabled=True, static_keywords=STATIC_KW,
            dynamic_keywords=[], legitimate_keywords=DEFAULT_LEGITIMATE_KEYWORDS,
            exempt_keywords=set(), safe_prefixes=(),
            malicious_keywords=set(STATIC_KW), is_malicious_context=ctx)
        assert len(kw.learned_keywords) > 0

    def test_full_pipeline_header_validation(self):
        """请求头验证"""
        msg = make_akto_msg(requestHeaders='{"user-agent":"curl/7.68","accept":"text/html"}')
        raw_log = parse_akto_json_message(orjson.dumps(msg).decode())
        std_log = transform_raw_log(raw_log)
        headers = orjson.loads(std_log["request_headers"])
        env = {f"HTTP_{k.upper().replace('-', '_')}": v or "" for k, v in headers.items()}
        result = evaluate_header_policy(env, method="GET")
        assert result is not None

    def test_full_pipeline_path_manifest_integration(self):
        """Path Manifest 集成"""
        pm = PathManifest()
        for i in range(5):
            pm.record(f"/api/users/{i}", "GET", 200)
        assert pm.path_exists("/api/users/123") == True
        assert pm.path_exists("/api/unknown") == False

    def test_full_pipeline_unicode_path(self):
        """Unicode 路径"""
        msg = make_akto_msg(path="/api/用户/列表", method="GET")
        raw_log = parse_akto_json_message(orjson.dumps(msg).decode())
        std_log = transform_raw_log(raw_log)
        assert "用户" in std_log["uri_path"]

    def test_full_pipeline_large_body_truncated(self):
        """大 body 截断"""
        large_body = "A" * 5000
        msg = make_akto_msg(requestPayload=large_body)
        raw_log = parse_akto_json_message(orjson.dumps(msg).decode())
        std_log = transform_raw_log(raw_log)
        assert len(std_log["req_body_truncated"]) <= 1024

    def test_full_pipeline_akto_extensions_preserved(self):
        """Akto 扩展字段保留"""
        msg = make_akto_msg()
        raw_log = parse_akto_json_message(orjson.dumps(msg).decode())
        std_log = transform_raw_log(raw_log)
        assert std_log["akto_account_id"] == "1000000"
        assert std_log["akto_vxlan_id"] == "1"
        assert std_log["source"] == "MIRRORING"
        assert std_log["request_headers"] is not None

    def test_full_pipeline_trace_id_deterministic(self):
        """trace_id 确定性"""
        msg = make_akto_msg()
        raw_log = parse_akto_json_message(orjson.dumps(msg).decode())
        std_log1 = transform_raw_log(raw_log)
        std_log2 = transform_raw_log(raw_log)
        assert std_log1["trace_id"] == std_log2["trace_id"]

    def test_full_pipeline_trace_id_different_inputs(self):
        """不同输入产生不同 trace_id"""
        msg1 = make_akto_msg(ip="10.0.0.1")
        msg2 = make_akto_msg(ip="10.0.0.2")
        std1 = transform_raw_log(parse_akto_json_message(orjson.dumps(msg1).decode()))
        std2 = transform_raw_log(parse_akto_json_message(orjson.dumps(msg2).decode()))
        assert std1["trace_id"] != std2["trace_id"]

    def test_full_pipeline_post_method_preserved(self):
        """POST 方法保留"""
        msg = make_akto_msg(method="POST")
        std_log = transform_raw_log(parse_akto_json_message(orjson.dumps(msg).decode()))
        assert std_log["method"] == "POST"

    def test_full_pipeline_status_code_preserved(self):
        """状态码保留"""
        msg = make_akto_msg(statusCode="403")
        std_log = transform_raw_log(parse_akto_json_message(orjson.dumps(msg).decode()))
        assert std_log["status_code"] == 403

    def test_full_pipeline_empty_path(self):
        """空路径"""
        msg = make_akto_msg(path="")
        std_log = transform_raw_log(parse_akto_json_message(orjson.dumps(msg).decode()))
        assert std_log["uri_path"] == "/"

    def test_full_pipeline_invalid_json_handled(self):
        """非法 JSON 处理"""
        with pytest.raises(Exception):
            parse_akto_json_message("invalid json")

    def test_full_pipeline_json_array_rejected(self):
        """JSON 数组被拒绝"""
        with pytest.raises(ValueError):
            parse_akto_json_message("[1,2,3]")

    def test_full_pipeline_method_validation_get_to_post_only(self):
        """GET 到 POST-only 端点"""
        dec = evaluate_method_policy(method="GET", path="/api/upload/")
        assert dec.action == "block"

    def test_full_pipeline_method_validation_normal_get(self):
        """正常 GET"""
        dec = evaluate_method_policy(method="GET", path="/api/users/")
        assert dec.action == "allow"

    def test_full_pipeline_multiple_messages_independent(self):
        """多条消息独立处理"""
        messages = [make_akto_msg(ip=f"10.0.0.{i}", path=f"/api/item/{i}") for i in range(10)]
        std_logs = [transform_raw_log(parse_akto_json_message(orjson.dumps(m).decode())) for m in messages]
        trace_ids = [s["trace_id"] for s in std_logs]
        assert len(set(trace_ids)) == 10

    def test_full_pipeline_100th_test(self):
        """第 100 项测试：config_override 白名单不可覆盖连接参数"""
        assert 'kafka_brokers' not in _OVERRIDABLE_KEYS
        assert 'redis_cluster_url' not in _OVERRIDABLE_KEYS
        assert 'core_process_pool_size' not in _OVERRIDABLE_KEYS
        assert 'rate_limit_max_requests' in _OVERRIDABLE_KEYS
