"""
AIWAF-Stream 异步流式检测引擎
"""
import asyncio
import ipaddress
import time
import orjson
from aiwaf.stream.asyncbreaker import CircuitBreaker, CircuitBreakerError
from concurrent.futures import ProcessPoolExecutor
from concurrent.futures.process import BrokenProcessPool
from typing import List
from aiokafka import AIOKafkaProducer, AIOKafkaConsumer
from prometheus_client import Counter

from aiwaf.stream.acl_bootstrap import init_worker, run_core_logic_batch_isolated, ItemErrorResult
from aiwaf.stream.redis_facade import (
    RedisStateFacade, RedisClusterStateManager, init_fail_secure,
    local_blacklist, local_rate_limit,
    _current_buffer, _backup_buffer, background_sync_worker
)
# 注意: local_blacklist, local_rate_limit, _current_buffer, _backup_buffer
# 会被 init_fail_secure() 重新赋值，因此需要通过模块引用访问
import aiwaf.stream.redis_facade as _rf_mod
from aiwaf.core.rate_limit import FLOOD_BLOCK
from aiwaf.stream.akto_adapter import parse_akto_json_message
from aiwaf.stream.preprocessor import transform_raw_log, init_body_limits
from aiwaf.core.path_manifest import PathManifest
from aiwaf.core.header_validation import evaluate_header_policy
from aiwaf.core.uuid_tamper import record_uuid_signal, is_malformed_uuid, collect_uuid_model_fields
from aiwaf.core.geo_policy import evaluate_geo_policy
from aiwaf.core.geoip import lookup_country_name, GEOIP_AVAILABLE
from aiwaf.core.exemptions import should_apply_middleware_for_path
from aiwaf.core.method_validation import evaluate_method_policy
from aiwaf.stream.config_override import ConfigOverride

METRIC_ENGINE_IN = Counter('aiwaf_engine_in_total', 'Logs received')
METRIC_DLQ_OUT = Counter('aiwaf_dlq_out_total', 'Messages routed to DLQ')
METRIC_POOL_FATAL = Counter('aiwaf_pool_fatal_total', 'ProcessPool broken count')


class AIWAFStreamEngine:
    def __init__(self, settings, state_mgr: RedisClusterStateManager, model_path: str):
        self.settings = settings
        self.facade = RedisStateFacade(state_mgr)
        self.model_path = model_path

        # 根据 settings 初始化 Fail-Secure 全局对象
        init_fail_secure(settings)

        # 根据 settings 初始化 Body 截断阈值
        init_body_limits(
            max_hash_bytes=settings.max_body_hash_bytes,
            max_store_bytes=settings.max_body_store_bytes,
        )

        # 根据 settings 追加预定义特征（模块变量覆盖，不替换默认值）
        self._apply_extra_patterns(settings)

    def _apply_extra_patterns(self, settings):
        """将配置中的特征合并到模块常量（追加或替换模式）"""
        import aiwaf.core.ip_keyword as ip_kw
        import aiwaf.core.malicious_context as mc
        import aiwaf.core.honeypot as hp

        # STATIC_KW
        if settings.static_keywords_extra:
            extra = [s.strip() for s in settings.static_keywords_extra.split(",") if s.strip()]
            if settings.static_keywords_replace_mode:
                mc.STATIC_KW = extra
            else:
                mc.STATIC_KW = list(mc.STATIC_KW) + extra

        # DEFAULT_LEGITIMATE_KEYWORDS
        if settings.legitimate_keywords_extra:
            extra = set(s.strip() for s in settings.legitimate_keywords_extra.split(",") if s.strip())
            if settings.legitimate_keywords_replace_mode:
                mc.DEFAULT_LEGITIMATE_KEYWORDS = extra
            else:
                mc.DEFAULT_LEGITIMATE_KEYWORDS = mc.DEFAULT_LEGITIMATE_KEYWORDS | extra

        # INHERENTLY_MALICIOUS_PATTERNS
        if settings.inherently_malicious_extra:
            extra = tuple(s.strip() for s in settings.inherently_malicious_extra.split(",") if s.strip())
            if settings.inherently_malicious_replace_mode:
                ip_kw.INHERENTLY_MALICIOUS_PATTERNS = extra
            else:
                ip_kw.INHERENTLY_MALICIOUS_PATTERNS = ip_kw.INHERENTLY_MALICIOUS_PATTERNS + extra

        # VERY_STRONG_ATTACK_PATTERNS
        if settings.very_strong_attacks_extra:
            extra = tuple(s.strip() for s in settings.very_strong_attacks_extra.split(",") if s.strip())
            if settings.very_strong_attacks_replace_mode:
                ip_kw.VERY_STRONG_ATTACK_PATTERNS = extra
            else:
                ip_kw.VERY_STRONG_ATTACK_PATTERNS = ip_kw.VERY_STRONG_ATTACK_PATTERNS + extra

        # PROBE_PATH_PATTERNS（编译为正则）
        if settings.probe_path_patterns_extra:
            import re
            extra = tuple(re.compile(p.strip()) for p in settings.probe_path_patterns_extra.split(",") if p.strip())
            if settings.probe_path_patterns_replace_mode:
                ip_kw.PROBE_PATH_PATTERNS = extra
            else:
                ip_kw.PROBE_PATH_PATTERNS = ip_kw.PROBE_PATH_PATTERNS + extra

        # OBVIOUS_POST_ONLY_SUFFIXES
        if settings.post_only_suffixes_extra:
            extra = tuple(s.strip() for s in settings.post_only_suffixes_extra.split(",") if s.strip())
            if settings.post_only_suffixes_replace_mode:
                hp.OBVIOUS_POST_ONLY_SUFFIXES = extra
            else:
                hp.OBVIOUS_POST_ONLY_SUFFIXES = hp.OBVIOUS_POST_ONLY_SUFFIXES + extra

        # LOGIN_PATH_PREFIXES
        if settings.login_paths_extra:
            extra = tuple(s.strip() for s in settings.login_paths_extra.split(",") if s.strip())
            if settings.login_paths_replace_mode:
                hp.LOGIN_PATH_PREFIXES = extra
            else:
                hp.LOGIN_PATH_PREFIXES = hp.LOGIN_PATH_PREFIXES + extra

        # 同步更新 acl_bootstrap 中的引用（子进程 import 快照问题）
        import aiwaf.stream.acl_bootstrap as ab
        ab.STATIC_KW = mc.STATIC_KW
        ab.DEFAULT_LEGITIMATE_KEYWORDS = mc.DEFAULT_LEGITIMATE_KEYWORDS

        self.core_executor = ProcessPoolExecutor(
            max_workers=settings.core_process_pool_size,
            max_tasks_per_child=settings.max_tasks_per_child,
            initializer=init_worker,
            initargs=(self.model_path,)
        )
        self.batch_queue = asyncio.Queue(maxsize=settings.batch_queue_maxsize)

        self.producer = AIOKafkaProducer(
            bootstrap_servers=settings.kafka_brokers,
            enable_idempotence=settings.kafka_enable_idempotence,
            acks=settings.kafka_acks
        )

        self.dynamic_keywords_cache: List[str] = []
        self._tasks: list = []
        self._cancel_event = asyncio.Event()
        self.consumer = None
        self.path_manifest = PathManifest()
        self.config_override = ConfigOverride(self.facade)
        self._path_rules = self._parse_path_rules(settings.path_rules)

    def _parse_path_rules(self, rules_str: str) -> list:
        """解析 path_rules JSON 字符串为规则列表"""
        if not rules_str:
            return []
        try:
            import json
            rules = json.loads(rules_str)
            return rules if isinstance(rules, list) else []
        except Exception:
            return []

    async def start(self):
        await self.producer.start()

        # Consumer（新增：消费 Akto Kafka 流量）
        self.consumer = AIOKafkaConsumer(
            self.settings.input_topic,
            bootstrap_servers=self.settings.kafka_brokers,
            group_id=self.settings.consumer_group,
            value_deserializer=lambda v: v,
            key_deserializer=lambda v: v.decode('utf-8') if v else None,
            auto_offset_reset=self.settings.kafka_auto_offset_reset,
            enable_auto_commit=False,
            max_poll_records=self.settings.kafka_max_poll_records,
        )
        await self.consumer.start()

        self._tasks.append(asyncio.create_task(self._batch_dispatcher()))
        self._tasks.append(asyncio.create_task(
            background_sync_worker(self.facade.mgr, self._cancel_event, self.settings.background_sync_interval)
        ))
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
        """后台独立 Task 定时刷新缓存"""
        interval = self.settings.keyword_refresh_interval
        while not self._cancel_event.is_set():
            try:
                self.dynamic_keywords_cache = await self.facade.get_top_keywords(self.settings.keyword_top_n)
            except (CircuitBreakerError, OSError, asyncio.TimeoutError):
                pass
            try:
                await asyncio.wait_for(
                    asyncio.sleep(interval),
                    timeout=interval,
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
                        async with asyncio.timeout(self.settings.batch_timeout_ms / 1000):
                            while len(batch_logs) < self.settings.batch_max_size:
                                item = await self.batch_queue.get()
                                batch_logs.append(item['log']); batch_ts.append(item['ts'])
                                batch_et.append(item['et']); batch_futures.append(item['future'])
                    except asyncio.TimeoutError:
                        pass

                current_kws = self.dynamic_keywords_cache

                loop = asyncio.get_running_loop()
                # 传入已知路径模板集（用于 path_exists 判定）
                known_paths = self.path_manifest.get_all_templates()
                flood_threshold = await self.config_override.get_async("rate_limit_flood_threshold", self.settings.rate_limit_flood_threshold)
                rl_window = await self.config_override.get_async("rate_limit_window", self.settings.rate_limit_window)
                rl_max_req = await self.config_override.get_async("rate_limit_max_requests", self.settings.rate_limit_max_requests)

                # AI 异常检测：从 Redis 加载 IP 历史窗口
                ip_histories = {}
                if self.settings.ai_anomaly_enabled and redis_available:
                    unique_ips = set()
                    for log_bytes in batch_logs:
                        try:
                            sl = orjson.loads(log_bytes)
                            unique_ips.add(sl.get("client_ip", ""))
                        except Exception:
                            pass
                    for ip in unique_ips:
                        if ip:
                            ip_histories[ip] = await self.facade.get_ip_history(ip)

                batch_results = await loop.run_in_executor(
                    self.core_executor, run_core_logic_batch_isolated,
                    batch_logs, batch_ts, batch_et, current_kws,
                    (), None, None, (), None,
                    flood_threshold, True, known_paths,
                    rl_window, rl_max_req,
                    self.settings.ai_anomaly_enabled,
                    self.settings.ai_anomaly_window,
                    ip_histories if ip_histories else None,
                )

                # AI 异常检测：将更新后的 IP 历史写回 Redis
                if self.settings.ai_anomaly_enabled and redis_available and ip_histories:
                    for ip, hist in ip_histories.items():
                        if hist:
                            await self.facade.set_ip_history(ip, hist, self.settings.ai_anomaly_window)
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
                    max_tasks_per_child=self.settings.max_tasks_per_child,
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
        uri_path = std_log.get("uri_path", "/")

        # 记录路径到 Path Manifest（用于 path_exists 判定）
        self.path_manifest.record(
            path=std_log.get("uri_path", "/"),
            method=std_log.get("method", "GET"),
            status_code=std_log.get("status_code", 0),
        )

        # ── 请求头验证 ──
        # 跳过豁免 IP（支持 CIDR）+ 按路径规则跳过 + 全局开关
        raw_headers = std_log.get("request_headers", "")
        header_skip_ips = await self.config_override.get_async("header_skip_ips", self.settings.header_skip_ips)
        header_skip_paths = await self.config_override.get_async("header_skip_paths", self.settings.header_skip_paths)
        header_enabled = self.settings.detection_header_enabled and should_apply_middleware_for_path(uri_path, self._path_rules, "header_validation")
        if raw_headers and header_enabled and self._should_check_header(ip, uri_path, header_skip_ips, header_skip_paths):
            try:
                headers_dict = orjson.loads(raw_headers) if isinstance(raw_headers, str) else raw_headers
                # 转为 WSGI environ 格式（evaluate_header_policy 期望的输入）
                environ = {}
                for k, v in headers_dict.items():
                    wsgi_key = f"HTTP_{k.upper().replace('-', '_')}"
                    environ[wsgi_key] = v or ""

                # 从配置构建必需头列表
                required = [f"HTTP_{h.strip().upper().replace('-', '_')}"
                            for h in self.settings.header_required.split(",") if h.strip()] or None

                # 自定义可疑 UA / 合法爬虫
                suspicious_ua = self.settings.header_suspicious_ua.split(",") if self.settings.header_suspicious_ua else None
                legit_bots = self.settings.header_legitimate_bots.split(",") if self.settings.header_legitimate_bots else None

                header_dec = evaluate_header_policy(
                    environ,
                    method=std_log.get("method", "GET"),
                    config_required_headers=required,
                    max_header_bytes=self.settings.header_max_bytes,
                    max_header_count=self.settings.header_max_count,
                    max_user_agent_length=self.settings.header_max_ua_length,
                    max_accept_length=self.settings.header_max_accept_length,
                    suspicious_user_agents=suspicious_ua,
                    legitimate_bots=legit_bots,
                )
                if header_dec:  # 返回字符串=block reason, None=允许
                    try:
                        await self._emit_alert(std_log, f"HeaderBlock:{header_dec}")
                    except Exception:
                        pass
                    return
            except Exception:
                pass

        # ── 路径豁免检查（配置 + 运行时 Redis）──
        # 注意：uri_path 已在函数开头赋值，此处不再重复赋值
        skip_paths = [s.strip() for s in self.settings.header_skip_paths.split(",") if s.strip()]
        for prefix in skip_paths:
            if uri_path.startswith(prefix):
                return  # 豁免路径跳过所有检测

        # ── UUID 篡改检测 ──
        # 全局开关 + 按路径规则跳过
        if self.settings.detection_uuid_enabled and should_apply_middleware_for_path(uri_path, self._path_rules, "uuid_tamper"):
            path_segments = uri_path.strip("/").split("/")
            for seg in path_segments:
                # 只检查 36 字符且含 dash 的段（UUID 格式特征）
                if len(seg) == 36 and seg.count('-') >= 4 and is_malformed_uuid(seg):
                    try:
                        record_uuid_signal(ip, "malformed_uuid", config={
                            "block_threshold": self.settings.uuid_block_threshold,
                            "malformed_weight": self.settings.uuid_malformed_weight,
                            "not_found_weight": self.settings.uuid_not_found_weight,
                            "success_decay": self.settings.uuid_success_decay,
                            "window_seconds": self.settings.uuid_window_seconds,
                        })
                        try:
                            await self._emit_alert(std_log, "UUIDTamper:malformed_uuid")
                        except Exception:
                            pass
                    except Exception:
                        pass
                    break

        # ── 地理围栏 (GeoIP) ──
        if self.settings.detection_geo_enabled and self.settings.geoip_db_path and GEOIP_AVAILABLE and should_apply_middleware_for_path(uri_path, self._path_rules, "geo_block"):
            try:
                country = lookup_country_name(ip, self.settings.geoip_db_path)
                if country:
                    geo_dec = evaluate_geo_policy(
                        country=country,
                        allow_countries=set(s for s in self.settings.geo_allow_countries.split(",") if s) if self.settings.geo_allow_countries else set(),
                        block_countries=set(s for s in self.settings.geo_block_countries.split(",") if s) if self.settings.geo_block_countries else set(),
                        dynamic_blocked=[],
                    )
                    if geo_dec.block:
                        try:
                            await self._emit_alert(std_log, f"GeoBlock:{country}")
                        except Exception:
                            pass
                        return
            except Exception:
                pass

        # ── HTTP 方法验证 ──
        if self.settings.detection_method_enabled and should_apply_middleware_for_path(uri_path, self._path_rules, "method_validation"):
            method = std_log.get("method", "GET")
            method_u = (method or "").upper()
            # GET→POST-only 检测（无误报风险，默认开启）
            # 不支持的方法检测（PUT/PATCH/DELETE 可能误报，默认关闭）
            check_post_only = self.settings.detection_method_post_only
            check_unsupported = self.settings.detection_method_unsupported
            if method_u == "GET" and check_post_only:
                from aiwaf.core.honeypot import should_block_get_to_post_only_endpoint
                if should_block_get_to_post_only_endpoint(uri_path, accepts_get=False):
                    try:
                        await self._emit_alert(std_log, f"MethodBlock:GET to POST-only endpoint: {uri_path}")
                    except Exception:
                        pass
                    return
            elif method_u not in ("GET", "POST", "HEAD", "OPTIONS") and check_unsupported:
                try:
                    await self._emit_alert(std_log, f"MethodBlock:Unsupported method {method_u} for {uri_path}")
                except Exception:
                    pass
                return

        redis_available = True
        try:
            import logging as _lg
            if await self.facade.is_duplicate_and_add(trace_id, is_retry, retry_count):
                return
            if self.settings.detection_rate_limit_enabled:
                timestamps = await self.facade.get_and_update_rate_limit(
                    ip, event_time,
                    await self.config_override.get_async("rate_limit_window", self.settings.rate_limit_window),
                    await self.config_override.get_async("rate_limit_max_requests", self.settings.rate_limit_max_requests),
                )
            else:
                timestamps = []
        except CircuitBreakerError:
            redis_available = False
            # Fail-Secure 本地防线（可全局关闭）
            if not self.settings.detection_fail_secure_enabled:
                return
            if ip in _rf_mod.local_blacklist or ip in _rf_mod._current_buffer or ip in _rf_mod._backup_buffer:
                try:
                    await self._emit_alert(std_log, "Local_Blacklist_Block")
                except Exception:
                    pass
                return

            _rf_mod.local_rate_limit[ip] = _rf_mod.local_rate_limit.get(ip, 0) + 1
            fail_secure_limit = await self.config_override.get_async("fail_secure_local_limit", self.settings.fail_secure_local_limit)
            if _rf_mod.local_rate_limit[ip] > fail_secure_limit:
                auto_block = await self.config_override.get_async("auto_block_enabled", self.settings.auto_block_enabled)
                if auto_block:
                    _rf_mod.local_blacklist[ip] = True
                    _rf_mod._backup_buffer.append(ip)
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
            auto_block = await self.config_override.get_async("auto_block_enabled", self.settings.auto_block_enabled)
            if redis_available and auto_block and result.side_effects.get('blocked_ips'):
                asyncio.create_task(self.facade.batch_block_ips(result.side_effects.get('blocked_ips', [])))
            try:
                await self._route_to_dlq(std_log, Exception(f"{result.error_type}: {result.error_msg}"))
            except Exception:
                pass
            return

        if redis_available:
            auto_block = await self.config_override.get_async("auto_block_enabled", self.settings.auto_block_enabled)
            auto_learn = await self.config_override.get_async("auto_learn_keywords", self.settings.auto_learn_keywords)
            if auto_block and result.side_effects.get('blocked_ips'):
                asyncio.create_task(self.facade.batch_block_ips(result.side_effects.get('blocked_ips', [])))
            if auto_learn and result.side_effects.get('learned_keywords'):
                asyncio.create_task(self._batch_add_keywords(result.side_effects.get('learned_keywords', [])))

        if self.settings.detection_rate_limit_enabled and result.rl_decision.action == FLOOD_BLOCK:
            try:
                await self._emit_alert(std_log, "RateLimitFlood")
            except Exception:
                pass
        elif self.settings.detection_keyword_enabled and result.kw_decision.block_reason:
            try:
                await self._emit_alert(std_log, f"KeywordBlock:{result.kw_decision.block_reason}")
            except Exception:
                pass
        elif self.settings.ai_anomaly_enabled and result.side_effects.get('ai_anomaly_block'):
            try:
                await self._emit_alert(std_log, f"AIAnomaly:{result.side_effects['ai_anomaly_block']}")
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
        # ── V6.0 补丁：提取 country_code（GeoIP 查询） ──
        # country_code 用于 MaliciousEventMessage.metadata.country_code
        # 仅当 GeoIP 数据库可用时查询，避免性能损耗
        country_code = ""
        if (self.settings.geoip_db_path and GEOIP_AVAILABLE
                and self.settings.detection_geo_enabled):
            try:
                ip = std_log.get("client_ip", "")
                if ip:
                    country_code = lookup_country_name(ip, self.settings.geoip_db_path) or ""
            except Exception as e:
                # 审计修复 #2：GeoIP 查询异常不再静默吞没，记录警告日志
                import logging as _logging
                _logging.getLogger("aiwaf.engine").warning(
                    "GeoIP 查询异常: %s, ip=%s", e, std_log.get("client_ip", "")
                )

        alert = {
            # 现有字段
            "trace_id": std_log.get("trace_id"),
            "request_uuid": std_log.get("request_uuid", ""),  # 源端 UUID（可选，用于外部系统关联）
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

            # ── V6.0 新增字段：供 V6.0 出站适配器使用 ──
            # api_collection_id: 原生 Collection ID（int32），透传至 latest_api_collection_id (字段 7)
            "api_collection_id": std_log.get("api_collection_id", 0),
            # request_headers: 请求头（JSON 字符串），用于 Raw HTTP 重构
            "request_headers": std_log.get("request_headers", ""),
            # host: 请求 Host，透传至 MaliciousEventMessage.host (字段 17)
            "host": std_log.get("host", ""),
            # country_code: 源 IP 国家代码，透传至 metadata.country_code
            "country_code": country_code,
        }
        try:
            await self.producer.send_and_wait(self.settings.alert_topic, orjson.dumps(alert))
        except Exception as e:
            # 审计修复 #1：Kafka 发送异常不再静默吞没，记录错误日志
            import logging as _logging
            _logging.getLogger("aiwaf.engine").error(
                "告警发送到 Kafka 失败: %s, trace_id=%s, rule=%s",
                e, std_log.get("trace_id", ""), rule,
            )

    def _should_check_header(self, ip: str, path: str, skip_ips: str, skip_paths: str) -> bool:
        """判断是否需要对该 IP/路径进行请求头检查"""
        # 检查豁免 IP（支持 CIDR）
        skip_ip_list = [s.strip() for s in skip_ips.split(",") if s.strip()]
        if skip_ip_list:
            try:
                addr = ipaddress.ip_address(ip)
                for cidr in skip_ip_list:
                    if addr in ipaddress.ip_network(cidr, strict=False):
                        return False
            except (ValueError, OSError):
                if ip in skip_ip_list:
                    return False

        # 检查豁免路径前缀
        skip_path_list = [s.strip() for s in skip_paths.split(",") if s.strip()]
        for prefix in skip_path_list:
            if path.startswith(prefix):
                return False

        return True

    def _classify_severity(self, rule: str) -> str:
        """根据规则名称分类严重程度"""
        rule_lower = (rule or "").lower()
        if "flood" in rule_lower or "ratelimit" in rule_lower:
            return "MEDIUM"
        if "keyword" in rule_lower:
            return "HIGH"
        if "blacklist" in rule_lower:
            return "HIGH"
        if "header" in rule_lower:
            return "HIGH"
        if "uuid" in rule_lower:
            return "HIGH"
        if "geo" in rule_lower:
            return "MEDIUM"
        if "aianomaly" in rule_lower or "ai anomaly" in rule_lower:
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
                            raw_log = parse_akto_json_message(msg.value.decode('utf-8', errors='replace'))
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
                    await asyncio.sleep(self.settings.kafka_retry_interval)
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
        try:
            await self.producer.send_and_wait(self.settings.dlq_topic, orjson.dumps(dlq_payload))
        except Exception:
            pass
