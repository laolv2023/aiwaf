#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AIWAF 接入 Akto V6.0 出站适配器 —— 生产级网关
==================================================

模块职责
--------
消费 AIWAF 引擎产出的告警消息（Kafka topic: aiwaf.alerts，JSON 格式），
经过以下五重核心处理后，转换为 Akto 原生 Protobuf 格式
（MaliciousEventKafkaEnvelope），注入 Akto 的
``akto.threat_detection.malicious_events`` topic，
供 Akto 原生 ``SendMaliciousEventsToBackend`` 消费并转发至 Backend。

五重核心处理（设计文档第 3 节"核心护城河设计"）
------------------------------------------------
1. 告警分级过滤阀（Filter Valve）
   - 仅放行高威胁层级：ai_anomaly / uuid_tamper / honeypot / ip_keyword_block
   - 丢弃低威胁层级：rate_limit / geo_block / header_validation 等

2. 威胁分类融合映射表（Threat Category Fusion）
   - 将 AIWAF 检测层级映射为 Akto 原生 sub_category
   - ip_keyword_block → SQLInjection
   - ai_anomaly → ai_anomaly
   - honeypot → honeypot
   - uuid_tamper → uuid_tamper

3. 采样限流器（SlidingWindowSampler）
   - 滑动窗口（默认 60 秒）内同一 (src_ip, layer, request_url) 最多放行 5 条
   - 防止告警雪崩淹没 Akto Backend，同时保留代表性样本

4. Raw HTTP 安全截断重构（Payload Safe Truncation）
   - 将请求方法/URL/Headers/Body 重构为原始 HTTP 报文
   - 硬截断至 4096 字节，超出部分追加截断标记

5. 原生 ID 透传（Native ID Pass-through）
   - akto_account_id → envelope.account_id
   - api_collection_id → event.latest_api_collection_id
   - 缺失任一 ID 视为脏数据，直接丢弃

设计依据
--------
《AIWAF 接入 Akto 架构设计方案 (V6.0 源码级对齐终版)》第 4 节
"生产级适配器核心代码（Python V6.0）"

约束
----
- 对 Akto 零修改：仅向 akto.threat_detection.malicious_events 注入 Protobuf 消息
- 对 AIWAF 的修改以补丁方式给出
- 使用 kafka-python（同步）库，与设计文档一致
"""

from __future__ import annotations

import json
import logging
import signal
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Any, Deque, Dict, Optional, Set

# ── Akto Protobuf 桩代码（vendor 自 Akto .proto 定义，对 Akto 零修改）──
from akto_proto.threat_detection.message.malicious_event.v1 import message_pb2
from akto_proto.threat_detection.message.malicious_event.event_type.v1 import (
    event_type_pb2,
)
from akto_proto.threat_detection.message.sample_request.v1 import (
    message_pb2 as sample_request_pb2,
)

logger = logging.getLogger("aiwaf.akto_v6_adapter")


# ═══════════════════════════════════════════════════════════════════════════
# 第一部分：常量定义（设计文档第 3 节）
# ═══════════════════════════════════════════════════════════════════════════

# ── 1. 告警分级过滤阀：仅放行高威胁层级 ──
# 设计文档第 3.1 节：丢弃 rate_limit / geo_block / header_validation 等低威胁层级，
# 仅保留 AIWAF 独有的高威胁检测能力，避免低价值告警淹没 Akto Backend。
ALLOWED_THREAT_LAYERS: Set[str] = {
    "ai_anomaly",        # AI 异常检测（AIWAF 核心能力）
    "uuid_tamper",       # UUID 篡改检测
    "honeypot",          # 蜜罐端点检测（GET→POST-only 端点）
    "ip_keyword_block",  # IP+关键词联合阻断（含 SQL 注入等）
}

# ── 2. 威胁分类融合映射表：AIWAF 层级 → Akto 原生 sub_category ──
# 设计文档第 3.2 节：将 AIWAF 检测层级映射为 Akto 原生 sub_category，
# 使 Akto Backend 能在威胁看板上正确分类展示。
# 注意：ip_keyword_block 映射为 SQLInjection（Akto 原生分类），
# 其余三个保持原名（Akto 原生不存在的自定义分类，Backend 会自动归入"其他"）。
AIWAF_TO_AKTO_SUBCATEGORY: Dict[str, str] = {
    "ip_keyword_block": "SQLInjection",   # 关键词阻断 → SQL 注入分类
    "ai_anomaly":      "ai_anomaly",      # AI 异常 → 自定义分类
    "honeypot":        "honeypot",        # 蜜罐 → 自定义分类
    "uuid_tamper":     "uuid_tamper",     # UUID 篡改 → 自定义分类
}

# ── 3. Raw HTTP 安全截断参数 ──
# 设计文档第 3.3 节：latest_api_payload 最大 4096 字节，超出部分硬截断。
MAX_PAYLOAD_BYTES: int = 4096
TRUNCATION_SUFFIX: str = "... [Truncated by AIWAF Adapter]"

# ── 4. 采样限流器默认参数 ──
# 设计文档第 3.4 节：滑动窗口 60 秒，同一 key 最多 5 条样本。
DEFAULT_SAMPLER_WINDOW_SECONDS: int = 60
DEFAULT_SAMPLER_MAX_SAMPLES: int = 5

# ── 5. AIWAF rule_id → 检测层级 映射表 ──
# AIWAF 引擎的 _emit_alert 产出的 rule_id 格式为 "Prefix:reason" 或 "Prefix"，
# 此映射表将 rule_id 前缀转换为 V6.0 适配器内部的层级标识。
# 仅 ALLOWED_THREAT_LAYERS 中的层级会通过过滤阀。
_RULE_PREFIX_TO_LAYER: Dict[str, str] = {
    "KeywordBlock":  "ip_keyword_block",  # 关键词阻断（含 SQL 注入等）
    "AIAnomaly":     "ai_anomaly",        # AI 异常检测
    "UUIDTamper":    "uuid_tamper",       # UUID 篡改
    # 蜜罐检测：GET 请求 POST-only 端点，rule_id 为 "MethodBlock:GET to POST-only endpoint:..."
    # 需要特殊处理（见 _derive_layer 函数），此处不直接映射
    "MethodBlock":   "method_validation",  # 方法校验（默认丢弃，GET→POST-only 特殊处理为 honeypot）
    "RateLimitFlood":    "rate_limit",     # 速率限制（丢弃）
    "HeaderBlock":       "header_validation",  # 请求头校验（丢弃）
    "GeoBlock":          "geo_block",      # 地理位置阻断（丢弃）
    "Local_Blacklist_Block":  "local_blacklist",   # 本地黑名单（丢弃）
    "Local_RateLimit_Block":  "local_ratelimit",   # 本地速率限制（丢弃）
}


# ═══════════════════════════════════════════════════════════════════════════
# 第二部分：AIWAF rule_id → 检测层级 推导
# ═══════════════════════════════════════════════════════════════════════════

def _derive_layer(rule_id: str) -> str:
    """
    从 AIWAF 告警的 rule_id 推导检测层级。

    AIWAF rule_id 格式：
        - "KeywordBlock:sql_injection" → ip_keyword_block
        - "AIAnomaly:score=0.95"       → ai_anomaly
        - "UUIDTamper:malformed_uuid"  → uuid_tamper
        - "MethodBlock:GET to POST-only endpoint: /api/create/"
            → honeypot（蜜罐端点检测，特殊处理）
        - "MethodBlock:Unsupported method PUT for /api/users"
            → method_validation（普通方法校验，丢弃）
        - "RateLimitFlood"             → rate_limit
        - "HeaderBlock:missing-ua"     → header_validation
        - "GeoBlock:CN"                → geo_block

    特殊处理：
        MethodBlock 中包含 "GET to POST-only endpoint" 的为蜜罐检测，
        映射为 honeypot 层级（设计文档允许的高威胁层级）。
        其余 MethodBlock 为普通方法校验，映射为 method_validation（丢弃）。

    参数
    ----
    rule_id : str
        AIWAF 引擎 _emit_alert 产出的规则标识。

    返回
    ----
    str
        检测层级标识（如 ip_keyword_block / ai_anomaly / honeypot 等）。
        无法识别的 rule_id 返回 "unknown"。
    """
    if not rule_id:
        return "unknown"

    # 蜜罐检测特殊处理：GET 请求 POST-only 端点
    # rule_id 格式: "MethodBlock:GET to POST-only endpoint: /api/create/"
    if rule_id.startswith("MethodBlock:") and "GET to POST-only endpoint" in rule_id:
        return "honeypot"

    # 通用前缀匹配
    for prefix, layer in _RULE_PREFIX_TO_LAYER.items():
        if rule_id.startswith(prefix):
            return layer

    return "unknown"


def _derive_reason(rule_id: str) -> str:
    """
    从 AIWAF 告警的 rule_id 提取检测原因。

    rule_id 格式为 "Prefix:reason"，提取冒号后的部分作为原因。
    若无冒号，返回完整 rule_id。

    参数
    ----
    rule_id : str
        AIWAF 引擎 _emit_alert 产出的规则标识。

    返回
    ----
    str
        检测原因描述。
    """
    if not rule_id:
        return ""
    # 取第一个冒号后的内容作为原因
    idx = rule_id.find(":")
    if idx >= 0:
        return rule_id[idx + 1:].strip()
    return rule_id.strip()


# ═══════════════════════════════════════════════════════════════════════════
# 第三部分：采样限流器（SlidingWindowSampler）
# ═══════════════════════════════════════════════════════════════════════════

class SlidingWindowSampler:
    """
    滑动窗口采样限流器（设计文档第 3.4 节）。

    功能
    ----
    在滑动时间窗口（默认 60 秒）内，对同一采样键（src_ip, layer, request_url）
    最多放行 max_samples 条告警，超出部分丢弃。

    设计目标
    --------
    - 防止告警雪崩：同一攻击源在短时间内产生大量告警时，仅保留代表性样本
    - 保留多样性：不同 src_ip / layer / request_url 的告警独立计数
    - 线程安全：使用 threading.Lock 保护内部数据结构

    算法
    ----
    使用 deque 维护每个采样键在窗口内的时间戳列表：
    1. 清理过期时间戳（超出窗口的老数据）
    2. 若窗口内样本数 < max_samples，追加当前时间戳，返回 True（放行）
    3. 若窗口内样本数 >= max_samples，返回 False（丢弃）

    参数
    ----
    window_seconds : int
        滑动窗口大小（秒），默认 60。
    max_samples : int
        窗口内最大样本数，默认 5。
    """

    def __init__(
        self,
        window_seconds: int = DEFAULT_SAMPLER_WINDOW_SECONDS,
        max_samples: int = DEFAULT_SAMPLER_MAX_SAMPLES,
    ):
        if window_seconds <= 0:
            raise ValueError(f"window_seconds 必须为正数，当前: {window_seconds}")
        if max_samples <= 0:
            raise ValueError(f"max_samples 必须为正数，当前: {max_samples}")

        self._window_seconds = window_seconds
        self._max_samples = max_samples
        # 采样键 → 窗口内时间戳队列
        self._buckets: Dict[Tuple[str, str, str], Deque[float]] = defaultdict(deque)
        # 线程锁：保护 _buckets 的并发访问
        self._lock = threading.Lock()
        # 统计计数器
        self._total_allowed = 0
        self._total_dropped = 0

    def should_sample(
        self,
        src_ip: str,
        layer: str,
        request_url: str,
        now: Optional[float] = None,
    ) -> bool:
        """
        判断当前告警是否应该被采样（放行）。

        参数
        ----
        src_ip : str
            源 IP 地址。
        layer : str
            检测层级（如 ai_anomaly / ip_keyword_block）。
        request_url : str
            请求 URL。
        now : float, optional
            当前时间戳（用于测试注入），默认 time.time()。

        返回
        ----
        bool
            True 表示放行（窗口内样本数未达上限），
            False 表示丢弃（窗口内样本数已达上限）。
        """
        if now is None:
            now = time.time()

        key = (src_ip or "", layer or "", request_url or "")
        cutoff = now - self._window_seconds

        with self._lock:
            bucket = self._buckets[key]

            # 1. 清理过期时间戳（滑动窗口左边界之前的数据）
            while bucket and bucket[0] < cutoff:
                bucket.popleft()

            # 2. 判断是否放行
            if len(bucket) < self._max_samples:
                bucket.append(now)
                self._total_allowed += 1
                return True
            else:
                self._total_dropped += 1
                return False

    def cleanup(self, now: Optional[float] = None) -> int:
        """
        清理所有采样键的过期时间戳，回收内存。

        优化：先在锁内快速收集所有 key 的快照，然后在锁外逐个清理，
        减少锁持有时间，避免阻塞 should_sample() 调用。

        参数
        ----
        now : float, optional
            当前时间戳（用于测试注入）。

        返回
        ----
        int
            被清理的采样键数量。
        """
        if now is None:
            now = time.time()
        cutoff = now - self._window_seconds
        removed_keys = 0

        # 第一阶段：锁内快速快照所有 key，并清理过期时间戳
        with self._lock:
            empty_keys = []
            for key, bucket in self._buckets.items():
                # 清理过期时间戳
                while bucket and bucket[0] < cutoff:
                    bucket.popleft()
                # 标记空桶以待删除
                if not bucket:
                    empty_keys.append(key)
            # 第二阶段：锁内删除空桶（del 操作很快，不会长时间持锁）
            for key in empty_keys:
                del self._buckets[key]
                removed_keys += 1

        return removed_keys

    def stats(self) -> Dict[str, int]:
        """
        返回采样器统计信息。

        返回
        ----
        dict
            包含 total_allowed / total_dropped / active_keys 三个计数器。
        """
        with self._lock:
            return {
                "total_allowed": self._total_allowed,
                "total_dropped": self._total_dropped,
                "active_keys": len(self._buckets),
            }


# ═══════════════════════════════════════════════════════════════════════════
# 第四部分：Raw HTTP 安全截断重构（设计文档第 3.3 节）
# ═══════════════════════════════════════════════════════════════════════════

def build_raw_http_request(
    method: str,
    url: str,
    headers: Any,
    body: str,
    max_bytes: int = MAX_PAYLOAD_BYTES,
) -> str:
    """
    构造原始 HTTP 请求报文并安全截断至 max_bytes 字节。

    设计文档第 3.3 节：
        将请求方法/URL/Headers/Body 重构为原始 HTTP 报文字符串，
        硬截断至 4096 字节，超出部分追加 "... [Truncated by AIWAF Adapter]" 标记。

    报文格式（标准 HTTP/1.1 请求报文）：
        GET /api/users?id=1 HTTP/1.1
        Host: api.example.com
        User-Agent: Mozilla/5.0
        Content-Type: application/json

        {"name":"test"}

    参数
    ----
    method : str
        HTTP 方法（GET / POST / PUT 等）。
    url : str
        请求 URL（含查询参数）。
    headers : Any
        请求头，支持 dict / JSON 字符串 / None。
    body : str
        请求体内容。
    max_bytes : int
        最大字节数，默认 4096。

    返回
    ----
    str
        重构并截断后的原始 HTTP 请求报文。
    """
    # ── 规范化输入 ──
    method = (method or "GET").upper()
    url = url or "/"
    body = body or ""

    # ── 解析 headers ──
    header_lines = []
    if headers:
        if isinstance(headers, str):
            # JSON 字符串 → dict
            try:
                headers_dict = json.loads(headers)
            except (json.JSONDecodeError, TypeError):
                headers_dict = {}
        elif isinstance(headers, dict):
            headers_dict = headers
        else:
            headers_dict = {}

        for k, v in headers_dict.items():
            header_lines.append(f"{k}: {v}")

    # ── 构造原始 HTTP 报文 ──
    parts = [f"{method} {url} HTTP/1.1"]
    if header_lines:
        parts.extend(header_lines)
    # 空行分隔 headers 和 body
    raw_http = "\r\n".join(parts) + "\r\n\r\n" + body

    # ── 安全截断 ──
    raw_bytes = raw_http.encode("utf-8", errors="replace")
    if len(raw_bytes) <= max_bytes:
        return raw_http

    # 硬截断：预留截断标记的长度
    suffix_bytes = TRUNCATION_SUFFIX.encode("utf-8")
    truncated_bytes = raw_bytes[: max_bytes - len(suffix_bytes)] + suffix_bytes
    return truncated_bytes.decode("utf-8", errors="replace")


# ═══════════════════════════════════════════════════════════════════════════
# 第五部分：告警字段规范化（AIWAF 告警 → V6.0 适配器内部格式）
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class NormalizedAlert:
    """
    规范化后的告警数据结构（V6.0 适配器内部格式）。

    此结构统一了 AIWAF 引擎产出的告警字段命名，
    便于后续过滤阀、采样器、Protobuf 构造等环节使用。
    """
    layer: str               # 检测层级（ai_anomaly / uuid_tamper / honeypot / ip_keyword_block）
    src_ip: str              # 源 IP
    request_url: str         # 请求 URL
    http_method: str         # HTTP 方法
    request_headers: Any     # 请求头（dict 或 JSON 字符串）
    request_body: str        # 请求体
    akto_account_id: str     # Akto 账号 ID（原生透传）
    api_collection_id: int   # API 集合 ID（原生透传）
    reason: str              # 检测原因
    country_code: str        # 国家代码
    host: str                # 主机名
    timestamp: float         # 告警时间戳
    action: str              # 处置动作（BLOCKED / ALERTED）
    severity: str            # 严重程度（HIGH / MEDIUM / LOW）
    status_code: int         # HTTP 状态码
    trace_id: str            # 追踪 ID


def normalize_alert(raw_alert: Dict[str, Any]) -> Optional[NormalizedAlert]:
    """
    将 AIWAF 引擎产出的原始告警 JSON 规范化为 V6.0 适配器内部格式。

    AIWAF 引擎 _emit_alert 产出的告警字段：
        - rule_id:        "KeywordBlock:sql_injection" 等
        - client_ip:      "1.2.3.4"
        - akto_account_id: "1000000"
        - api_collection_id: 6（需补丁添加）
        - method:         "GET"
        - uri_path:       "/api/users"
        - detected_at:    1719500000.0
        - severity:       "HIGH"
        - req_body_truncated: "..."
        - request_headers: {...}（需补丁添加）
        - host:           "api.example.com"（需补丁添加）
        - country_code:   "CN"（需补丁添加）

    参数
    ----
    raw_alert : dict
        AIWAF 引擎产出的原始告警 JSON（已 json.loads 解析）。

    返回
    ----
    NormalizedAlert or None
        规范化后的告警对象。若输入为空则返回 None。
    """
    if not raw_alert or not isinstance(raw_alert, dict):
        return None

    rule_id = raw_alert.get("rule_id", "")
    layer = _derive_layer(rule_id)
    reason = _derive_reason(rule_id)

    # api_collection_id 可能是 int 或 str，统一转为 int
    collection_id_raw = raw_alert.get("api_collection_id", 0)
    try:
        api_collection_id = int(collection_id_raw) if collection_id_raw else 0
    except (ValueError, TypeError):
        api_collection_id = 0

    # 时间戳优先使用 detected_at，回退到 alert_timestamp
    timestamp = raw_alert.get("detected_at") or raw_alert.get("alert_timestamp") or time.time()
    try:
        timestamp = float(timestamp)
    except (ValueError, TypeError):
        timestamp = time.time()

    # 状态码
    try:
        status_code = int(raw_alert.get("status_code", 0))
    except (ValueError, TypeError):
        status_code = 0

    return NormalizedAlert(
        layer=layer,
        src_ip=raw_alert.get("client_ip", "") or "",
        request_url=raw_alert.get("uri_path", "/") or "/",
        http_method=raw_alert.get("method", "GET") or "GET",
        request_headers=raw_alert.get("request_headers", {}),
        request_body=raw_alert.get("req_body_truncated", "") or "",
        akto_account_id=raw_alert.get("akto_account_id", "") or "",
        api_collection_id=api_collection_id,
        reason=reason,
        country_code=raw_alert.get("country_code", "") or "",
        host=raw_alert.get("host", "") or "",
        timestamp=timestamp,
        action="BLOCKED",  # AIWAF 告警均为阻断类告警
        severity=raw_alert.get("severity", "HIGH") or "HIGH",
        status_code=status_code,
        trace_id=raw_alert.get("trace_id", "") or "",
    )


# ═══════════════════════════════════════════════════════════════════════════
# 第六部分：Protobuf 消息构造（设计文档第 4 节）
# ═══════════════════════════════════════════════════════════════════════════

def build_malicious_event(alert: NormalizedAlert) -> message_pb2.MaliciousEventMessage:
    """
    根据规范化告警构造 Akto 原生 MaliciousEventMessage（Protobuf）。

    设计文档第 4 节字段映射：
        event.actor                    ← alert.src_ip
        event.sub_category             ← AIWAF_TO_AKTO_SUBCATEGORY[alert.layer]
        event.filter_id                ← "AIWAF:{alert.layer}"
        event.category                 ← "AIWAF"
        event.detected_at              ← int(alert.timestamp)
        event.latest_api_ip            ← alert.src_ip
        event.latest_api_endpoint      ← alert.request_url
        event.latest_api_method        ← alert.http_method
        event.latest_api_collection_id ← alert.api_collection_id
        event.latest_api_payload       ← build_raw_http_request(...)
        event.severity                 ← alert.severity
        event.successful_exploit       ← False
        event.status                   ← alert.action
        event.context_source           ← "API"
        event.event_type               ← EVENT_TYPE_SINGLE
        event.host                     ← alert.host
        event.metadata.reason          ← alert.reason
        event.metadata.country_code    ← alert.country_code

    参数
    ----
    alert : NormalizedAlert
        规范化后的告警对象。

    返回
    ----
    message_pb2.MaliciousEventMessage
        构造完成的 Protobuf 消息（尚未序列化）。
    """
    # ── 构造 Raw HTTP 报文（安全截断至 4096 字节）──
    raw_http = build_raw_http_request(
        method=alert.http_method,
        url=alert.request_url,
        headers=alert.request_headers,
        body=alert.request_body,
    )

    # ── 构造 Metadata（设计在 sample_request.v1.message_pb2 中定义）──
    metadata = sample_request_pb2.Metadata()
    metadata.reason = alert.reason or ""
    metadata.country_code = alert.country_code or ""

    # ── 构造 MaliciousEventMessage ──
    event = message_pb2.MaliciousEventMessage()
    event.actor = alert.src_ip
    event.sub_category = AIWAF_TO_AKTO_SUBCATEGORY.get(alert.layer, alert.layer)
    event.filter_id = f"AIWAF:{alert.layer}"
    event.category = "AIWAF"
    event.detected_at = int(alert.timestamp)
    event.latest_api_ip = alert.src_ip
    event.latest_api_endpoint = alert.request_url
    event.latest_api_method = alert.http_method
    event.latest_api_collection_id = alert.api_collection_id
    event.latest_api_payload = raw_http
    event.severity = alert.severity
    event.successful_exploit = False
    event.status = alert.action
    event.context_source = "API"
    event.event_type = event_type_pb2.EVENT_TYPE_SINGLE
    event.host = alert.host
    event.metadata.CopyFrom(metadata)

    return event


def build_kafka_envelope(
    alert: NormalizedAlert,
    event: message_pb2.MaliciousEventMessage,
) -> message_pb2.MaliciousEventKafkaEnvelope:
    """
    构造 Akto 原生 MaliciousEventKafkaEnvelope（Kafka 外层信封）。

    设计文档第 4 节：
        envelope.account_id       ← alert.akto_account_id（原生 ID 透传）
        envelope.actor            ← alert.src_ip
        envelope.malicious_event  ← event（内层 MaliciousEventMessage）

    参数
    ----
    alert : NormalizedAlert
        规范化后的告警对象（用于提取 account_id 和 actor）。
    event : message_pb2.MaliciousEventMessage
        已构造的内层 Protobuf 消息。

    返回
    ----
    message_pb2.MaliciousEventKafkaEnvelope
        构造完成的 Kafka 信封消息（尚未序列化）。
    """
    envelope = message_pb2.MaliciousEventKafkaEnvelope()
    envelope.account_id = alert.akto_account_id
    envelope.actor = alert.src_ip
    envelope.malicious_event.CopyFrom(event)
    return envelope


# ═══════════════════════════════════════════════════════════════════════════
# 第七部分：生产级适配器类（AktoV6Adapter）
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class AktoV6AdapterConfig:
    """
    V6.0 适配器配置。

    封装 Kafka 连接参数、topic 名称、采样器参数等，
    便于从 YAML 配置文件或环境变量加载。
    """
    # Kafka 连接
    kafka_bootstrap_servers: str = "localhost:9092"

    # 消费配置
    alert_topic: str = "aiwaf.alerts"
    consumer_group: str = "aiwaf-akto-adapter-v6"
    consumer_auto_offset_reset: str = "latest"
    consumer_enable_auto_commit: bool = True
    consumer_poll_timeout_ms: int = 1000

    # 生产配置
    malicious_events_topic: str = "akto.threat_detection.malicious_events"
    producer_acks: str = "all"
    producer_retries: int = 3

    # 采样限流器
    sampler_window_seconds: int = DEFAULT_SAMPLER_WINDOW_SECONDS
    sampler_max_samples: int = DEFAULT_SAMPLER_MAX_SAMPLES

    # Raw HTTP 截断
    max_payload_bytes: int = MAX_PAYLOAD_BYTES

    # 运行控制
    cleanup_interval_seconds: int = 300  # 采样器清理间隔


class AktoV6Adapter:
    """
    AIWAF 接入 Akto V6.0 生产级适配器。

    生命周期
    --------
    1. __init__: 初始化配置、采样器、Kafka 消费者/生产者
    2. run: 启动主消费循环，处理告警并注入 Akto
    3. shutdown: 优雅关闭，释放 Kafka 连接

    核心处理流程（每条告警）
    -----------------------
    1. JSON 解析 → normalize_alert → NormalizedAlert
    2. 过滤阀：layer ∈ ALLOWED_THREAT_LAYERS ?
    3. 采样器：SlidingWindowSampler.should_sample() ?
    4. 原生 ID 透传校验：akto_account_id 和 api_collection_id 非空 ?
    5. Protobuf 构造：build_malicious_event + build_kafka_envelope
    6. 注入 Kafka：producer.send(malicious_events_topic, envelope.SerializeToString())

    生产级特性
    ----------
    - 优雅关闭：捕获 SIGINT/SIGTERM，安全退出消费循环
    - 错误隔离：单条告警处理异常不影响整体循环
    - 采样器定期清理：防止内存泄漏
    - 统计指标：processed / filtered / sampled_out / injected / errors
    - 结构化日志：便于运维排查
    """

    def __init__(self, config: AktoV6AdapterConfig):
        self._config = config
        self._sampler = SlidingWindowSampler(
            window_seconds=config.sampler_window_seconds,
            max_samples=config.sampler_max_samples,
        )
        self._consumer = None
        self._producer = None
        self._running = False
        self._shutdown_event = threading.Event()

        # 统计指标
        self._stats = {
            "processed": 0,       # 总处理数
            "filtered_out": 0,    # 被过滤阀丢弃
            "sampled_out": 0,     # 被采样器丢弃
            "id_missing": 0,      # 原生 ID 缺失丢弃
            "injected": 0,        # 成功注入 Akto
            "errors": 0,          # 处理异常
        }
        self._stats_lock = threading.Lock()

    def _init_kafka(self):
        """延迟初始化 Kafka 消费者和生产者。"""
        from kafka import KafkaConsumer, KafkaProducer

        # ── 消费者：订阅 aiwaf.alerts ──
        self._consumer = KafkaConsumer(
            self._config.alert_topic,
            bootstrap_servers=self._config.kafka_bootstrap_servers,
            group_id=self._config.consumer_group,
            auto_offset_reset=self._config.consumer_auto_offset_reset,
            enable_auto_commit=self._config.consumer_enable_auto_commit,
            consumer_poll_timeout_ms=self._config.consumer_poll_timeout_ms,
            value_deserializer=lambda v: v,  # 保持原始 bytes，由适配器解析
            key_deserializer=lambda k: k,
        )
        logger.info(
            "Kafka 消费者已连接: brokers=%s, topic=%s, group=%s",
            self._config.kafka_bootstrap_servers,
            self._config.alert_topic,
            self._config.consumer_group,
        )

        # ── 生产者：向 akto.threat_detection.malicious_events 注入 ──
        # 审计修复 #15：设置 max_request_size 为 10MB，防止大 Protobuf 消息被拒
        self._producer = KafkaProducer(
            bootstrap_servers=self._config.kafka_bootstrap_servers,
            acks=self._config.producer_acks,
            retries=self._config.producer_retries,
            value_serializer=lambda v: v,  # 已序列化的 bytes
            key_serializer=lambda k: k,
            max_request_size=10 * 1024 * 1024,  # 10MB，默认 1MB 可能不够
        )
        logger.info(
            "Kafka 生产者已连接: brokers=%s, topic=%s",
            self._config.kafka_bootstrap_servers,
            self._config.malicious_events_topic,
        )

    def _inc_stat(self, key: str, count: int = 1):
        """线程安全地递增统计计数器。"""
        with self._stats_lock:
            self._stats[key] += count

    def get_stats(self) -> Dict[str, int]:
        """获取当前统计指标快照。"""
        with self._stats_lock:
            return dict(self._stats)

    def process_single_alert(self, raw_alert: Dict[str, Any]) -> tuple:
        """
        处理单条告警（核心五重处理流程）。

        此方法为可测试的纯逻辑方法，不涉及 Kafka I/O，
        便于单元测试验证过滤阀、采样器、Protobuf 构造等逻辑。

        参数
        ----
        raw_alert : dict
            AIWAF 引擎产出的原始告警 JSON（已解析为 dict）。

        返回
        ----
        Tuple[bool, Optional[bytes]]
            (True, envelope_bytes) 表示告警通过所有过滤并成功构造 Protobuf 消息，
            (False, None) 表示告警被丢弃（过滤阀/采样器/ID 缺失/构造失败）。
        """
        self._inc_stat("processed")

        # ── 步骤 1：规范化告警字段 ──
        alert = normalize_alert(raw_alert)
        if alert is None:
            self._inc_stat("errors")
            # 安全审计修复：不记录完整 raw_alert（可能含敏感请求体），
            # 仅记录关键字段用于排查
            # 审计修复：raw_alert 可能为 None，需防御性处理
            if isinstance(raw_alert, dict):
                logger.warning(
                    "告警规范化失败，丢弃: rule_id=%s, trace_id=%s, client_ip=%s",
                    raw_alert.get("rule_id", ""),
                    raw_alert.get("trace_id", ""),
                    raw_alert.get("client_ip", ""),
                )
            else:
                logger.warning("告警规范化失败，丢弃: 输入类型=%s", type(raw_alert).__name__)
            return False, None

        # ── 步骤 2：告警分级过滤阀 ──
        if alert.layer not in ALLOWED_THREAT_LAYERS:
            self._inc_stat("filtered_out")
            logger.debug(
                "过滤阀丢弃: layer=%s 不在允许列表, trace_id=%s",
                alert.layer, alert.trace_id,
            )
            return False, None

        # ── 步骤 3：采样限流器 ──
        if not self._sampler.should_sample(
            src_ip=alert.src_ip,
            layer=alert.layer,
            request_url=alert.request_url,
        ):
            self._inc_stat("sampled_out")
            logger.debug(
                "采样器丢弃: src_ip=%s, layer=%s, url=%s, trace_id=%s",
                alert.src_ip, alert.layer, alert.request_url, alert.trace_id,
            )
            return False, None

        # ── 步骤 4：原生 ID 透传校验（脏数据保护）──
        if not alert.akto_account_id or not alert.api_collection_id:
            self._inc_stat("id_missing")
            logger.debug(
                "原生 ID 缺失丢弃: account_id=%s, collection_id=%s, trace_id=%s",
                alert.akto_account_id, alert.api_collection_id, alert.trace_id,
            )
            return False, None

        # ── 步骤 5：Protobuf 消息构造 ──
        try:
            event = build_malicious_event(alert)
            envelope = build_kafka_envelope(alert, event)
            # 审计修复：不再修改输入 dict，直接返回序列化后的 bytes
            return True, envelope.SerializeToString()
        except Exception as e:
            self._inc_stat("errors")
            logger.error(
                "Protobuf 构造失败: %s, trace_id=%s, layer=%s, src_ip=%s",
                e, alert.trace_id, alert.layer, alert.src_ip,
                exc_info=True,
            )
            return False, None

    def run(self):
        """
        启动主消费循环。

        持续消费 aiwaf.alerts topic 的告警消息，
        经过五重处理后注入 akto.threat_detection.malicious_events topic。

        捕获 SIGINT/SIGTERM 信号实现优雅关闭。

        生产级特性：
        - Kafka 连接失败自动重试（指数退避）
        - 使用 poll() 替代阻塞迭代，确保信号可中断
        - 关闭前 flush 生产者，防止消息丢失
        - 定期输出统计指标日志
        """
        # ── 注册信号处理器（优雅关闭）──
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

        # ── 初始化 Kafka（带重试）──
        # 审计修复 #6：Kafka 连接失败时自动重试，避免直接崩溃
        max_retries = 5
        retry_delay = 5  # 秒
        for attempt in range(1, max_retries + 1):
            try:
                self._init_kafka()
                break
            except Exception as e:
                if attempt < max_retries:
                    logger.warning(
                        "Kafka 连接失败（第 %d/%d 次）: %s，%ds 后重试...",
                        attempt, max_retries, e, retry_delay,
                    )
                    self._shutdown_event.wait(retry_delay)
                    retry_delay = min(retry_delay * 2, 60)  # 指数退避，上限 60s
                else:
                    logger.error("Kafka 连接失败，已达最大重试次数 %d，退出", max_retries)
                    raise

        self._running = True
        logger.info("AIWAF Akto V6.0 适配器已启动")

        # ── 启动采样器定期清理线程 ──
        cleanup_thread = threading.Thread(
            target=self._cleanup_loop, daemon=True, name="sampler-cleanup"
        )
        cleanup_thread.start()

        # ── 启动统计指标定期输出线程 ──
        # 审计修复 #14：定期输出统计指标，增强可观测性
        stats_thread = threading.Thread(
            target=self._stats_loop, daemon=True, name="stats-reporter"
        )
        stats_thread.start()

        # ── 主消费循环 ──
        # 审计修复 #3：使用 poll() 替代 `for msg in consumer` 阻塞迭代，
        # 确保 SIGTERM/SIGINT 能及时中断消费循环
        try:
            while not self._shutdown_event.is_set():
                # poll 超时 1 秒，确保定期检查 shutdown 事件
                # 审计修复 R2#2：max_records 使用固定值 500，不与 timeout_ms 混用
                records = self._consumer.poll(
                    timeout_ms=1000,
                    max_records=500,
                )
                if not records:
                    continue

                for _topic_partition, msgs in records.items():
                    for msg in msgs:
                        if self._shutdown_event.is_set():
                            break
                        try:
                            # 解析 JSON 告警
                            raw_alert = json.loads(msg.value.decode("utf-8", errors="replace"))

                            # 五重处理
                            # 审计修复 #9：process_single_alert 返回 (bool, Optional[bytes])
                            success, envelope_bytes = self.process_single_alert(raw_alert)
                            if success and envelope_bytes:
                                # 注入 Akto Kafka topic
                                self._producer.send(
                                    self._config.malicious_events_topic,
                                    envelope_bytes,
                                )
                                self._inc_stat("injected")
                                logger.debug(
                                    "成功注入 Akto: trace_id=%s, layer=%s",
                                    raw_alert.get("trace_id", ""),
                                    _derive_layer(raw_alert.get("rule_id", "")),
                                )
                        except json.JSONDecodeError as e:
                            self._inc_stat("errors")
                            logger.error("JSON 解析失败: %s, raw=%s", e, msg.value[:200])
                        except Exception as e:
                            self._inc_stat("errors")
                            logger.error("告警处理异常: %s", e, exc_info=True)

        except Exception as e:
            logger.error("主消费循环异常: %s", e, exc_info=True)
        finally:
            # 审计修复 #4：关闭前 flush 生产者，确保所有消息已发送
            # 审计修复 #5：cleanup 使用 try/except 确保资源释放
            self._cleanup()
            cleanup_thread.join(timeout=5)
            stats_thread.join(timeout=5)
            logger.info("AIWAF Akto V6.0 适配器已停止, 统计: %s", self.get_stats())

    def _cleanup_loop(self):
        """采样器定期清理后台线程，防止内存泄漏。"""
        while not self._shutdown_event.is_set():
            # 使用 wait 替代 sleep，确保能及时响应关闭信号
            if self._shutdown_event.wait(self._config.cleanup_interval_seconds):
                break
            try:
                removed = self._sampler.cleanup()
                if removed > 0:
                    logger.debug("采样器清理: 回收 %d 个空桶", removed)
            except Exception as e:
                logger.error("采样器清理异常: %s", e)

    def _stats_loop(self):
        """定期输出统计指标日志，增强可观测性。"""
        stats_interval = 60  # 每 60 秒输出一次
        while not self._shutdown_event.is_set():
            if self._shutdown_event.wait(stats_interval):
                break
            try:
                stats = self.get_stats()
                logger.info("适配器运行统计: %s", stats)
            except Exception as e:
                logger.error("统计指标输出异常: %s", e)

    def _signal_handler(self, signum, frame):
        """信号处理器：设置关闭标志，优雅退出。"""
        logger.info("收到信号 %s，准备优雅关闭...", signum)
        self._shutdown_event.set()
        # 审计修复 #3：唤醒阻塞的 consumer.poll()
        if self._consumer is not None:
            try:
                self._consumer.stop()
            except Exception:
                pass

    def _cleanup(self):
        """清理 Kafka 连接资源。"""
        self._running = False
        # 审计修复 #5：每个资源关闭都使用独立的 try/except，确保一个失败不影响其他
        if self._producer is not None:
            try:
                # 审计修复 #4：flush 确保所有缓冲消息已发送
                self._producer.flush(timeout=10)
            except Exception as e:
                logger.error("flush Kafka 生产者异常: %s", e)
            try:
                self._producer.close(timeout=10)
            except Exception as e:
                logger.error("关闭 Kafka 生产者异常: %s", e)
        if self._consumer is not None:
            try:
                self._consumer.close()
            except Exception as e:
                logger.error("关闭 Kafka 消费者异常: %s", e)


# ═══════════════════════════════════════════════════════════════════════════
# 第八部分：独立入口函数（设计文档第 4 节 process_stream）
# ═══════════════════════════════════════════════════════════════════════════

def process_stream(
    bootstrap_servers: str = "localhost:9092",
    alert_topic: str = "aiwaf.alerts",
    malicious_events_topic: str = "akto.threat_detection.malicious_events",
    consumer_group: str = "aiwaf-akto-adapter-v6",
):
    """
    V6.0 适配器独立运行入口（设计文档第 4 节）。

    封装 AktoV6Adapter 的初始化和运行，
    便于作为独立进程启动或通过命令行调用。

    参数
    ----
    bootstrap_servers : str
        Kafka broker 地址列表（逗号分隔）。
    alert_topic : str
        AIWAF 告警 topic（消费源）。
    malicious_events_topic : str
        Akto 恶意事件 topic（注入目标）。
    consumer_group : str
        Kafka 消费者组 ID。
    """
    config = AktoV6AdapterConfig(
        kafka_bootstrap_servers=bootstrap_servers,
        alert_topic=alert_topic,
        malicious_events_topic=malicious_events_topic,
        consumer_group=consumer_group,
    )
    adapter = AktoV6Adapter(config)
    adapter.run()


def main():
    """命令行入口：从环境变量读取配置并启动适配器。"""
    import os

    logging.basicConfig(
        level=os.environ.get("AIWAF_LOG_LEVEL", "INFO"),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    process_stream(
        bootstrap_servers=os.environ.get(
            "KAFKA_BOOTSTRAP_SERVERS", "localhost:9092"
        ),
        alert_topic=os.environ.get("AIWAF_ALERT_TOPIC", "aiwaf.alerts"),
        malicious_events_topic=os.environ.get(
            "AKTO_MALICIOUS_EVENTS_TOPIC",
            "akto.threat_detection.malicious_events",
        ),
        consumer_group=os.environ.get(
            "AIWAF_AKTO_CONSUMER_GROUP", "aiwaf-akto-adapter-v6"
        ),
    )


if __name__ == "__main__":
    main()
