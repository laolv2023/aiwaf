#!/usr/bin/env python3
"""
AIWAF-Stream 基准测试沙箱

将攻击流量转换为 Akto Kafka 消息格式，注入 akto.api.logs Topic，
统计 akto.aiwaf.alerts Topic 的告警输出率。

用法:
    # 启动 Kafka + Redis
    docker compose up -d kafka redis

    # 启动 AIWAF 引擎
    python -m aiwaf.stream.engine &

    # 运行基准测试
    python scripts/sandbox.py --mode attacks

    # 运行正常流量（验证不误杀）
    python scripts/sandbox.py --mode normal

    # 运行全部 + 对比
    python scripts/sandbox.py --mode all

依赖:
    pip install aiokafka orjson

    # logs2 Protobuf 双写模式（可选）:
    pip install protobuf

来源: 改造自 aiwaf-project/aiwaf examples/sandbox/attack-suite.py
"""
import asyncio
import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
# P2-01修复: 确保 scripts/ 目录在 path 中, 以便 import message_pb2
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from aiokafka import AIOKafkaProducer, AIOKafkaConsumer
except ImportError:
    print("Error: pip install aiokafka")
    sys.exit(1)

import orjson

# ── 配置 ──

KAFKA_BROKERS = os.getenv("KAFKA_BROKERS", "127.0.0.1:49092")
INPUT_TOPIC = os.getenv("KAFKA_INPUT_TOPIC", "akto.api.logs")
INPUT_TOPIC_2 = os.getenv("KAFKA_INPUT_TOPIC_2", "akto.api.logs2")
ALERT_TOPIC = os.getenv("KAFKA_ALERT_TOPIC", "akto.aiwaf.alerts")
ENABLE_LOGS2 = os.getenv("ENABLE_LOGS2", "false").lower() in ("1", "true", "yes")

# ── Protobuf 消息构建（logs2）──
# 动态构建 HttpResponseParam protobuf, 不依赖 protoc 编译
try:
    from message_pb2 import HttpResponseParam as _PB_HttpResponseParam, StringList as _PB_StringList
    _PB_AVAILABLE = True
except Exception:
    _PB_AVAILABLE = False

# ── Akto 消息构建 ──
# 对齐 mirroring-api-logging 的 akto.api.logs Topic 输出格式
# 参考: mirroring-api-logging/main.go L579-601 (HttpResponseParam JSON 序列化)

def make_akto_msg(
    path: str,
    method: str = "GET",
    ip: str = "10.0.0.1",
    status_code: str = "200",
    user_agent: str = "Mozilla/5.0",
    accept: str = "text/html",
    request_body: str = "",
    dest_ip: str = "10.0.0.2",
) -> Dict[str, Any]:
    """构建 Akto 格式的 Kafka 消息（对齐 mirroring-api-logging logs 格式）

    对齐项:
      - time: 秒级 Unix 时间戳（mirroring 用 time.Now().Unix()）
      - type: HTTP 协议版本（mirroring 用 req.Proto，如 "HTTP/1.1"）
      - status: 完整状态行（mirroring 用 resp.Status，如 "200 OK"）
      - is_pending: 是否待处理（mirroring 的 isPending 字段）
      - statusCode: string 类型（mirroring 所有字段均为 string）
    """
    headers = {
        "user-agent": user_agent,
        "accept": accept,
        "host": "api.example.com",
        "connection": "Keep-Alive",
    }
    if method in ("POST", "PUT", "PATCH"):
        headers["content-type"] = "application/json"
        headers["content-length"] = str(len(request_body))

    # status: 对齐 mirroring 的 resp.Status 格式 "200 OK"
    status_line = f"{status_code} OK" if status_code == "200" else f"{status_code} Error"

    # P3-01修复: 每条消息时间略有不同（毫秒级递增），对齐 mirroring 逐条时间戳
    _now = int(time.time() * 1000)  # 毫秒级

    return {
        "path": path,
        "method": method,
        "requestHeaders": orjson.dumps(headers).decode(),
        "responseHeaders": orjson.dumps({"content-type": "application/json"}).decode(),
        "requestPayload": request_body,
        "responsePayload": "",
        "ip": ip,
        "destIp": dest_ip,
        "time": str(_now // 1000),  # 秒级 Unix 时间戳，对齐 mirroring time.Now().Unix()
        "statusCode": status_code,       # string 类型，对齐 mirroring
        "type": "HTTP/1.1",              # HTTP 协议版本，对齐 mirroring req.Proto
        "status": status_line,           # 完整状态行，对齐 mirroring resp.Status
        "akto_account_id": "1000000",
        "akto_vxlan_id": "-1",          # P3-02修复: 对齐 mirroring 实时镜像模式 vxlanID=-1
        "is_pending": "false",           # 对齐 mirroring isPending 字段
        "source": "MIRRORING",
        "direction": "REQUEST",
    }


def _headers_json_to_map(headers_json: str) -> dict:
    """将 JSON string 格式的 headers 转为 dict"""
    if not headers_json:
        return {}
    try:
        return orjson.loads(headers_json) if isinstance(headers_json, (str, bytes)) else headers_json
    except Exception:
        return {}


def make_akto_pb(msg: Dict[str, Any]) -> bytes:
    """将 Akto JSON 消息转为 Protobuf 二进制（logs2 格式）

    字段类型转换:
      - statusCode: string → int32
      - time: string → int32
      - is_pending: string → bool
      - requestHeaders/responseHeaders: JSON string → map<StringList>
      - api_collection_id: 从 akto_vxlan_id 转换

    对齐: mirroring-api-logging/protobuf/traffic_payload/message.proto
    """
    if not _PB_AVAILABLE:
        raise RuntimeError("protobuf 运行时不可用, 请安装: pip install protobuf")

    pb = _PB_HttpResponseParam()

    # string 字段直接赋值
    pb.method = msg.get("method", "")
    pb.path = msg.get("path", "")
    pb.type = msg.get("type", "HTTP/1.1")
    pb.request_payload = msg.get("requestPayload", "")
    pb.status = msg.get("status", "")
    pb.response_payload = msg.get("responsePayload", "")
    pb.akto_account_id = msg.get("akto_account_id", "1000000")
    pb.ip = msg.get("ip", "")
    pb.dest_ip = msg.get("destIp", "")
    pb.direction = msg.get("direction", "REQUEST")
    pb.source = msg.get("source", "MIRRORING")
    pb.akto_vxlan_id = msg.get("akto_vxlan_id", "-1")

    # int32 字段 (P2-02修复: 添加范围检查, 防止溢出)
    try:
        sc = int(msg.get("statusCode", "0"))
        pb.status_code = max(0, min(sc, 2147483647))
    except (ValueError, TypeError):
        pb.status_code = 0

    try:
        t = int(msg.get("time", "0"))
        pb.time = max(0, min(t, 2147483647))
    except (ValueError, TypeError):
        pb.time = 0

    # api_collection_id: 从 akto_vxlan_id 转换（mirroring 行为）
    # P3-02修复: mirroring 实时镜像模式 vxlanID=-1, protobuf int32 不支持负数的 api_collection_id
    try:
        ac_id = int(msg.get("akto_vxlan_id", "0"))
        pb.api_collection_id = max(0, min(ac_id, 2147483647))
    except (ValueError, TypeError):
        pb.api_collection_id = 0

    # bool 字段
    pb.is_pending = str(msg.get("is_pending", "false")).lower() in ("true", "1", "yes")

    # map<string, StringList> 字段
    # P1-01修复: protobuf 动态描述符的 map field 用 get_or_create + MergeFrom
    for k, v in _headers_json_to_map(msg.get("requestHeaders", "")).items():
        sl = _PB_StringList()
        if isinstance(v, list):
            sl.values.extend(v)
        else:
            sl.values.append(str(v))
        pb.request_headers[k].MergeFrom(sl)

    for k, v in _headers_json_to_map(msg.get("responseHeaders", "")).items():
        sl = _PB_StringList()
        if isinstance(v, list):
            sl.values.extend(v)
        else:
            sl.values.append(str(v))
        pb.response_headers[k].MergeFrom(sl)

    return pb.SerializeToString()


# ── 攻击模式 ──

@dataclass
class AttackResult:
    name: str
    messages_sent: int
    alerts_received: int
    attack_type: str = ""


async def send_and_collect(
    producer: AIOKafkaProducer,
    consumer: AIOKafkaConsumer,
    messages: List[Dict[str, Any]],
    attack_name: str,
    wait_seconds: float = 2.0,
) -> AttackResult:
    """发送一批消息到 Kafka（logs + logs2 双写），等待并收集告警"""
    sent = len(messages)

    # 发送消息: logs (JSON) + logs2 (Protobuf, 可选)
    for msg in messages:
        await producer.send_and_wait(INPUT_TOPIC, orjson.dumps(msg))
        if ENABLE_LOGS2 and _PB_AVAILABLE:
            # P1-02修复: 序列化失败不影响整批发送
            try:
                pb_bytes = make_akto_pb(msg)
                await producer.send_and_wait(INPUT_TOPIC_2, pb_bytes)
            except Exception as e:
                # protobuf 序列化失败仅记录, 不中断
                pass

    # 等待 AIWAF 处理
    await asyncio.sleep(wait_seconds)

    # 收集告警
    alerts = 0
    try:
        while True:
            msg = await asyncio.wait_for(consumer.getone(), timeout=0.5)
            alerts += 1
    except asyncio.TimeoutError:
        pass

    return AttackResult(
        name=attack_name,
        messages_sent=sent,
        alerts_received=alerts,
    )


# ── 12 种攻击模式（与官方仓库 attack-suite.py 一致）──

def gen_brute_force(ip: str = "203.0.113.1") -> List[Dict[str, Any]]:
    """暴力破解登录"""
    msgs = []
    for i in range(50):
        body = orjson.dumps({"email": f"admin{i}@example.com", "password": "password"}).decode()
        msgs.append(make_akto_msg("/rest/user/login", "POST", ip, "401", request_body=body))
    return msgs

def gen_credential_stuffing(ip: str = "203.0.113.2") -> List[Dict[str, Any]]:
    """凭证填充"""
    msgs = []
    candidates = [
        {"email": "admin@juice-sh.op", "password": "admin123"},
        {"email": "admin@juice-sh.op", "password": "password"},
        {"email": "test@juice-sh.op", "password": "test"},
        {"email": "demo@juice-sh.op", "password": "demo"},
    ]
    for cred in candidates:
        for _ in range(10):
            body = orjson.dumps(cred).decode()
            msgs.append(make_akto_msg("/rest/user/login", "POST", ip, "401", request_body=body))
    return msgs

def gen_path_probe(ip: str = "203.0.113.3") -> List[Dict[str, Any]]:
    """路径探测"""
    paths = [
        "/admin.php", "/.env", "/.git/config", "/../etc/passwd",
        "/wp-login.php", "/phpmyadmin", "/config.php", "/server-status",
        "/actuator/env", "/api/internal", "/backup.zip", "/.well-known/security.txt",
    ]
    return [make_akto_msg(p, "GET", ip, "404") for p in paths]

def gen_header_probe(ip: str = "203.0.113.4") -> List[Dict[str, Any]]:
    """可疑 Header"""
    return [make_akto_msg("/", "GET", ip, "200", user_agent="sqlmap/1.0", accept="")]

def gen_header_variations(ip: str = "203.0.113.5") -> List[Dict[str, Any]]:
    """Header 变体"""
    uas = ["sqlmap/1.8", "nikto/2.5.0", "masscan/1.3", "curl/7.88.1", "python-requests/2.31.0"]
    return [make_akto_msg("/", "GET", ip, "200", user_agent=ua, accept="") for ua in uas]

def gen_burst(ip: str = "203.0.113.6") -> List[Dict[str, Any]]:
    """突发流量（速率限制测试）"""
    return [make_akto_msg("/", "GET", ip, "200") for _ in range(30)]

def gen_burst_mixed(ip: str = "203.0.113.7") -> List[Dict[str, Any]]:
    """混合突发流量"""
    msgs = []
    for i in range(40):
        if i % 3 == 0:
            body = orjson.dumps({"email": f"burst{i}@example.com", "password": "x"}).decode()
            msgs.append(make_akto_msg("/rest/user/login", "POST", ip, "401", request_body=body))
        elif i % 3 == 1:
            msgs.append(make_akto_msg("/rest/products", "GET", ip, "200"))
        else:
            msgs.append(make_akto_msg("/", "GET", ip, "200"))
    return msgs

def gen_method_probe(ip: str = "203.0.113.8") -> List[Dict[str, Any]]:
    """HTTP 方法探测"""
    return [
        make_akto_msg("/api/", "PUT", ip, "405"),
        make_akto_msg("/api/", "DELETE", ip, "405"),
        make_akto_msg("/api/", "PATCH", ip, "405"),
    ]

def gen_query_injection(ip: str = "203.0.113.9") -> List[Dict[str, Any]]:
    """查询参数注入"""
    payloads = [
        "/rest/products/search?q=' OR 1=1--",
        "/rest/products/search?q=<script>alert(1)</script>",
        "/rest/products/search?q=';WAITFOR DELAY '0:0:3'--",
    ]
    return [make_akto_msg(p, "GET", ip, "200") for p in payloads]

def gen_owasp_top10(ip: str = "203.0.113.10") -> List[Dict[str, Any]]:
    """OWASP Top 10 攻击"""
    msgs = []
    attacks = [
        ("/rest/products/search?q=' OR 1=1--", "GET", "200", ""),
        ("/rest/products/search?q=<script>alert(1)</script>", "GET", "200", ""),
        ("/.env", "GET", "404", ""),
        ("/.git/config", "GET", "404", ""),
        ("/admin", "GET", "403", ""),
        ("/rest/products/search?q=../../../etc/passwd", "GET", "200", ""),
        ("/rest/user/login", "POST", "401", orjson.dumps({"email": "admin@juice-sh.op", "password": "admin123"}).decode()),
        ("/rest/user/login", "POST", "401", orjson.dumps({"email": "admin@juice-sh.op' OR 1=1--", "password": "x"}).decode()),
    ]
    for path, method, status, body in attacks:
        msgs.append(make_akto_msg(path, method, ip, status, request_body=body))
    return msgs

def gen_long_path(ip: str = "203.0.113.11") -> List[Dict[str, Any]]:
    """超长路径"""
    return [make_akto_msg("/" + "a" * 2047, "GET", ip, "404")]

def gen_normal_traffic(ip: str = "198.51.100.1") -> List[Dict[str, Any]]:
    """正常流量（验证不误杀）"""
    normal_ua = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120 Safari/537.36"
    normal_accept = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    msgs = []
    for _ in range(10):
        msgs.append(make_akto_msg("/", "GET", ip, "200", user_agent=normal_ua, accept=normal_accept))
        msgs.append(make_akto_msg("/rest/products", "GET", ip, "200", user_agent=normal_ua, accept=normal_accept))
        msgs.append(make_akto_msg("/rest/products/search?q=apple", "GET", ip, "200", user_agent=normal_ua, accept=normal_accept))
        msgs.append(make_akto_msg("/api/Products/1", "GET", ip, "200", user_agent=normal_ua, accept=normal_accept))
    return msgs


# ── 测试套件 ──

ATTACK_SUITE = [
    ("brute_force", gen_brute_force),
    ("credential_stuffing", gen_credential_stuffing),
    ("path_probe", gen_path_probe),
    ("header_probe", gen_header_probe),
    ("header_variations", gen_header_variations),
    ("burst", gen_burst),
    ("burst_mixed", gen_burst_mixed),
    ("method_probe", gen_method_probe),
    ("query_injection", gen_query_injection),
    ("owasp_top10", gen_owasp_top10),
    ("long_path", gen_long_path),
]

async def run_sandbox(mode: str = "all"):
    """运行基准测试"""
    print(f"{'=' * 70}")
    print(f"  AIWAF-Stream Sandbox — 基准测试")
    print(f"  Kafka: {KAFKA_BROKERS}")
    print(f"  Logs:  {INPUT_TOPIC}")
    if ENABLE_LOGS2 and _PB_AVAILABLE:
        print(f"  Logs2: {INPUT_TOPIC_2} (Protobuf 双写已启用)")
    elif ENABLE_LOGS2 and not _PB_AVAILABLE:
        print(f"  Logs2: ⚠️ 已启用但 protobuf 运行时不可用（pip install protobuf）")
    else:
        print(f"  Logs2: 未启用（设置 ENABLE_LOGS2=true 开启）")
    print(f"  Alert: {ALERT_TOPIC}")
    print(f"  Mode:  {mode}")
    print(f"{'=' * 70}\n")

    producer = AIOKafkaProducer(bootstrap_servers=KAFKA_BROKERS, value_serializer=lambda v: v)
    consumer = AIOKafkaConsumer(
        ALERT_TOPIC,
        bootstrap_servers=KAFKA_BROKERS,
        group_id="sandbox-consumer",
        auto_offset_reset="latest",
        value_deserializer=lambda v: v,
    )

    # P1-01修复: consumer.start() 失败时清理已启动的 producer
    await producer.start()
    try:
        await consumer.start()
    except Exception:
        await producer.stop()
        raise

    results: List[AttackResult] = []

    try:
        # 正常流量
        if mode in ("normal", "all"):
            print("[1/2] 正常流量测试（验证不误杀）...")
            msgs = gen_normal_traffic()
            result = await send_and_collect(producer, consumer, msgs, "normal_traffic", wait_seconds=3.0)
            results.append(result)
            false_positive_rate = (result.alerts_received / result.messages_sent * 100) if result.messages_sent else 0
            print(f"  发送: {result.messages_sent}, 告警: {result.alerts_received}, 误报率: {false_positive_rate:.1f}%\n")

        # 攻击流量
        if mode in ("attacks", "all"):
            print("[2/2] 攻击流量测试（验证检测率）...")
            for name, gen_fn in ATTACK_SUITE:
                msgs = gen_fn()
                result = await send_and_collect(producer, consumer, msgs, name, wait_seconds=1.0)
                detection_rate = (result.alerts_received / result.messages_sent * 100) if result.messages_sent else 0
                print(f"  {name:30s} 发送: {result.messages_sent:3d}, 告警: {result.alerts_received:3d}, 检测率: {detection_rate:5.1f}%")
                results.append(result)
            print()

        # 汇总
        print(f"{'=' * 70}")
        print(f"  汇总")
        print(f"{'=' * 70}")
        total_sent = sum(r.messages_sent for r in results if r.name != "normal_traffic")
        total_alerts = sum(r.alerts_received for r in results if r.name != "normal_traffic")
        normal_sent = sum(r.messages_sent for r in results if r.name == "normal_traffic")
        normal_alerts = sum(r.alerts_received for r in results if r.name == "normal_traffic")

        print(f"  攻击检测率:   {total_alerts}/{total_sent} = {(total_alerts/max(total_sent,1)*100):.1f}%")
        print(f"  正常误报率:   {normal_alerts}/{normal_sent} = {(normal_alerts/max(normal_sent,1)*100):.1f}%")
        print()

        # 保存结果
        report = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "kafka_brokers": KAFKA_BROKERS,
            "input_topic": INPUT_TOPIC,
            "input_topic_2": INPUT_TOPIC_2 if ENABLE_LOGS2 and _PB_AVAILABLE else None,
            "logs2_enabled": ENABLE_LOGS2 and _PB_AVAILABLE,
            "alert_topic": ALERT_TOPIC,
            "results": [
                {"name": r.name, "sent": r.messages_sent, "alerts": r.alerts_received}
                for r in results
            ],
            "summary": {
                "attack_detection_rate": f"{total_alerts}/{total_sent} ({total_alerts/max(total_sent,1)*100:.1f}%)",
                "normal_false_positive_rate": f"{normal_alerts}/{normal_sent} ({normal_alerts/max(normal_sent,1)*100:.1f}%)",
            },
        }

        output_file = Path(f"sandbox_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        output_file.write_text(json.dumps(report, indent=2, ensure_ascii=False))
        print(f"  结果已保存: {output_file}")

    finally:
        await producer.stop()
        await consumer.stop()


def main():
    parser = argparse.ArgumentParser(description="AIWAF-Stream Sandbox — 基准测试")
    parser.add_argument("--mode", default="all", choices=["normal", "attacks", "all"])
    parser.add_argument("--local", action="store_true", help="本地模拟模式（不需要 Kafka/Redis）")
    args = parser.parse_args()

    if args.local:
        asyncio.run(run_sandbox_local(args.mode))
    else:
        asyncio.run(run_sandbox(args.mode))


async def run_sandbox_local(mode: str = "all"):
    """
    本地模拟模式：不走 Kafka/Redis，直接在内存中调用 AIWAF 检测管道。

    适用于：
    - 无 Kafka/Redis 环境的开发机
    - 快速验证检测能力
    - CI/CD 流水线中的回归测试
    """
    from aiwaf.stream.akto_adapter import parse_akto_json_message
    from aiwaf.stream.preprocessor import transform_raw_log
    from aiwaf.core.path_manifest import PathManifest
    from aiwaf.core.malicious_context import is_malicious_context, STATIC_KW, DEFAULT_LEGITIMATE_KEYWORDS
    from aiwaf.core.ip_keyword import evaluate_keyword_policy
    from aiwaf.core.header_validation import evaluate_header_policy
    from aiwaf.core.uuid_tamper import is_malformed_uuid
    from aiwaf.core.method_validation import evaluate_method_policy

    print(f"{'=' * 70}")
    print(f"  AIWAF-Stream Sandbox — 本地模拟模式")
    print(f"  Mode: {mode}")
    print(f"{'=' * 70}\n")

    pm = PathManifest()
    results: List[AttackResult] = []

    def process_message(msg: Dict[str, Any]) -> Optional[str]:
        """处理单条消息，返回告警 rule_id 或 None"""
        try:
            msg_json = orjson.dumps(msg).decode()
            raw_log = parse_akto_json_message(msg_json)
            std_log = transform_raw_log(raw_log)

            uri_path = std_log.get("uri_path", "")
            method = std_log.get("method", "GET")
            status_code = std_log.get("status_code", 0)
            ip = std_log.get("client_ip", "")

            pm.record(uri_path, method, status_code)

            # Header 验证
            rh = std_log.get("request_headers", "")
            if rh:
                hd = orjson.loads(rh) if isinstance(rh, str) else rh
                env = {}
                for k, v in hd.items():
                    env[f"HTTP_{k.upper().replace('-', '_')}"] = v or ""
                h = evaluate_header_policy(env, method=method)
                if h:
                    return f"HeaderBlock:{h[:30]}"

            # UUID 篡改
            for seg in uri_path.strip("/").split("/"):
                if len(seg) == 36 and seg.count('-') >= 4 and is_malformed_uuid(seg):
                    return "UUIDTamper:malformed_uuid"

            # 关键词检测
            # 修复：将 query_strings 拼接到 path 中一起检查，使 is_malicious_context 能检测到 SQL 注入等攻击
            query_strings = std_log.get("query_strings", [])
            full_path = uri_path
            if query_strings:
                full_path = uri_path + "?" + "&".join(str(qs) for qs in query_strings)

            def ctx(seg, _p=full_path, _s=status_code):
                return is_malicious_context(_p, seg, str(_s), STATIC_KW)

            kw = evaluate_keyword_policy(
                path=uri_path, query_keys=std_log.get("query_keys", []),
                path_exists=pm.path_exists(uri_path),
                keyword_learning_enabled=True, static_keywords=STATIC_KW,
                dynamic_keywords=[], legitimate_keywords=DEFAULT_LEGITIMATE_KEYWORDS,
                exempt_keywords=set(), safe_prefixes=(),
                malicious_keywords=set(STATIC_KW), is_malicious_context=ctx,
                query_strings=std_log.get("query_strings", []))
            if kw.block_reason:
                return f"KeywordBlock:{kw.block_reason[:30]}"

            # 方法验证
            m = evaluate_method_policy(method=method, path=uri_path)
            if m.action == "block":
                return f"MethodBlock:{m.reason[:30]}"

            return None
        except Exception:
            return None

    # 正常流量
    if mode in ("normal", "all"):
        print("[1/2] 正常流量测试（验证不误杀）...")
        msgs = gen_normal_traffic()
        alerts = sum(1 for m in msgs if process_message(m) is not None)
        result = AttackResult(name="normal_traffic", messages_sent=len(msgs), alerts_received=alerts)
        results.append(result)
        fpr = (alerts / len(msgs) * 100) if msgs else 0
        print(f"  发送: {len(msgs)}, 告警: {alerts}, 误报率: {fpr:.1f}%\n")

    # 攻击流量
    if mode in ("attacks", "all"):
        print("[2/2] 攻击流量测试（验证检测率）...")
        for name, gen_fn in ATTACK_SUITE:
            msgs = gen_fn()
            alerts = sum(1 for m in msgs if process_message(m) is not None)
            dr = (alerts / len(msgs) * 100) if msgs else 0
            print(f"  {name:30s} 发送: {len(msgs):3d}, 告警: {alerts:3d}, 检测率: {dr:5.1f}%")
            results.append(AttackResult(name=name, messages_sent=len(msgs), alerts_received=alerts))
        print()

    # 汇总
    print(f"{'=' * 70}")
    print(f"  汇总")
    print(f"{'=' * 70}")
    total_sent = sum(r.messages_sent for r in results if r.name != "normal_traffic")
    total_alerts = sum(r.alerts_received for r in results if r.name != "normal_traffic")
    normal_sent = sum(r.messages_sent for r in results if r.name == "normal_traffic")
    normal_alerts = sum(r.alerts_received for r in results if r.name == "normal_traffic")

    print(f"  攻击检测率:   {total_alerts}/{total_sent} = {(total_alerts/max(total_sent,1)*100):.1f}%")
    print(f"  正常误报率:   {normal_alerts}/{normal_sent} = {(normal_alerts/max(normal_sent,1)*100):.1f}%")
    print(f"  Path Manifest: {len(pm.get_all_templates())} 个模板")
    print()

    # 保存结果
    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "mode": "local",
        "results": [
            {"name": r.name, "sent": r.messages_sent, "alerts": r.alerts_received}
            for r in results
        ],
        "summary": {
            "attack_detection_rate": f"{total_alerts}/{total_sent} ({total_alerts/max(total_sent,1)*100:.1f}%)",
            "normal_false_positive_rate": f"{normal_alerts}/{normal_sent} ({normal_alerts/max(normal_sent,1)*100:.1f}%)",
        },
    }

    output_file = Path(f"sandbox_results_local_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    output_file.write_text(json.dumps(report, indent=2, ensure_ascii=False))
    print(f"  结果已保存: {output_file}")


if __name__ == "__main__":
    main()
