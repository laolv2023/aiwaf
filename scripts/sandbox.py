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

try:
    from aiokafka import AIOKafkaProducer, AIOKafkaConsumer
except ImportError:
    print("Error: pip install aiokafka")
    sys.exit(1)

import orjson

# ── 配置 ──

KAFKA_BROKERS = os.getenv("KAFKA_BROKERS", "localhost:9092")
INPUT_TOPIC = os.getenv("KAFKA_INPUT_TOPIC", "akto.api.logs")
ALERT_TOPIC = os.getenv("KAFKA_ALERT_TOPIC", "akto.aiwaf.alerts")

# ── Akto 消息构建 ──

_time_counter = int(time.time())

def _next_time() -> str:
    global _time_counter
    _time_counter += 1
    return str(_time_counter)

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
    """构建 Akto 格式的 Kafka 消息"""
    headers = {
        "user-agent": user_agent,
        "accept": accept,
        "host": "api.example.com",
        "connection": "Keep-Alive",
    }
    if method in ("POST", "PUT", "PATCH"):
        headers["content-type"] = "application/json"
        headers["content-length"] = str(len(request_body))

    return {
        "path": path,
        "method": method,
        "requestHeaders": orjson.dumps(headers).decode(),
        "responseHeaders": orjson.dumps({"content-type": "application/json"}).decode(),
        "requestPayload": request_body,
        "responsePayload": "",
        "ip": ip,
        "destIp": dest_ip,
        "time": _next_time(),
        "statusCode": status_code,
        "status": "OK" if status_code == "200" else "Error",
        "akto_account_id": "1000000",
        "akto_vxlan_id": "1",
        "source": "MIRRORING",
        "direction": "REQUEST",
    }


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
    """发送一批消息到 Kafka，等待并收集告警"""
    sent = len(messages)

    # 发送消息
    for msg in messages:
        await producer.send_and_wait(INPUT_TOPIC, orjson.dumps(msg))

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
    print(f"  Input: {INPUT_TOPIC}")
    print(f"  Alert: {ALERT_TOPIC}")
    print(f"  Mode:  {mode}")
    print(f"{'=' * 70}\n")

    producer = AIOKafkaProducer(bootstrap_servers=KAFKA_BROKERS, value_deserializer=lambda v: v)
    consumer = AIOKafkaConsumer(
        ALERT_TOPIC,
        bootstrap_servers=KAFKA_BROKERS,
        group_id="sandbox-consumer",
        auto_offset_reset="latest",
        value_deserializer=lambda v: v,
    )

    await producer.start()
    await consumer.start()

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
    args = parser.parse_args()
    asyncio.run(run_sandbox(args.mode))


if __name__ == "__main__":
    main()
