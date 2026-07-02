#!/usr/bin/env python3
"""
端到端验证脚本：从真实 Kafka 消费 Akto 消息，走完整个管道

支持两种消息格式:
    --format json   消费 akto.api.logs  (JSON 字符串)
    --format pb     消费 akto.api.logs2 (Protobuf 二进制)

使用方法:
    # 验证 logs (JSON, 默认)
    KAFKA_BROKERS=localhost:29092 python verify_akto_logs.py

    # 验证 logs2 (Protobuf)
    KAFKA_BROKERS=localhost:29092 python verify_akto_logs.py --format pb

参考文档: docs/AIWAF_Akto_Integration_Design.md §4.3
"""
import argparse
import asyncio
import os
import sys

from aiokafka import AIOKafkaConsumer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # 项目根目录

from aiwaf.stream.akto_adapter import parse_akto_json_message, parse_akto_pb_message
from aiwaf.stream.preprocessor import transform_raw_log


async def verify(fmt: str = "json"):
    """从 Kafka 消费 10 条消息，验证完整管道

    Args:
        fmt: 消息格式 — "json" 消费 logs, "pb" 消费 logs2
    """
    brokers = os.getenv("KAFKA_BROKERS", "localhost:29092")

    if fmt == "pb":
        # P2-01修复: 提前检查 protobuf 运行时是否可用
        try:
            from message_pb2 import HttpResponseParam  # noqa: F401
        except Exception:
            print("ERROR: protobuf 运行时不可用, 请安装: pip install protobuf")
            print("       并确保 message_pb2.py 在 scripts/ 目录或 PYTHONPATH 中")
            return
        topic = os.getenv("KAFKA_INPUT_TOPIC_2", "akto.api.logs2")
        parser = parse_akto_pb_message
        fmt_label = "pb"
    else:
        topic = os.getenv("KAFKA_INPUT_TOPIC", "akto.api.logs")
        parser = parse_akto_json_message
        fmt_label = "json"

    consumer = AIOKafkaConsumer(
        topic,
        bootstrap_servers=brokers,
        group_id="aiwaf-verify",
        auto_offset_reset="latest",
        value_deserializer=lambda v: v,
    )

    print(f"Connecting to {brokers}, topic={topic}, format={fmt_label} ...")
    await consumer.start()
    print("Connected. Waiting for messages...\n")

    count = 0
    ok = 0
    fail = 0
    try:
        async for msg in consumer:
            try:
                if fmt == "pb":
                    # Protobuf: 直接传 bytes
                    raw_log = parser(msg.value)
                else:
                    # JSON: 先 decode 再解析
                    raw_log = parser(msg.value.decode("utf-8"))
                std_log = transform_raw_log(raw_log)
                print(
                    f"[OK] [{fmt_label}] trace_id={std_log['trace_id'][:8]} "
                    f"ip={std_log['client_ip']} "
                    f"path={std_log['uri_path']} "
                    f"method={std_log['method']} "
                    f"status={std_log['status_code']}"
                )
                ok += 1
            except Exception as e:
                print(f"[FAIL] [{fmt_label}] {type(e).__name__}: {str(e)[:200]}")
                fail += 1
            count += 1
            if count >= 10:
                break
    finally:
        print(f"\nResult: {ok} ok, {fail} fail out of {count} (format={fmt_label})")
        await consumer.stop()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="验证 Akto Kafka 消息解析管道")
    parser.add_argument(
        "--format", choices=["json", "pb"], default="json",
        help="消息格式: json=akto.api.logs, pb=akto.api.logs2 (默认: json)",
    )
    args = parser.parse_args()
    asyncio.run(verify(args.format))
