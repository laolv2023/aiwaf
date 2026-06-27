#!/usr/bin/env python3
"""
端到端验证脚本：从真实 Kafka 消费 akto.api.logs 消息，走完整个管道

使用方法:
    KAFKA_BROKERS=localhost:29092 python verify_akto_logs.py

参考文档: docs/AIWAF_Akto_Integration_Design.md §4.3
"""
import asyncio
import os
import sys

from aiokafka import AIOKafkaConsumer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from akto_adapter import parse_akto_json_message
from preprocessor import transform_raw_log


async def verify():
    """从 akto.api.logs 消费 10 条消息，验证完整管道"""
    brokers = os.getenv("KAFKA_BROKERS", "localhost:29092")
    topic = os.getenv("KAFKA_INPUT_TOPIC", "akto.api.logs")

    consumer = AIOKafkaConsumer(
        topic,
        bootstrap_servers=brokers,
        group_id="aiwaf-verify",
        auto_offset_reset="latest",
        value_deserializer=lambda v: v,
    )

    print(f"Connecting to {brokers}, topic={topic} ...")
    await consumer.start()
    print("Connected. Waiting for messages...\n")

    count = 0
    ok = 0
    fail = 0
    async for msg in consumer:
        try:
            raw_log = parse_akto_json_message(msg.value.decode("utf-8"))
            std_log = transform_raw_log(raw_log)
            print(
                f"[OK] trace_id={std_log['trace_id'][:8]} "
                f"ip={std_log['client_ip']} "
                f"path={std_log['uri_path']} "
                f"method={std_log['method']} "
                f"status={std_log['status_code']}"
            )
            ok += 1
        except Exception as e:
            print(f"[FAIL] {e} | raw={msg.value[:200]}")
            fail += 1
        count += 1
        if count >= 10:
            break

    print(f"\nResult: {ok} ok, {fail} fail out of {count}")
    await consumer.stop()


if __name__ == "__main__":
    asyncio.run(verify())
