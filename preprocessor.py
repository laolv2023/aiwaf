"""
预处理引擎：零信任指纹、Query 参数保真、Body 降维与标准化
"""
import hashlib
import orjson
from typing import Dict, Any

MAX_BODY_HASH_BYTES = 10 * 1024 * 1024  # 10MB 防御性截断阈值 (适应文件上传)
MAX_BODY_STORE_BYTES = 1024             # 1KB 存储截断阈值


def generate_deterministic_trace_id(std_log: dict) -> str:
    """零信任流式指纹：基于完整 Body bytes 计算，杜绝截断碰撞"""
    ip = std_log.get("client_ip", "")
    uri = std_log.get("uri_path", "")
    ts = str(std_log.get("timestamp", ""))

    raw_body = std_log.get("request_body", "")

    # 强制处理 dict/list 等非字符串类型，防止 hashlib.update() 崩溃
    if isinstance(raw_body, str):
        raw_body_bytes = raw_body.encode('utf-8')
    elif isinstance(raw_body, bytes):
        raw_body_bytes = raw_body
    else:
        raw_body_bytes = orjson.dumps(raw_body)  # dict/list 自动序列化为标准 JSON

    # 对完整 bytes 进行 Hash，仅在超长时截断防 OOM
    if len(raw_body_bytes) > MAX_BODY_HASH_BYTES:
        raw_body_bytes = raw_body_bytes[:MAX_BODY_HASH_BYTES]

    body_hasher = hashlib.md5()
    body_hasher.update(raw_body_bytes)
    body_hash = body_hasher.hexdigest()

    raw = f"{ip}|{uri}|{body_hash}|{ts}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]  # 128-bit effective


def transform_raw_log(raw_log: dict) -> dict:
    """将原始日志转换为 AIWAF 标准格式"""
    # 保留 Query 参数的 Key=Value 结构，兼容列表展开，防止 SQLi/XSS 漏报
    query_params = raw_log.get("query_params", {})
    query_strings = []
    query_keys = []
    if isinstance(query_params, dict):
        for k, v in query_params.items():
            query_keys.append(k)
            if isinstance(v, list):
                for item in v:
                    query_strings.append(f"{k}={item}")  # 还原 HTTP 语义
            else:
                query_strings.append(f"{k}={v}")

    std_log = {
        "client_ip": raw_log.get("client_ip") or raw_log.get("remote_addr"),
        "timestamp": raw_log.get("timestamp"),
        "method": raw_log.get("method", "GET"),
        "uri_path": raw_log.get("uri_path", "/"),
        "query_keys": query_keys,
        "query_strings": query_strings,
        "status_code": raw_log.get("status", 200),
        "request_body": raw_log.get("request_body", "")
    }

    std_log["trace_id"] = generate_deterministic_trace_id(std_log)

    # Body 降维截断 (仅用于存储和 DLQ，不影响指纹)
    raw_body = std_log["request_body"]
    if isinstance(raw_body, str):
        raw_body_str = raw_body
    elif isinstance(raw_body, bytes):
        raw_body_str = raw_body.decode('utf-8', errors='ignore')
    else:
        raw_body_str = orjson.dumps(raw_body).decode('utf-8')  # 确保 DLQ 消费者可解析

    std_log["req_body_truncated"] = raw_body_str[:MAX_BODY_STORE_BYTES]
    del std_log["request_body"]  # 释放主进程内存

    return std_log
