"""
Akto Kafka 数据源适配层

将 akto.api.logs Topic 的 JSON 消息转换为 AIWAF preprocessor.transform_raw_log 期望的格式。

字段映射说明：
  - Akto 所有字段均为 String 类型（包括 statusCode 和 time）
  - 适配层负责类型转换：statusCode → int, time → float
  - path 含完整 URI（含 query string），需用 urlparse 拆分
  - 输出键名必须与 transform_raw_log 的读取键名精确匹配

参考文档: docs/AIWAF_Akto_Integration_Design.md §3.1
"""
import orjson
from urllib.parse import urlparse, parse_qs
from typing import Dict, Any


def parse_akto_json_message(raw_json: str) -> Dict[str, Any]:
    """
    将 akto.api.logs 的 JSON 消息转为 transform_raw_log 期望的格式。

    Args:
        raw_json: JSON 字符串或已解析的 dict

    Returns:
        raw_log dict，包含 7 个核心字段 + 6 个 akto 扩展字段

    Raises:
        orjson.JSONDecodeError: JSON 解析失败
    """
    msg = orjson.loads(raw_json) if isinstance(raw_json, (str, bytes)) else raw_json

    # 防御：orjson.loads 可能返回 list/str/number 等非 dict 类型
    if not isinstance(msg, dict):
        raise ValueError(f"Expected JSON object, got {type(msg).__name__}")

    # path 含完整 URI（含 query string），需拆分
    # 兼容两种格式：纯路径 "/api/v1" 或完整 URL "https://host/api/v1?foo=bar"
    raw_path = msg.get("path", "/") or "/"
    if "://" in raw_path:
        parsed = urlparse(raw_path)
    else:
        parsed = urlparse(f"http://dummy{raw_path}")

    # transform_raw_log 期望 query_params 是 dict（key → str 或 list）
    query_params = {}
    for k, v in parse_qs(parsed.query).items():
        query_params[k] = v[0] if len(v) == 1 else v

    # statusCode 和 time 在 akto.api.logs 中是 String 类型，需转 int/float
    # 兼容已转换的 int/float 输入（int(int) 和 float(float) 均安全）
    status_code = msg.get("statusCode", "200")
    try:
        status_int = int(status_code)
    except (ValueError, TypeError):
        status_int = 200

    time_str = msg.get("time", "0")
    try:
        timestamp = float(time_str)
    except (ValueError, TypeError):
        timestamp = 0.0

    # ── V6.0 补丁：提取原生 api_collection_id ──
    # 依据《V6.0 设计》第 2 节"协议映射契约"：
    #   api_collection_id (HttpResponseParam 字段 6) → latest_api_collection_id (MaliciousEventMessage 字段 7)
    #
    # Akto JSON 格式中 apiCollectionId 的来源（源码级对齐）：
    #   - HttpCallParser.parseKafkaMessage 使用 akto_vxlan_id 作为 apiCollectionId
    #   - 部分版本可能直接包含 apiCollectionId / api_collection_id 字段
    # 因此按优先级提取：apiCollectionId > api_collection_id > akto_vxlan_id
    api_collection_id_raw = (
        msg.get("apiCollectionId")
        or msg.get("api_collection_id")
        or msg.get("akto_vxlan_id")
        or "0"
    )
    try:
        api_collection_id = int(api_collection_id_raw)
    except (ValueError, TypeError):
        api_collection_id = 0

    # ── V6.0 补丁：提取 host 字段 ──
    # host 用于 MaliciousEventMessage.host (字段 17)
    # 优先从 JSON 顶层获取，其次从 requestHeaders 中解析 Host 头
    host = msg.get("host", "")
    if not host:
        try:
            headers_str = msg.get("requestHeaders", "")
            if headers_str:
                # orjson.loads 返回 dict；兼容已解析的 dict 输入
                headers_obj = orjson.loads(headers_str) if isinstance(headers_str, str) else headers_str
                if isinstance(headers_obj, dict):
                    # HTTP 头部大小写不敏感，尝试多种大小写
                    host = headers_obj.get("Host") or headers_obj.get("host") or headers_obj.get("HOST") or ""
        except (orjson.JSONDecodeError, TypeError, ValueError):
            pass

    return {
        # transform_raw_log 直接读取的字段（键名必须匹配）
        "client_ip": msg.get("ip") or msg.get("client_ip") or "unknown",
        "timestamp": timestamp,
        "method": msg.get("method", "GET"),
        "uri_path": parsed.path or "/",
        "query_params": query_params,   # transform_raw_log 读取此字段
        "status": status_int,           # transform_raw_log 读取 raw_log.get("status", 200)
        "request_body": msg.get("requestPayload", "") or "",
        # akto 扩展字段（透传到告警，需 preprocessor.py 透传支持）
        "akto_account_id": msg.get("akto_account_id", ""),
        "akto_vxlan_id": msg.get("akto_vxlan_id", ""),
        "source": msg.get("source", ""),
        "direction": msg.get("direction", ""),
        "dest_ip": msg.get("destIp", ""),
        "response_payload": msg.get("responsePayload", ""),
        "request_headers": msg.get("requestHeaders", ""),  # JSON string
        "response_headers": msg.get("responseHeaders", ""),
        "request_uuid": msg.get("request_uuid", "") or msg.get("requestUuid", ""),  # 源端 UUID（可选）
        # V6.0 新增透传字段
        "api_collection_id": api_collection_id,  # 原生 Collection ID（int32，透传至 latest_api_collection_id）
        "host": host,                            # 请求 Host（透传至 MaliciousEventMessage.host）
    }


def _pb_headers_to_json_str(pb_headers) -> str:
    """将 protobuf map<string, StringList> 转为 JSON string

    对齐 parse_akto_json_message 的输出格式：requestHeaders/responseHeaders 为 JSON string
    """
    if not pb_headers:
        return "{}"
    try:
        import orjson
        result = {}
        for k, v in pb_headers.items():
            values = list(v.values) if v.values else []
            if len(values) == 1:
                result[k] = values[0]
            else:
                result[k] = values
        return orjson.dumps(result).decode()
    except Exception:
        return "{}"


def parse_akto_pb_message(raw_bytes: bytes) -> Dict[str, Any]:
    """将 akto.api.logs2 的 Protobuf 消息转为 transform_raw_log 期望的格式

    与 parse_akto_json_message 输出格式完全一致，仅输入不同（Protobuf vs JSON）

    Args:
        raw_bytes: Protobuf 序列化的 HttpResponseParam 二进制数据

    Returns:
        raw_log dict，与 parse_akto_json_message 返回值结构相同

    Raises:
        Exception: Protobuf 解析失败
    """
    from message_pb2 import HttpResponseParam

    pb = HttpResponseParam()
    pb.ParseFromString(raw_bytes)

    # 从 protobuf map 中提取 host
    host = ""
    for k, v in pb.request_headers.items():
        if k.lower() == "host" and v.values:
            host = v.values[0]
            break

    # api_collection_id: int32 → int
    api_collection_id = pb.api_collection_id

    # path 含完整 URI（含 query string），需用 urlparse 拆分
    raw_path = pb.path or "/"
    parsed = urlparse(raw_path)
    query_params = {k: v[0] if len(v) == 1 else v for k, v in parse_qs(parsed.query).items()}

    # time: int32 秒级 → float
    timestamp = float(pb.time) if pb.time else 0.0

    # statusCode: int32 → int
    status_int = pb.status_code if pb.status_code else 200

    return {
        "client_ip": pb.ip or "unknown",
        "timestamp": timestamp,
        "method": pb.method or "GET",
        "uri_path": parsed.path or "/",
        "query_params": query_params,
        "status": status_int,
        "request_body": pb.request_payload or "",
        "akto_account_id": pb.akto_account_id or "",
        "akto_vxlan_id": pb.akto_vxlan_id or "",
        "source": pb.source or "",
        "direction": pb.direction or "",
        "dest_ip": pb.dest_ip or "",
        "response_payload": pb.response_payload or "",
        "request_headers": _pb_headers_to_json_str(pb.request_headers),
        "response_headers": _pb_headers_to_json_str(pb.response_headers),
        "request_uuid": "",
        "api_collection_id": api_collection_id,
        "host": host,
    }
