"""
Airflow DAG: 离线模型训练与规则快照同步
"""
from concurrent.futures import ProcessPoolExecutor
from aiwaf.core.ip_keyword import evaluate_keyword_policy
from aiwaf.core.malicious_context import is_malicious_context, STATIC_KW


def _process_row_purifier(args):
    """子进程行级处理，纯函数参数注入。
    直接对接真实 evaluate_keyword_policy，不做任何包装。
    """
    row_dict, dynamic_kws = args
    uri_path = row_dict.get('uri_path', '/')
    status = str(row_dict.get('status_code', 0))

    def _ctx_fn(seg, _path=uri_path, _status=status):
        return is_malicious_context(_path, seg, _status, STATIC_KW)

    kw_dec = evaluate_keyword_policy(
        path=uri_path,
        query_keys=row_dict.get('query_keys', []),
        path_exists=False,
        keyword_learning_enabled=False,
        static_keywords=STATIC_KW,
        dynamic_keywords=dynamic_kws,
        legitimate_keywords=set(),
        exempt_keywords=set(),
        safe_prefixes=(),
        malicious_keywords=set(STATIC_KW),
        is_malicious_context=_ctx_fn,
    )
    return not kw_dec.block_reason
