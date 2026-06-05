"""
Airflow DAG: 离线模型训练与规则快照同步
"""
from concurrent.futures import ProcessPoolExecutor
from aiwaf.core.ip_keyword import evaluate_keyword_policy


def _default_malicious_context(seg: str) -> bool:
    """默认恶意上下文判定：生产环境替换为 ML 模型。"""
    return False


def _process_row_purifier(args):
    """子进程行级处理，纯函数参数注入。
    直接对接真实 evaluate_keyword_policy，不做任何包装。
    """
    row_dict, dynamic_kws = args
    kw_dec = evaluate_keyword_policy(
        path=row_dict.get('uri_path', '/'),
        query_keys=row_dict.get('query_keys', []),
        path_exists=False,
        keyword_learning_enabled=False,
        static_keywords=(),
        dynamic_keywords=dynamic_kws,
        legitimate_keywords=set(),
        exempt_keywords=set(),
        safe_prefixes=(),
        malicious_keywords=set(),
        is_malicious_context=_default_malicious_context,
    )
    return not kw_dec.block_reason
