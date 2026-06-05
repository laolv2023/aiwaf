"""
Airflow DAG: 离线模型训练与规则快照同步
"""
from concurrent.futures import ProcessPoolExecutor
from aiwaf.core.ip_keyword import evaluate_keyword_policy


def _process_row_purifier(args):
    """子进程行级处理，纯函数参数注入"""
    row_dict, dynamic_kws = args
    kw_dec = evaluate_keyword_policy(
        path=row_dict.get('uri_path', '/'),
        query_keys=row_dict.get('query_keys', []),
        query_strings=row_dict.get('query_strings', []),
        dynamic_keywords=dynamic_kws,
        offline_mode=True
    )
    return not kw_dec.block_reason
