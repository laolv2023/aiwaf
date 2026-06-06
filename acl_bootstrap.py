"""
AIWAF-Stream 运行时防腐层 (ACL) 与子进程环境
"""
import orjson
from dataclasses import dataclass, field
from typing import List, Tuple, Any

from aiwaf.core.rate_limit import evaluate_rate_limit
from aiwaf.core.ip_keyword import evaluate_keyword_policy


@dataclass
class ItemErrorResult:
    """单条消息处理失败的包装类，确保 100% 可序列化"""
    trace_id: str
    error_type: str
    error_msg: str
    side_effects: dict = field(default_factory=dict)


@dataclass
class ItemSuccessResult:
    """单条消息处理成功的包装类"""
    trace_id: str
    rl_decision: Any
    kw_decision: Any
    side_effects: dict


class ProcessLocalCollector:
    """替代 AIWAF 原生的全局 Redis/CSV Store，将同步写操作转化为内存追加"""
    def __init__(self):
        self.blocked_ips: List[Tuple[str, str]] = []
        self.learned_keywords: List[str] = []

    def block_ip(self, ip: str, reason: str, extended_request_info: Any = None) -> None:
        self.blocked_ips.append((ip, reason))

    def is_blocked(self, ip: str) -> bool:
        return False

    def add_keyword(self, kw: str, count: int = 1) -> None:
        self.learned_keywords.append(kw)

    def get_top_keywords(self, n: int = 50) -> List[str]:
        return []

    def extract_and_clear(self) -> dict:
        """原子级提取并清空副作用，防止跨请求污染"""
        effects = {'blocked_ips': list(self.blocked_ips), 'learned_keywords': list(self.learned_keywords)}
        self.blocked_ips.clear()
        self.learned_keywords.clear()
        return effects


_collector = ProcessLocalCollector()
_local_model = None


def _default_malicious_context(seg: str) -> bool:
    """默认恶意上下文判定：生产环境替换为 ML 模型。"""
    return False


def init_worker(model_path: str):
    """ProcessPoolExecutor 的 initializer，在子进程启动时加载 AI 模型"""
    global _local_model
    import joblib
    _local_model = joblib.load(model_path)


def run_core_logic_batch_isolated(
    batch_logs_json: List[bytes],
    batch_timestamps: List[list],
    batch_event_times: List[float],
    dynamic_kws: List[str],
    static_keywords: tuple = (),
    legitimate_keywords: set = None,
    exempt_keywords: set = None,
    safe_prefixes: tuple = (),
    malicious_keywords: set = None,
    flood_threshold: int = 150,
    keyword_learning_enabled: bool = True,
) -> List[Any]:
    """子进程批量执行入口，逐条容错"""
    if legitimate_keywords is None:
        legitimate_keywords = set()
    if exempt_keywords is None:
        exempt_keywords = set()
    if malicious_keywords is None:
        malicious_keywords = set()

    batch_results = []
    for i, log_json in enumerate(batch_logs_json):
        trace_id = "unknown"
        side_effects = {}
        try:
            std_log = orjson.loads(log_json)
            trace_id = std_log.get("trace_id", "unknown")

            rl_dec = evaluate_rate_limit(
                timestamps=batch_timestamps[i],
                now=batch_event_times[i],
                window_seconds=60,
                max_requests=100,
                flood_threshold=flood_threshold,
            )
            kw_dec = evaluate_keyword_policy(
                path=std_log["uri_path"],
                query_keys=std_log.get("query_keys", []),
                path_exists=False,
                keyword_learning_enabled=keyword_learning_enabled,
                static_keywords=static_keywords,
                dynamic_keywords=dynamic_kws,
                legitimate_keywords=legitimate_keywords,
                exempt_keywords=exempt_keywords,
                safe_prefixes=safe_prefixes,
                malicious_keywords=malicious_keywords,
                is_malicious_context=_default_malicious_context,
            )

            # 先提取副作用到局部变量，再构造 Result
            side_effects = _collector.extract_and_clear()
            try:
                batch_results.append(ItemSuccessResult(trace_id, rl_dec, kw_dec, side_effects))
            except Exception:
                batch_results.append(ItemErrorResult(trace_id, "ItemSuccessResult", "dataclass construction failed", side_effects))
        except Exception as e:
            side_effects = _collector.extract_and_clear()
            batch_results.append(ItemErrorResult(trace_id, type(e).__name__, str(e), side_effects))
    return batch_results
