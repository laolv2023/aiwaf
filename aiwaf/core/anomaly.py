"""
异常检测引擎（纯 Python 实现）

移植自 aiwaf-project/aiwaf 的 aiwaf/core/anomaly.py。
去除了 Rust 后端和 sklearn 依赖，保留纯 Python 的行为分析逻辑。

功能：
  - analyze_recent_behavior_python: 基于历史请求的行为统计（404率、关键词命中、突发请求）
  - build_feature_vector: 构建特征向量（供未来 ML 模型使用）
  - evaluate_anomaly: 综合异常评估（行为统计 + 扫描路径检测）
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Callable, List, Optional, Sequence, Tuple, Any

from .constants import STATUS_IDX as DEFAULT_STATUS_IDX
from .malicious_context import is_scanning_path


HistoryEntry = Tuple[float, str, int, float]  # (timestamp, path, status_code, response_time)


@dataclass(frozen=True)
class AnomalyStats:
    avg_kw_hits: float
    max_404s: int
    avg_burst: float
    total_requests: int
    scanning_404s: int
    legitimate_404s: int
    should_block: bool


@dataclass(frozen=True)
class AnomalyOutcome:
    block: bool
    reason: Optional[str]
    learned_keywords: List[str]
    updated_history: List[HistoryEntry]


def compute_kw_hits(path_lower: str, static_keywords: Sequence[str]) -> int:
    return sum(1 for kw in static_keywords if kw and str(kw) in path_lower)


def trim_history(history: Sequence[HistoryEntry], *, now: float, window_seconds: float) -> List[HistoryEntry]:
    window = max(float(window_seconds), 1.0)
    return [h for h in list(history or []) if now - float(h[0]) < window]


def extract_segments(path: str) -> List[str]:
    return [seg for seg in re.split(r"\W+", (path or "").lower()) if len(seg) > 3]


def analyze_recent_behavior_python(
    recent_data: Sequence[HistoryEntry],
    *,
    static_keywords: Sequence[str],
    path_exists: Callable[[str], bool],
    is_exempt_path: Callable[[str], bool],
) -> AnomalyStats:
    recent_kw_hits: List[int] = []
    recent_404s = 0
    recent_burst_counts: List[int] = []
    scanning_404s = 0

    for entry_time, entry_path, entry_status, _entry_resp_time in list(recent_data or []):
        entry_known_path = bool(path_exists(entry_path))
        entry_kw_hits = 0
        if (not entry_known_path) and (not bool(is_exempt_path(entry_path))):
            entry_kw_hits = compute_kw_hits(str(entry_path).lower(), static_keywords)
        recent_kw_hits.append(entry_kw_hits)

        if int(entry_status) == 404:
            recent_404s += 1
            if is_scanning_path(entry_path):
                scanning_404s += 1

        entry_burst = sum(1 for (t, _p, _s, _rt) in recent_data if abs(float(entry_time) - float(t)) <= 10)
        recent_burst_counts.append(entry_burst)

    avg_kw_hits = (sum(recent_kw_hits) / len(recent_kw_hits)) if recent_kw_hits else 0.0
    max_404s = int(recent_404s)
    avg_burst = (sum(recent_burst_counts) / len(recent_burst_counts)) if recent_burst_counts else 0.0
    total_requests = int(len(recent_data or []))
    legitimate_404s = int(max_404s - scanning_404s)

    should_block = not (
        avg_kw_hits < 3
        and scanning_404s < 5
        and legitimate_404s < 20
        and avg_burst < 25
        and total_requests < 150
    )
    if avg_kw_hits == 0 and max_404s == 0:
        should_block = False

    return AnomalyStats(
        avg_kw_hits=avg_kw_hits,
        max_404s=max_404s,
        avg_burst=avg_burst,
        total_requests=total_requests,
        scanning_404s=int(scanning_404s),
        legitimate_404s=int(legitimate_404s),
        should_block=bool(should_block),
    )


def build_feature_vector(
    *,
    path: str,
    status_code: int,
    response_time: float,
    now: float,
    history: Sequence[HistoryEntry],
    static_keywords: Sequence[str],
    status_index_values: Sequence[str] = DEFAULT_STATUS_IDX,
    path_exists_current: bool,
    is_exempt_path_current: bool,
) -> List[float]:
    path_len = len(path or "")
    kw_hits = 0
    if (not path_exists_current) and (not is_exempt_path_current):
        kw_hits = compute_kw_hits((path or "").lower(), static_keywords)

    status_code_str = str(int(status_code))
    status_idx = status_index_values.index(status_code_str) if status_code_str in status_index_values else -1
    burst_count = sum(1 for (t, _p, _s, _rt) in history if now - float(t) <= 10)
    total_404 = sum(1 for (_t, _p, s, _rt) in history if int(s) == 404)
    return [float(path_len), float(kw_hits), float(response_time), float(status_idx), float(burst_count), float(total_404)]


def evaluate_anomaly(
    *,
    ip: str,
    path: str,
    status_code: int,
    response_time: float,
    now: float,
    history: Sequence[HistoryEntry],
    window_seconds: float,
    model: Any = None,
    static_keywords: Sequence[str] = None,
    malicious_keywords: Sequence[str] = None,
    keyword_learning_enabled: bool = True,
    path_exists: Callable[[str], bool] = None,
    is_exempt_path: Callable[[str], bool] = None,
    is_malicious_context: Callable[[str], bool] = None,
    status_index_values: Sequence[str] = DEFAULT_STATUS_IDX,
    legitimate_keywords: Optional[set] = None,
) -> AnomalyOutcome:
    """
    综合异常评估。无 ML 模型时，基于行为统计判定。

    移植自官方仓库，适配说明：
    - path_exists 恒返回 False（流式版本无框架路由）
    - is_exempt_path 使用 exemptions 模块
    - model 参数保留但不使用（未来可接入 sklearn）
    """
    static_keywords = static_keywords or []
    malicious_keywords = malicious_keywords or []
    legitimate_keywords = legitimate_keywords or set()
    
    if path_exists is None:
        path_exists = lambda _: False
    if is_exempt_path is None:
        is_exempt_path = lambda _: False
    if is_malicious_context is None:
        is_malicious_context = lambda _: False

    trimmed = trim_history(history, now=now, window_seconds=window_seconds)
    path_exists_current = bool(path_exists(path))
    exempt_current = bool(is_exempt_path(path))

    feats = build_feature_vector(
        path=path,
        status_code=status_code,
        response_time=response_time,
        now=now,
        history=trimmed,
        static_keywords=static_keywords,
        status_index_values=status_index_values,
        path_exists_current=path_exists_current,
        is_exempt_path_current=exempt_current,
    )

    block = False
    reason = None

    # 无 ML 模型时，使用行为统计判定
    recent_data = [d for d in trimmed if now - float(d[0]) <= 300]
    stats = analyze_recent_behavior_python(
        recent_data,
        static_keywords=malicious_keywords,
        path_exists=path_exists,
        is_exempt_path=is_exempt_path,
    )
    if stats and stats.should_block:
        reason = (
            f"Behavioral anomaly "
            f"(404s:{stats.max_404s}, scanning:{stats.scanning_404s}, "
            f"kw:{stats.avg_kw_hits:.1f}, burst:{stats.avg_burst:.1f})"
        )
        block = True

    updated = list(trimmed)
    updated.append((float(now), str(path), int(status_code), float(response_time)))
    updated = trim_history(updated, now=now, window_seconds=window_seconds)

    learned_keywords: List[str] = []
    if (
        keyword_learning_enabled
        and int(status_code) == 404
        and (not path_exists_current)
        and (not exempt_current)
    ):
        for seg in extract_segments(path):
            if (
                seg not in legitimate_keywords
                and is_malicious_context(seg)
            ):
                learned_keywords.append(seg)

    return AnomalyOutcome(
        block=bool(block),
        reason=reason,
        learned_keywords=learned_keywords,
        updated_history=updated,
    )
