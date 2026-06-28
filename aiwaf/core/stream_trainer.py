"""
AIWAF-Stream 批量训练器

移植自 aiwaf-project/aiwaf 的 aiwaf/django/trainer.py。
适配流式版本：从 Redis 历史窗口读取请求记录（替代日志文件解析），
训练 IsolationForest 模型，学习关键词，更新黑名单。

依赖（可选）:
  - sklearn: IsolationForest 训练
  - pandas: 特征 DataFrame
  - numpy: 数值计算
  无以上依赖时自动降级为关键词-only 模式。

数据流:
  Redis 历史请求 → 特征提取 → IsolationForest 训练 → 模型持久化
                                              → 关键词学习 → Redis
                                              → 异常 IP → Redis 黑名单
"""
import os
import re
import time
import logging
from collections import Counter, defaultdict
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple

from aiwaf.core.constants import STATUS_IDX
from aiwaf.core.malicious_context import STATIC_KW, is_malicious_context, is_scanning_path, DEFAULT_LEGITIMATE_KEYWORDS
from aiwaf.core.training_features import python_feature_from_record, python_features_batched
from aiwaf.core.rust_backend import (
    rust_available, rust_isolation_forest_available,
    rust_isolation_forest_class, is_rust_isolation_forest,
    extract_features as rust_extract_features,
)

try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    np = None
    NUMPY_AVAILABLE = False

try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    pd = None
    PANDAS_AVAILABLE = False

try:
    from sklearn.ensemble import IsolationForest
    SKLEARN_AVAILABLE = True
except ImportError:
    IsolationForest = None
    SKLEARN_AVAILABLE = False

logger = logging.getLogger(__name__)

MIN_AI_LOGS = 50  # 最小训练样本数


def train_from_records(
    records: List[Dict[str, Any]],
    *,
    legitimate_keywords: Optional[set] = None,
    keyword_learning_enabled: bool = True,
    disable_ai: bool = False,
    force_ai: bool = False,
    contamination: float = 0.05,
    n_estimators: int = 100,
    max_samples: str = "auto",
    model_save_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    从请求记录列表训练 AI 模型 + 学习关键词。

    Args:
        records: 请求记录列表，每条含 ip, path, status, timestamp, response_time
        legitimate_keywords: 合法关键词白名单
        keyword_learning_enabled: 是否启用关键词学习
        disable_ai: 禁用 AI 训练
        force_ai: 强制 AI 训练（忽略最小样本数）
        contamination: IsolationForest 污染率
        n_estimators: IsolationForest 树数
        max_samples: IsolationForest 最大样本数
        model_save_path: 模型保存路径

    Returns:
        训练结果 dict: {
            "parsed_count": int,
            "ai_trained": bool,
            "model_path": Optional[str],
            "learned_keywords": List[str],
            "blocked_ips": List[Tuple[str, str]],
        }
    """
    if legitimate_keywords is None:
        legitimate_keywords = DEFAULT_LEGITIMATE_KEYWORDS

    result = {
        "parsed_count": 0,
        "ai_trained": False,
        "model_path": None,
        "learned_keywords": [],
        "blocked_ips": [],
    }

    if not records:
        logger.info("Nothing to train on — no records.")
        return result

    parsed_count = len(records)
    result["parsed_count"] = parsed_count

    # ── 统计 IP 404 次数 ──
    ip_404: Dict[str, int] = defaultdict(int)
    for rec in records:
        if str(rec.get("status", "")).startswith("404"):
            ip_404[rec["ip"]] += 1

    # ── 构建训练记录 ──
    # training_features.py 期望 timestamp 是 datetime 对象（用于 .total_seconds()）
    from datetime import datetime as _dt
    train_records = []
    for rec in records:
        path = rec.get("path", "")
        status = str(rec.get("status", "200"))
        status_idx = STATUS_IDX.index(status) if status in STATUS_IDX else -1
        ts_raw = rec.get("timestamp", 0)
        # 统一转为 datetime 对象
        if isinstance(ts_raw, (int, float)):
            ts_dt = _dt.fromtimestamp(float(ts_raw))
        elif isinstance(ts_raw, _dt):
            ts_dt = ts_raw
        else:
            ts_dt = _dt.fromtimestamp(0)
        train_records.append({
            "ip": rec.get("ip", ""),
            "path_len": len(path),
            "path_lower": path.lower(),
            "resp_time": float(rec.get("response_time", 0.0)),
            "status": status,
            "status_idx": status_idx,  # training_features.py 需要
            "timestamp": ts_dt,         # datetime 对象 (python_feature_from_record 用)
            "timestamp_epoch": ts_dt.timestamp(),  # float (rust_backend 用)
            "kw_check": True,
            "total_404": ip_404.get(rec.get("ip", ""), 0),
        })

    # ── 关键词学习 ──
    tokens: Counter = Counter()
    token_example_paths: Dict[str, List[str]] = defaultdict(list)

    if keyword_learning_enabled:
        for rec in records:
            path = rec.get("path", "")
            status = str(rec.get("status", "200"))
            if status.startswith(("4", "5")):
                path_lower = path.lower()
                for seg in re.split(r"\W+", path_lower):
                    if (len(seg) > 3
                            and seg not in STATIC_KW
                            and seg not in legitimate_keywords
                            and is_malicious_context(seg)):
                        tokens[seg] += 1
                        if len(token_example_paths[seg]) < 5:
                            token_example_paths[seg].append(path)

        learned = []
        for kw, cnt in tokens.most_common(500):
            if (cnt >= 2 and len(kw) >= 4
                    and kw not in legitimate_keywords
                    and token_example_paths.get(kw)):
                learned.append(kw)
        result["learned_keywords"] = learned
        if learned:
            logger.info(f"Learned {len(learned)} suspicious keywords: {learned[:10]}")

    # ── AI 模型训练 ──
    if not disable_ai and not force_ai and parsed_count < MIN_AI_LOGS:
        logger.info(f"AI training skipped: {parsed_count} records < {MIN_AI_LOGS}. Falling back to keyword-only.")
        disable_ai = True

    if not disable_ai:
        if not PANDAS_AVAILABLE:
            logger.info("AI model training skipped — pandas not available.")
            disable_ai = True
        elif not SKLEARN_AVAILABLE and not rust_isolation_forest_available():
            logger.info("AI model training skipped — scikit-learn not available and Rust backend unavailable.")
            disable_ai = True

    if not disable_ai:
        logger.info("Training AI anomaly detection model...")
        try:
            # 提取特征
            ip_times: Dict[str, list] = defaultdict(list)
            for tr in train_records:
                ip_times[tr["ip"]].append(tr["timestamp"])  # datetime 对象

            feature_dicts = []
            for tr in train_records:
                feat = python_feature_from_record(tr, ip_times, STATIC_KW)
                if feat:
                    feature_dicts.append(feat)

            if not feature_dicts:
                logger.info("No features extracted — skipping AI training.")
                return result

            df = pd.DataFrame(feature_dicts)
            feature_cols = [c for c in df.columns if c != "ip"]
            X = df[feature_cols].astype(float).values

            use_rust_ai = rust_isolation_forest_available()

            if use_rust_ai:
                rust_cls = rust_isolation_forest_class()
                model = rust_cls(
                    n_estimators=n_estimators,
                    max_samples=max_samples,
                    contamination=contamination,
                )
                model.fit(X.tolist())
            else:
                model = IsolationForest(
                    n_estimators=n_estimators,
                    max_samples=max_samples,
                    contamination=contamination,
                    random_state=42,
                    n_jobs=-1,
                )
                model.fit(X)

            result["ai_trained"] = True

            # 保存模型
            if model_save_path:
                import joblib
                os.makedirs(os.path.dirname(model_save_path) or ".", exist_ok=True)
                joblib.dump(model, model_save_path)
                result["model_path"] = model_save_path
                logger.info(f"Model saved to {model_save_path}")

            # 检测异常 IP
            predictions = model.predict(X)
            anomalous_indices = [i for i, p in enumerate(predictions) if p == -1]
            anomalous_ips = set()
            for idx in anomalous_indices:
                anomalous_ips.add(feature_dicts[idx]["ip"])

            for ip in anomalous_ips:
                if ip_404.get(ip, 0) > 0 or any(
                    is_scanning_path(r.get("path", ""))
                    for r in records if r.get("ip") == ip
                ):
                    result["blocked_ips"].append((ip, "AI anomaly detection"))

            if result["blocked_ips"]:
                logger.info(f"AI detected {len(result['blocked_ips'])} anomalous IPs")

        except Exception as e:
            logger.error(f"AI training failed: {e}")

    return result


def load_model(model_path: str):
    """加载持久化的 IsolationForest 模型"""
    try:
        import joblib
        return joblib.load(model_path)
    except Exception as e:
        logger.error(f"Failed to load model from {model_path}: {e}")
        return None


def predict_with_model(model, features: List[float]) -> int:
    """
    使用模型预测单条记录是否异常。

    Returns:
        1 = 正常, -1 = 异常, None = 无法预测
    """
    if model is None:
        return None
    try:
        if is_rust_isolation_forest(model):
            return int(model.predict([list(map(float, features))])[0])
        if not NUMPY_AVAILABLE:
            return None
        X = np.array(list(features), dtype=float).reshape(1, -1)
        return int(model.predict(X)[0])
    except Exception:
        return None
