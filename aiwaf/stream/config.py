"""
AIWAF 配置模块

支持两种配置方式，优先级从高到低：
  1. 环境变量（适配 Docker/K8s）
  2. YAML 配置文件（适配本地开发/集中管理）
  3. 内置默认值

YAML 配置文件路径通过环境变量 AIWAF_CONFIG 指定：
  AIWAF_CONFIG=/etc/aiwaf/config.yaml python engine.py

如果 AIWAF_CONFIG 未设置，默认读取 ./config.yaml（如果存在）。
环境变量会覆盖 YAML 中同名字段。

YAML 格式示例见 config.example.yaml

参考文档: docs/AIWAF_Akto_Integration_Design.md §3.4
"""
import os
from dataclasses import dataclass, fields


@dataclass
class Settings:
    """AIWAF 运行配置"""

    # Redis
    redis_cluster_url: str = "redis://localhost:6379"

    # Kafka
    kafka_brokers: str = "localhost:9092"

    # Kafka Topics
    input_topic: str = "akto.api.logs"           # 消费 Topic（Akto 流量日志 JSON）
    alert_topic: str = "akto.aiwaf.alerts"        # 告警 Topic
    dlq_topic: str = "akto.aiwaf.dlq"             # 死信 Topic

    # Kafka Consumer
    consumer_group: str = "aiwaf-consumer-group"  # Consumer Group ID

    # 进程池
    core_process_pool_size: int = 4

    # 速率限制
    rate_limit_window: int = 60           # 窗口大小（秒）
    rate_limit_max_requests: int = 100    # 窗口内最大请求数
    rate_limit_flood_threshold: int = 150 # 洪泛检测阈值
    fail_secure_local_limit: int = 50     # Redis 不可用时的本地降级阈值

    # 地理围栏
    geoip_db_path: str = ""               # MaxMind GeoIP DB 路径（空=禁用）
    geo_block_countries: str = ""         # 阻止的国家（逗号分隔）
    geo_allow_countries: str = ""         # 允许的国家（逗号分隔，空=全部允许）

    # Kafka Producer
    kafka_enable_idempotence: bool = True  # 幂等生产者
    kafka_acks: str = "all"                # 确认级别（all/1/0）

    # Kafka Consumer
    kafka_auto_offset_reset: str = "earliest"  # 无偏移时从最早开始
    kafka_max_poll_records: int = 500          # 单次拉取最大记录数

    # 进程池
    max_tasks_per_child: int = 200         # 子进程最大任务数（防内存泄漏）

    # 微批处理
    batch_max_size: int = 50               # 每批最大消息数
    batch_timeout_ms: int = 10             # 批处理超时（毫秒）
    batch_queue_maxsize: int = 10000       # 批处理队列最大长度

    # 关键词刷新
    keyword_refresh_interval: int = 10     # 关键词缓存刷新间隔（秒）
    keyword_top_n: int = 500               # 从 Redis 获取的 Top N 关键词数

    # Redis TTL
    dedup_ttl: int = 86400                 # 去重记录 TTL（秒，默认 24 小时）
    blacklist_ttl: int = 3600              # IP 黑名单 TTL（秒，默认 1 小时）
    local_blacklist_ttl: int = 300         # 本地黑名单 TTL（秒，默认 5 分钟）
    local_rate_limit_ttl: int = 60         # 本地速率限制 TTL（秒）

    # 熔断器
    circuit_breaker_fail_max: int = 5      # 连续失败多少次跳闸
    circuit_breaker_timeout: int = 60      # 熔断器恢复探测间隔（秒）

    # Fail-Secure 缓冲
    max_pending_ips: int = 10000           # 待同步 IP 缓冲最大长度

    # Body 截断
    max_body_hash_bytes: int = 10485760    # Body 哈希截断阈值（字节，默认 10MB）
    max_body_store_bytes: int = 1024       # Body 存储截断阈值（字节，默认 1KB）

    # 请求头验证
    header_required: str = "user-agent,accept"  # 必需头（逗号分隔，空=不检查）
    header_skip_ips: str = ""                  # 跳过头检查的 IP/CIDR（逗号分隔）
    header_skip_paths: str = ""                # 跳过头检查的路径前缀（逗号分隔）
    header_max_ua_length: int = 500            # User-Agent 最大长度
    header_max_accept_length: int = 4096       # Accept 最大长度
    header_suspicious_ua: str = ""             # 自定义可疑 UA 模式（逗号分隔，空=用默认）
    header_legitimate_bots: str = ""           # 合法爬虫 UA（逗号分隔，空=用默认）

    # AI 异常检测
    ai_min_logs: int = 50                      # 最小训练样本数（不足则跳过 AI 训练）
    ai_contamination: float = 0.05             # IsolationForest 污染率（异常比例）
    ai_n_estimators: int = 100                 # IsolationForest 树数
    ai_max_samples: str = "auto"               # IsolationForest 最大样本数

    # 蜜罐时序检测
    honeypot_ttl: int = 300                    # 蜜罐 GET 时间戳 TTL（秒）

    # 关键词策略
    keyword_min_segment_length: int = 3        # 路径段最小长度（短于此不参与关键词检测）

    # Redis 同步
    background_sync_interval: int = 5          # 后台同步 Worker 间隔（秒）

    # Kafka 消费
    kafka_retry_interval: int = 5              # 消费循环异常后重试间隔（秒）

    # 人工审核模式
    auto_block_enabled: bool = True            # 自动拉黑 IP（False=只告警不拉黑，需人工审批）
    auto_learn_keywords: bool = True           # 自动学习关键词（False=只告警不学习）

    # 按路径禁用检测模块（JSON 字符串，格式同 PATH_RULES）
    # 示例: [{"path": "/api/webhooks/", "disable": ["header_validation", "uuid_tamper"]}]
    path_rules: str = ""

    @classmethod
    def from_yaml(cls, path: str) -> "Settings":
        """从 YAML 配置文件加载"""
        try:
            import yaml
        except ImportError:
            raise ImportError("PyYAML is required for YAML config: pip install pyyaml")

        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        # 只取 dataclass 中定义的字段
        valid_keys = {field.name for field in fields(cls)}
        filtered = {k: v for k, v in data.items() if k in valid_keys}
        return cls(**filtered)

    @classmethod
    def from_env(cls) -> "Settings":
        """
        加载配置，优先级：环境变量 > YAML 文件 > 默认值

        YAML 文件路径：
          1. 环境变量 AIWAF_CONFIG 指定
          2. 默认 ./config.yaml（如果存在）
        """
        # Step 1: 从 YAML 加载基础配置
        yaml_path = os.getenv("AIWAF_CONFIG", "config.yaml")
        if os.path.exists(yaml_path):
            settings = cls.from_yaml(yaml_path)
        else:
            settings = cls()

        # Step 2: 环境变量覆盖 YAML（优先级更高）
        env_map = {
            "redis_cluster_url":           "REDIS_CLUSTER_URL",
            "kafka_brokers":               "KAFKA_BROKERS",
            "input_topic":                 "KAFKA_INPUT_TOPIC",
            "alert_topic":                 "KAFKA_ALERT_TOPIC",
            "dlq_topic":                   "KAFKA_DLQ_TOPIC",
            "consumer_group":              "KAFKA_CONSUMER_GROUP",
            "core_process_pool_size":      "CORE_PROCESS_POOL_SIZE",
            "rate_limit_window":           "RATE_LIMIT_WINDOW",
            "rate_limit_max_requests":     "RATE_LIMIT_MAX_REQUESTS",
            "rate_limit_flood_threshold":  "RATE_LIMIT_FLOOD_THRESHOLD",
            "fail_secure_local_limit":     "FAIL_SECURE_LOCAL_LIMIT",
            "geoip_db_path":               "GEOIP_DB_PATH",
            "geo_block_countries":         "GEO_BLOCK_COUNTRIES",
            "geo_allow_countries":         "GEO_ALLOW_COUNTRIES",
            "kafka_enable_idempotence":    "KAFKA_ENABLE_IDEMPOTENCE",
            "kafka_acks":                  "KAFKA_ACKS",
            "kafka_auto_offset_reset":     "KAFKA_AUTO_OFFSET_RESET",
            "kafka_max_poll_records":      "KAFKA_MAX_POLL_RECORDS",
            "max_tasks_per_child":         "MAX_TASKS_PER_CHILD",
            "batch_max_size":              "BATCH_MAX_SIZE",
            "batch_timeout_ms":            "BATCH_TIMEOUT_MS",
            "batch_queue_maxsize":         "BATCH_QUEUE_MAXSIZE",
            "keyword_refresh_interval":    "KEYWORD_REFRESH_INTERVAL",
            "keyword_top_n":               "KEYWORD_TOP_N",
            "dedup_ttl":                   "DEDUP_TTL",
            "blacklist_ttl":               "BLACKLIST_TTL",
            "local_blacklist_ttl":         "LOCAL_BLACKLIST_TTL",
            "local_rate_limit_ttl":        "LOCAL_RATE_LIMIT_TTL",
            "circuit_breaker_fail_max":    "CIRCUIT_BREAKER_FAIL_MAX",
            "circuit_breaker_timeout":     "CIRCUIT_BREAKER_TIMEOUT",
            "max_pending_ips":             "MAX_PENDING_IPS",
            "max_body_hash_bytes":         "MAX_BODY_HASH_BYTES",
            "max_body_store_bytes":        "MAX_BODY_STORE_BYTES",
            "header_required":             "HEADER_REQUIRED",
            "header_skip_ips":             "HEADER_SKIP_IPS",
            "header_skip_paths":           "HEADER_SKIP_PATHS",
            "header_max_ua_length":        "HEADER_MAX_UA_LENGTH",
            "header_max_accept_length":    "HEADER_MAX_ACCEPT_LENGTH",
            "header_suspicious_ua":        "HEADER_SUSPICIOUS_UA",
            "header_legitimate_bots":      "HEADER_LEGITIMATE_BOTS",
            "ai_min_logs":                 "AI_MIN_LOGS",
            "ai_contamination":            "AI_CONTAMINATION",
            "ai_n_estimators":             "AI_N_ESTIMATORS",
            "ai_max_samples":              "AI_MAX_SAMPLES",
            "honeypot_ttl":                "HONEYPOT_TTL",
            "keyword_min_segment_length":  "KEYWORD_MIN_SEGMENT_LENGTH",
            "background_sync_interval":    "BACKGROUND_SYNC_INTERVAL",
            "kafka_retry_interval":        "KAFKA_RETRY_INTERVAL",
            "auto_block_enabled":          "AUTO_BLOCK_ENABLED",
            "auto_learn_keywords":         "AUTO_LEARN_KEYWORDS",
            "path_rules":                  "PATH_RULES",
        }

        int_fields = {
            "core_process_pool_size", "rate_limit_window",
            "rate_limit_max_requests", "rate_limit_flood_threshold",
            "fail_secure_local_limit",
            "kafka_max_poll_records", "max_tasks_per_child",
            "batch_max_size", "batch_timeout_ms", "batch_queue_maxsize",
            "keyword_refresh_interval", "keyword_top_n",
            "dedup_ttl", "blacklist_ttl", "local_blacklist_ttl", "local_rate_limit_ttl",
            "circuit_breaker_fail_max", "circuit_breaker_timeout",
            "max_pending_ips", "max_body_hash_bytes", "max_body_store_bytes",
            "header_max_ua_length", "header_max_accept_length",
            "ai_min_logs", "ai_n_estimators",
            "honeypot_ttl", "keyword_min_segment_length",
            "background_sync_interval",
            "kafka_retry_interval",
        }

        float_fields = {
            "ai_contamination",
        }

        # int_fields 需要 int 转换，float_fields 需要 float 转换
        # bool_fields 需要布尔转换

        bool_fields = {
            "kafka_enable_idempotence",
            "auto_block_enabled",
            "auto_learn_keywords",
        }

        for attr, env_key in env_map.items():
            val = os.getenv(env_key)
            if val is not None:
                try:
                    if attr in int_fields:
                        val = int(val)
                    elif attr in float_fields:
                        val = float(val)
                    elif attr in bool_fields:
                        val = val.lower() in ("true", "1", "yes", "on")
                    setattr(settings, attr, val)
                except (ValueError, TypeError):
                    pass  # 非法值保留 YAML/默认值

        return settings
