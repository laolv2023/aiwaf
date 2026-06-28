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
            "redis_cluster_url":       "REDIS_CLUSTER_URL",
            "kafka_brokers":           "KAFKA_BROKERS",
            "input_topic":             "KAFKA_INPUT_TOPIC",
            "alert_topic":             "KAFKA_ALERT_TOPIC",
            "dlq_topic":               "KAFKA_DLQ_TOPIC",
            "consumer_group":          "KAFKA_CONSUMER_GROUP",
            "core_process_pool_size":  "CORE_PROCESS_POOL_SIZE",
            "rate_limit_window":       "RATE_LIMIT_WINDOW",
            "rate_limit_max_requests": "RATE_LIMIT_MAX_REQUESTS",
            "rate_limit_flood_threshold": "RATE_LIMIT_FLOOD_THRESHOLD",
            "fail_secure_local_limit": "FAIL_SECURE_LOCAL_LIMIT",
            "geoip_db_path":           "GEOIP_DB_PATH",
            "geo_block_countries":     "GEO_BLOCK_COUNTRIES",
            "geo_allow_countries":     "GEO_ALLOW_COUNTRIES",
        }

        int_fields = {
            "core_process_pool_size", "rate_limit_window",
            "rate_limit_max_requests", "rate_limit_flood_threshold",
            "fail_secure_local_limit",
        }

        for attr, env_key in env_map.items():
            val = os.getenv(env_key)
            if val is not None:
                if attr in int_fields:
                    val = int(val)
                setattr(settings, attr, val)

        return settings
