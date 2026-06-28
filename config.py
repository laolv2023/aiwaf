"""
AIWAF 配置模块

通过环境变量配置 Kafka / Redis 连接参数。
所有参数均有默认值，适配本地开发环境。

环境变量:
    KAFKA_BROKERS              Kafka broker 地址列表（逗号分隔）
    KAFKA_INPUT_TOPIC          消费 Topic（Akto 流量日志）
    KAFKA_ALERT_TOPIC          告警输出 Topic
    KAFKA_DLQ_TOPIC            死信队列 Topic
    KAFKA_CONSUMER_GROUP       Consumer Group ID
    REDIS_CLUSTER_URL          Redis 集群 URL
    CORE_PROCESS_POOL_SIZE     核心进程池大小

参考文档: docs/AIWAF_Akto_Integration_Design.md §3.4
"""
import os
from dataclasses import dataclass


@dataclass
class Settings:
    """AIWAF 运行配置"""

    # Redis
    redis_cluster_url: str

    # Kafka
    kafka_brokers: str

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

    @classmethod
    def from_env(cls) -> "Settings":
        """从环境变量加载配置"""
        return cls(
            redis_cluster_url=os.getenv("REDIS_CLUSTER_URL", "redis://localhost:6379"),
            kafka_brokers=os.getenv("KAFKA_BROKERS", "localhost:9092"),
            input_topic=os.getenv("KAFKA_INPUT_TOPIC", "akto.api.logs"),
            alert_topic=os.getenv("KAFKA_ALERT_TOPIC", "akto.aiwaf.alerts"),
            dlq_topic=os.getenv("KAFKA_DLQ_TOPIC", "akto.aiwaf.dlq"),
            consumer_group=os.getenv("KAFKA_CONSUMER_GROUP", "aiwaf-consumer-group"),
            core_process_pool_size=int(os.getenv("CORE_PROCESS_POOL_SIZE", "4")),
            rate_limit_window=int(os.getenv("RATE_LIMIT_WINDOW", "60")),
            rate_limit_max_requests=int(os.getenv("RATE_LIMIT_MAX_REQUESTS", "100")),
            rate_limit_flood_threshold=int(os.getenv("RATE_LIMIT_FLOOD_THRESHOLD", "150")),
            fail_secure_local_limit=int(os.getenv("FAIL_SECURE_LOCAL_LIMIT", "50")),
        )
