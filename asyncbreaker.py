"""
Async circuit breaker stub — 测试环境最小实现。
生产环境替换为真实的异步熔断器。
"""


class CircuitBreakerError(Exception):
    """熔断器打开时抛出的异常"""
    pass


class CircuitBreaker:
    """异步熔断器 stub：在测试中永不熔断，只提供一致的接口。"""

    def __init__(self, fail_max: int = 5, timeout_duration=None):
        self.fail_max = fail_max
        self.timeout_duration = timeout_duration
        self._fail_count = 0

    class _Context:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc_val, exc_tb):
            return False  # 不吞异常

    def context(self):
        """返回 async context manager，不做任何拦截。"""
        return self._Context()
