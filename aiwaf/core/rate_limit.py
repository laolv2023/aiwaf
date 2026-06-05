"""Mock AIWAF core rate_limit module."""
from dataclasses import dataclass
from typing import Optional

@dataclass
class RateLimitDecision:
    action: str = "pass"  # "pass" or "flood_block"

def evaluate_rate_limit(timestamps, window_seconds, max_requests, event_time: float = None):
    """Mock: returns block if timestamp count exceeds max_requests."""
    if event_time is None:
        import time
        event_time = time.time()
    cutoff = event_time - window_seconds
    recent = [t for t in timestamps if t > cutoff]
    if len(recent) >= max_requests:
        return RateLimitDecision(action="flood_block")
    return RateLimitDecision(action="pass")
