"""Mock AIWAF core ip_keyword module."""
from dataclasses import dataclass, field
from typing import List, Optional

@dataclass
class KeywordDecision:
    block_reason: Optional[str] = None

def evaluate_keyword_policy(path, query_keys, offline_mode=False, query_strings=None, dynamic_keywords=None):
    """Mock: checks if any dynamic keyword appears in path, query_keys, or query_strings."""
    keywords = dynamic_keywords or []
    if query_strings is None:
        query_strings = []
    if query_keys is None:
        query_keys = []
    path = path or "/"
    for kw in keywords:
        if kw in str(path):
            return KeywordDecision(block_reason=f"path_match:{kw}")
        for qk in query_keys:
            if kw in str(qk):
                return KeywordDecision(block_reason=f"query_key_match:{kw}")
        for qs in query_strings:
            if kw in qs:
                return KeywordDecision(block_reason=f"query_match:{kw}")
    return KeywordDecision()
