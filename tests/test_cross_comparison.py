"""
Cross-comparison test suite: 60 tests verifying byte-level equivalence
and behavioral parity between our aiwaf_stream system and the original AIWAF.

Modules are loaded via importlib to avoid conflicts:
  - orig_rl / orig_ip  → original at /sandbox/workspace/aiwaf/aiwaf-main/aiwaf/core/
  - our_rl  / our_ip   → our copy at /sandbox/workspace/aiwaf_stream/aiwaf/core/
"""

import hashlib
import importlib.util
import os
import random
import sys
import time

import pytest

# ---------------------------------------------------------------------------
# Path setup so our project modules can be imported
# ---------------------------------------------------------------------------
_project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

# Also allow original aiwaf package to be importable
_orig_root = "/sandbox/workspace/aiwaf/aiwaf-main"
if _orig_root not in sys.path:
    sys.path.insert(0, _orig_root)

# ---------------------------------------------------------------------------
# Import our project modules normally
# ---------------------------------------------------------------------------
from aiwaf.stream.preprocessor import transform_raw_log
from train_pipeline import _process_row_purifier
from aiwaf.stream.acl_bootstrap import _default_malicious_context

# ---------------------------------------------------------------------------
# Load the two core modules via importlib with distinct names
# ---------------------------------------------------------------------------
def _load_module(name, filepath):
    spec = importlib.util.spec_from_file_location(name, filepath)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

# Original
orig_rl = _load_module("orig_rate_limit",
                       "/sandbox/workspace/aiwaf/aiwaf-main/aiwaf/core/rate_limit.py")
orig_ip = _load_module("orig_ip_keyword",
                       "/sandbox/workspace/aiwaf/aiwaf-main/aiwaf/core/ip_keyword.py")

# Our copy
our_rl = _load_module("our_rate_limit",
                      "/sandbox/workspace/aiwaf_stream/aiwaf/core/rate_limit.py")
our_ip = _load_module("our_ip_keyword",
                      "/sandbox/workspace/aiwaf_stream/aiwaf/core/ip_keyword.py")


# ============================================================================
# DIMENSION 1: Byte-level equivalence (5 tests)
# ============================================================================
class TestByteLevelEquivalence:
    """Verify the two file pairs are byte-identical and expose the same API."""

    def test_file_hashes_match_rate_limit(self):
        """SHA256 of rate_limit.py must match."""
        def sha256(path):
            with open(path, "rb") as f:
                return hashlib.sha256(f.read()).hexdigest()
        assert sha256("/sandbox/workspace/aiwaf_stream/aiwaf/core/rate_limit.py") == \
               sha256("/sandbox/workspace/aiwaf/aiwaf-main/aiwaf/core/rate_limit.py")

    def test_file_hashes_match_ip_keyword(self):
        """SHA256 of ip_keyword.py must match."""
        def sha256(path):
            with open(path, "rb") as f:
                return hashlib.sha256(f.read()).hexdigest()
        assert sha256("/sandbox/workspace/aiwaf_stream/aiwaf/core/ip_keyword.py") == \
               sha256("/sandbox/workspace/aiwaf/aiwaf-main/aiwaf/core/ip_keyword.py")

    def test_rate_limit_constants_identical(self):
        """ALLOW / THROTTLE / FLOOD_BLOCK must be identical."""
        assert our_rl.ALLOW == orig_rl.ALLOW == "allow"
        assert our_rl.THROTTLE == orig_rl.THROTTLE == "throttle"
        assert our_rl.FLOOD_BLOCK == orig_rl.FLOOD_BLOCK == "flood_block"

    def test_rate_limit_dataclass_fields_identical(self):
        """RateLimitDecision must have the same fields."""
        our_fields = set(our_rl.RateLimitDecision.__dataclass_fields__.keys())
        orig_fields = set(orig_rl.RateLimitDecision.__dataclass_fields__.keys())
        assert our_fields == orig_fields == {"action", "count", "timestamps"}

    def test_keyword_dataclass_fields_identical(self):
        """KeywordDecision must have the same fields."""
        our_fields = set(our_ip.KeywordDecision.__dataclass_fields__.keys())
        orig_fields = set(orig_ip.KeywordDecision.__dataclass_fields__.keys())
        assert our_fields == orig_fields == {"block_reason", "learned_keywords", "segments"}

    def test_inherent_patterns_identical(self):
        """INHERENTLY_MALICIOUS_PATTERNS must be identical tuples."""
        assert our_ip.INHERENTLY_MALICIOUS_PATTERNS == orig_ip.INHERENTLY_MALICIOUS_PATTERNS
        assert len(our_ip.INHERENTLY_MALICIOUS_PATTERNS) == 8


# ============================================================================
# DIMENSION 2: evaluate_rate_limit behavior (15 tests)
# ============================================================================
class TestRateLimitBehavior:
    """Both modules must produce the same rate-limit decisions for the same input."""

    NOW = 1000.0
    WINDOW = 60.0
    MAX_REQ = 100
    FLOOD = 150

    # --- helper ---------------------------------------------------------------
    def _call_both(self, timestamps):
        o = orig_rl.evaluate_rate_limit(timestamps, self.NOW, self.WINDOW, self.MAX_REQ, self.FLOOD)
        u = our_rl.evaluate_rate_limit(timestamps, self.NOW, self.WINDOW, self.MAX_REQ, self.FLOOD)
        return o, u

    # --- individual scenarios -------------------------------------------------
    def test_allow_single_request(self):
        o, u = self._call_both([self.NOW - 10])
        assert o.action == u.action == "allow"
        assert o.count == u.count == 2          # trimmed has [old, now]
        assert u.timestamps == o.timestamps

    def test_allow_at_max(self):
        """Exactly max_requests active timestamps → allow (not >)."""
        # After appending now, count = max_requests → action stays "allow"
        ts = [self.NOW - i * 0.1 for i in range(self.MAX_REQ - 1)]
        o, u = self._call_both(ts)
        assert o.action == u.action == "allow"
        assert o.count == u.count == self.MAX_REQ

    def test_throttle_at_max_plus_one(self):
        """max_requests + 1 → throttle."""
        ts = [self.NOW - i * 0.1 for i in range(self.MAX_REQ + 1)]
        o, u = self._call_both(ts)
        assert o.action == u.action == "throttle"
        assert o.count == u.count == self.MAX_REQ + 2

    def test_flood_block_above_threshold(self):
        """Above flood threshold → flood_block."""
        ts = [self.NOW - i * 0.1 for i in range(self.FLOOD + 5)]
        o, u = self._call_both(ts)
        assert o.action == u.action == "flood_block"
        assert o.count > self.FLOOD

    def test_window_trims_old_timestamps(self):
        """Old timestamps outside window are removed."""
        old = self.NOW - self.WINDOW - 50
        recent = self.NOW - 10
        ts = [old, recent]
        o, u = self._call_both(ts)
        # Only the recent one + now remains
        assert o.count == u.count == 2
        assert old not in o.timestamps
        assert old not in u.timestamps
        assert recent in o.timestamps

    def test_empty_timestamps_list(self):
        o, u = self._call_both([])
        assert o.action == u.action == "allow"
        assert o.count == u.count == 1       # [now]
        assert u.timestamps == o.timestamps

    def test_none_timestamps(self):
        """None should be treated like an empty iterable."""
        o, u = self._call_both(None)
        assert o.action == u.action == "allow"
        assert o.count == u.count == 1
        assert u.timestamps == o.timestamps

    def test_both_return_same_count(self):
        """Both return same count for a non-trivial list."""
        ts = [self.NOW - i for i in range(25)]
        o, u = self._call_both(ts)
        assert o.count == u.count

    def test_both_return_same_timestamps_list(self):
        """Both return identical timestamps lists."""
        ts = [self.NOW - i * 2.5 for i in range(13)]
        o, u = self._call_both(ts)
        assert o.timestamps == u.timestamps

    def test_random_fuzz_100_sets(self):
        """100 random timestamp arrays → identical decisions."""
        rng = random.Random(42)
        for _ in range(100):
            n = rng.randint(0, 200)
            ts = sorted([self.NOW - rng.uniform(0, 120) for _ in range(n)])
            o, u = self._call_both(ts)
            assert o.action == u.action, f"mismatch action with ts={ts}"
            assert o.count == u.count, f"mismatch count with ts={ts}"
            assert o.timestamps == u.timestamps, f"mismatch timestamps with ts={ts}"

    def test_random_fuzz_100_param_ranges(self):
        """100 random parameter combos → identical decisions."""
        rng = random.Random(99)
        for _ in range(100):
            now = rng.uniform(1000, 10000)
            window = rng.uniform(10, 300)
            max_req = rng.randint(5, 200)
            flood = max_req + rng.randint(10, 100)
            n = rng.randint(0, 250)
            ts = sorted([now - rng.uniform(0, window * 2) for _ in range(n)])
            o = orig_rl.evaluate_rate_limit(ts, now, window, max_req, flood)
            u = our_rl.evaluate_rate_limit(ts, now, window, max_req, flood)
            assert o.action == u.action
            assert o.count == u.count
            assert o.timestamps == u.timestamps

    def test_timestamps_preserve_order(self):
        """Returned timestamps list must be in original order + now appended."""
        ts = [self.NOW - 50, self.NOW - 40, self.NOW - 30]
        _, u = self._call_both(ts)
        assert u.timestamps == ts + [self.NOW]

    def test_timestamps_all_outside_window(self):
        """All timestamps outside window → only [now] remains."""
        ts = [self.NOW - self.WINDOW - i for i in range(1, 10)]
        o, u = self._call_both(ts)
        assert o.timestamps == u.timestamps == [self.NOW]
        assert o.action == "allow"

    def test_build_rate_limit_key_identical(self):
        """build_rate_limit_key must produce identical keys."""
        args = ("pfx", "1.2.3.4", "/api/v1", "ip_path", "")
        assert our_rl.build_rate_limit_key(*args) == orig_rl.build_rate_limit_key(*args)

    def test_build_rate_limit_key_ip_mode(self):
        """IP-only mode keys must match."""
        args = ("pfx", "1.2.3.4", "/any", "ip", "")
        assert our_rl.build_rate_limit_key(*args) == orig_rl.build_rate_limit_key(*args)

    def test_build_rate_limit_key_with_app_key(self):
        """Keys with app_key must match."""
        args = ("pfx", "10.0.0.1", "/home", "ip_path", "myapp")
        assert our_rl.build_rate_limit_key(*args) == orig_rl.build_rate_limit_key(*args)


# ============================================================================
# DIMENSION 3: evaluate_keyword_policy behavior (20 tests)
# ============================================================================
class TestKeywordPolicyBehavior:
    """Both modules must return identical KeywordDecision for identical inputs."""

    # --- helpers --------------------------------------------------------------
    @staticmethod
    def _call_both(**kwargs):
        o = orig_ip.evaluate_keyword_policy(**kwargs)
        u = our_ip.evaluate_keyword_policy(**kwargs)
        return o, u

    @staticmethod
    def _assert_same_decision(o, u):
        assert o.block_reason == u.block_reason
        assert o.learned_keywords == u.learned_keywords
        assert o.segments == u.segments

    # --- mirror of original test_ip_keyword_policy_core.py --------------------
    def test_core_allows_normal_existing_route(self):
        """Original test: normal existing route passes."""
        o, u = self._call_both(
            path="/api/data",
            query_keys=[],
            path_exists=True,
            keyword_learning_enabled=True,
            static_keywords={".php", "xmlrpc", "wp-"},
            dynamic_keywords=set(),
            legitimate_keywords={"api", "data"},
            exempt_keywords=set(),
            safe_prefixes={"api"},
            malicious_keywords={"xmlrpc"},
            is_malicious_context=lambda _seg: False,
        )
        self._assert_same_decision(o, u)
        assert o.block_reason is None
        assert u.block_reason is None

    def test_core_blocks_nonexistent_suspicious_segment(self):
        """Original test: nonexistent path with suspicious segment blocks."""
        o, u = self._call_both(
            path="/shellupload",
            query_keys=[],
            path_exists=False,
            keyword_learning_enabled=True,
            static_keywords=set(),
            dynamic_keywords={"shellupload"},
            legitimate_keywords=set(),
            exempt_keywords=set(),
            safe_prefixes=set(),
            malicious_keywords={"shellupload"},
            is_malicious_context=lambda seg: seg == "shellupload",
        )
        self._assert_same_decision(o, u)
        assert o.block_reason is not None
        assert "shellupload" in o.block_reason

    def test_core_learns_only_when_suspicious_context(self):
        """Original test: learns keywords only for suspicious context."""
        o, u = self._call_both(
            path="/unknownpayload",
            query_keys=[],
            path_exists=False,
            keyword_learning_enabled=True,
            static_keywords=set(),
            dynamic_keywords=set(),
            legitimate_keywords=set(),
            exempt_keywords=set(),
            safe_prefixes=set(),
            malicious_keywords=set(),
            is_malicious_context=lambda seg: seg == "unknownpayload",
        )
        self._assert_same_decision(o, u)
        assert "unknownpayload" in o.learned_keywords
        assert "unknownpayload" in u.learned_keywords

    # --- expanded tests -------------------------------------------------------

    def test_nonexistent_path_with_inherent_malicious(self):
        """Path segment matches INHERENTLY_MALICIOUS_PATTERNS → block."""
        o, u = self._call_both(
            path="/attack/payload",
            query_keys=[],
            path_exists=False,
            keyword_learning_enabled=False,
            static_keywords=set(),
            dynamic_keywords=set(),
            legitimate_keywords=set(),
            exempt_keywords=set(),
            safe_prefixes=set(),
            malicious_keywords=set(),
            is_malicious_context=lambda _: False,
        )
        self._assert_same_decision(o, u)
        assert o.block_reason is not None
        assert "attack" in o.block_reason

    def test_nonexistent_path_with_probe_pattern(self):
        """Path matches PROBE_PATH_PATTERNS (e.g. /.env) → block."""
        o, u = self._call_both(
            path="/.env",
            query_keys=[],
            path_exists=False,
            keyword_learning_enabled=False,
            static_keywords=set(),
            dynamic_keywords=set(),
            legitimate_keywords=set(),
            exempt_keywords=set(),
            safe_prefixes=set(),
            malicious_keywords=set(),
            is_malicious_context=lambda _: False,
        )
        self._assert_same_decision(o, u)
        assert o.block_reason is not None
        assert "probe" in o.block_reason.lower()

    def test_existing_path_with_very_strong_blocks(self):
        """Existing path + suspicious keyword + very_strong indicators → block."""
        o, u = self._call_both(
            path="/api/../hack",
            query_keys=["cmd"],
            path_exists=True,
            keyword_learning_enabled=False,
            static_keywords={"hack"},
            dynamic_keywords=set(),
            legitimate_keywords=set(),
            exempt_keywords=set(),
            safe_prefixes=set(),
            malicious_keywords={"hack"},
            is_malicious_context=lambda _: True,
        )
        self._assert_same_decision(o, u)
        # "../" + "cmd" in query_keys → sum >= 2 → very_strong triggers → block
        assert o.block_reason is not None

    def test_existing_path_without_very_strong_no_block(self):
        """Existing path + keyword match but no very_strong → no block."""
        o, u = self._call_both(
            path="/api/evil",
            query_keys=[],
            path_exists=True,
            keyword_learning_enabled=False,
            static_keywords={"evil"},
            dynamic_keywords=set(),
            legitimate_keywords=set(),
            exempt_keywords=set(),
            safe_prefixes=set(),
            malicious_keywords=set(),
            is_malicious_context=lambda _: True,
        )
        self._assert_same_decision(o, u)
        assert o.block_reason is None

    def test_exempt_keywords_skipped(self):
        """Exempt keywords are not added to suspicious_kw (both modules agree)."""
        o, u = self._call_both(
            path="/admin/login",
            query_keys=[],
            path_exists=False,
            keyword_learning_enabled=False,
            static_keywords={"admin"},
            dynamic_keywords=set(),
            legitimate_keywords=set(),
            exempt_keywords={"admin"},
            safe_prefixes=set(),
            malicious_keywords=set(),
            is_malicious_context=lambda _: True,
        )
        self._assert_same_decision(o, u)
        # "admin" is exempt → not in suspicious_kw, but "login" may be caught
        # by inherent check with is_malicious_context always True.
        # We just verify both modules return the same decision.

    def test_legitimate_keywords_existing_skipped(self):
        """Legitimate keywords on existing path with non-malicious context are skipped."""
        o, u = self._call_both(
            path="/api/health",
            query_keys=[],
            path_exists=True,
            keyword_learning_enabled=False,
            static_keywords={"health"},
            dynamic_keywords=set(),
            legitimate_keywords={"api", "health"},
            exempt_keywords=set(),
            safe_prefixes=set(),
            malicious_keywords=set(),
            is_malicious_context=lambda _: False,
        )
        self._assert_same_decision(o, u)
        assert o.block_reason is None

    def test_safe_prefixes_protect(self):
        """Safe prefixes prevent keyword from becoming suspicious."""
        o, u = self._call_both(
            path="/static/js/bundle.js",
            query_keys=[],
            path_exists=False,
            keyword_learning_enabled=False,
            static_keywords={"bundle"},
            dynamic_keywords=set(),
            legitimate_keywords=set(),
            exempt_keywords=set(),
            safe_prefixes={"static"},
            malicious_keywords=set(),
            is_malicious_context=lambda _: True,
        )
        self._assert_same_decision(o, u)
        # "bundle" not in suspicious_kw due to safe_prefix "static"
        assert "bundle" not in (o.block_reason or "")

    def test_malicious_keywords_very_strong_triggers(self):
        """>2 malicious keywords + ../ → sum >= 2 → very_strong triggers on existing path."""
        o, u = self._call_both(
            path="/api/../xmlrpc/evil/backdoor",
            query_keys=["cmd"],
            path_exists=True,
            keyword_learning_enabled=False,
            static_keywords={"xmlrpc", "evil", "backdoor"},
            dynamic_keywords=set(),
            legitimate_keywords=set(),
            exempt_keywords=set(),
            safe_prefixes=set(),
            malicious_keywords={"xmlrpc", "evil", "backdoor"},
            is_malicious_context=lambda _: True,
        )
        self._assert_same_decision(o, u)
        # "../" + "cmd" query + >2 malicious keywords → sum >= 2 → very_strong True → block
        assert o.block_reason is not None

    def test_empty_all_params(self):
        """Empty everything → no block."""
        o, u = self._call_both(
            path="",
            query_keys=[],
            path_exists=False,
            keyword_learning_enabled=False,
            static_keywords=set(),
            dynamic_keywords=set(),
            legitimate_keywords=set(),
            exempt_keywords=set(),
            safe_prefixes=set(),
            malicious_keywords=set(),
            is_malicious_context=lambda _: False,
        )
        self._assert_same_decision(o, u)
        assert o.block_reason is None
        assert o.segments == []

    def test_empty_path_none_path(self):
        """path=None → same as empty string."""
        o, u = self._call_both(
            path=None,
            query_keys=[],
            path_exists=False,
            keyword_learning_enabled=False,
            static_keywords=set(),
            dynamic_keywords=set(),
            legitimate_keywords=set(),
            exempt_keywords=set(),
            safe_prefixes=set(),
            malicious_keywords=set(),
            is_malicious_context=lambda _: False,
        )
        self._assert_same_decision(o, u)

    def test_unicode_path_segments(self):
        """Non-ASCII path segments are handled identically."""
        o, u = self._call_both(
            path="/café/naïve/攻击测试",
            query_keys=[],
            path_exists=False,
            keyword_learning_enabled=False,
            static_keywords=set(),
            dynamic_keywords=set(),
            legitimate_keywords=set(),
            exempt_keywords=set(),
            safe_prefixes=set(),
            malicious_keywords=set(),
            is_malicious_context=lambda _: False,
        )
        self._assert_same_decision(o, u)
        # "攻击测试" > 3 chars → becomes segment
        assert o.segments == u.segments

    def test_identical_output_both_modules_complex(self):
        """Complex inputs → both modules produce identical output."""
        o, u = self._call_both(
            path="/wp-admin/setup-config.php",
            query_keys=["cmd", "exec", "file"],
            path_exists=False,
            keyword_learning_enabled=True,
            static_keywords={".php", "wp-", "xmlrpc"},
            dynamic_keywords={"setup", "config"},
            legitimate_keywords={"admin"},
            exempt_keywords=set(),
            safe_prefixes=set(),
            malicious_keywords={"wp-", "xmlrpc", ".php"},
            is_malicious_context=lambda s: s in {"wp-admin", "setup", "config", ".php"},
        )
        self._assert_same_decision(o, u)

    def test_random_path_fuzz_20(self):
        """20 random paths → same block_reason between both modules."""
        rng = random.Random(7)
        paths_pool = [
            "/api/health", "/admin/login", "/.git/config", "/shell.php",
            "/wp-content/upload", "/hackattack/me", "/exploit/now", "/backdoor",
            "/evil/path", "/inject/sql", "/xssattack/reflected", "/attack/vector",
            "/normal/page", "/user/profile", "/data/export",
            "/.htaccess", "/xmlrpc.php", "/config.bak", "/test.cgi",
            "/malicious/stuff", "/safe/route", "/union+select/1",
        ]
        for i in range(20):
            path = rng.choice(paths_pool)
            ctx_val = rng.choice([True, False])
            o, u = self._call_both(
                path=path,
                query_keys=[],
                path_exists=rng.choice([True, False]),
                keyword_learning_enabled=rng.choice([True, False]),
                static_keywords=set(rng.sample([".php", "wp-", "xmlrpc", "setup"], rng.randint(0, 2))),
                dynamic_keywords=set(rng.sample(["hack", "evil", "attack"], rng.randint(0, 2))),
                legitimate_keywords={"api", "admin", "user"},
                exempt_keywords=set(),
                safe_prefixes=set(rng.sample(["api", "static", "assets"], rng.randint(0, 1))),
                malicious_keywords={"xmlrpc", "wp-", ".php"},
                is_malicious_context=lambda _s, _v=ctx_val: _v,
            )
            assert o.block_reason == u.block_reason, f"mismatch at i={i} path={path}"
            assert o.learned_keywords == u.learned_keywords
            assert o.segments == u.segments

    def test_random_params_fuzz_10(self):
        """10 random parameter combos → same result."""
        rng = random.Random(13)
        for i in range(10):
            # Capture the choice for this iteration in the lambda default arg
            mal_ctx_val = rng.choice([True, False])
            o, u = self._call_both(
                path=rng.choice(["/api/test", "/evil/hack", "/.env", "/admin/backdoor"]),
                query_keys=rng.sample(["q", "cmd", "exec", "id", "page"], rng.randint(0, 3)),
                path_exists=rng.choice([True, False]),
                keyword_learning_enabled=rng.choice([True, False]),
                static_keywords=set(rng.sample(["hack", "evil", ".php"], rng.randint(0, 2))),
                dynamic_keywords=set(rng.sample(["test", "admin", "backdoor"], rng.randint(0, 2))),
                legitimate_keywords=set(rng.sample(["api", "test", "admin", "page"], rng.randint(0, 3))),
                exempt_keywords=set(rng.sample(["api", "health"], rng.randint(0, 1))),
                safe_prefixes=set(rng.sample(["api", "static"], rng.randint(0, 1))),
                malicious_keywords=set(rng.sample(["evil", "hack", "backdoor"], rng.randint(0, 2))),
                is_malicious_context=lambda _s, _v=mal_ctx_val: _v,
            )
            assert o.block_reason == u.block_reason, f"mismatch at i={i}"
            assert o.learned_keywords == u.learned_keywords
            assert o.segments == u.segments

    def test_probe_path_php_extension(self):
        """Path ending .php → probe block."""
        o, u = self._call_both(
            path="/shell.php",
            query_keys=[],
            path_exists=False,
            keyword_learning_enabled=False,
            static_keywords=set(),
            dynamic_keywords=set(),
            legitimate_keywords=set(),
            exempt_keywords=set(),
            safe_prefixes=set(),
            malicious_keywords=set(),
            is_malicious_context=lambda _: False,
        )
        self._assert_same_decision(o, u)
        assert o.block_reason is not None

    def test_probe_path_xmlrpc(self):
        """xmlrpc.php path → probe block."""
        o, u = self._call_both(
            path="/xmlrpc.php",
            query_keys=[],
            path_exists=False,
            keyword_learning_enabled=False,
            static_keywords=set(),
            dynamic_keywords=set(),
            legitimate_keywords=set(),
            exempt_keywords=set(),
            safe_prefixes=set(),
            malicious_keywords=set(),
            is_malicious_context=lambda _: False,
        )
        self._assert_same_decision(o, u)
        assert o.block_reason is not None

    def test_keyword_learning_disabled_no_learn(self):
        """keyword_learning_enabled=False → no keywords learned."""
        o, u = self._call_both(
            path="/malicious/inject",
            query_keys=[],
            path_exists=False,
            keyword_learning_enabled=False,
            static_keywords=set(),
            dynamic_keywords=set(),
            legitimate_keywords=set(),
            exempt_keywords=set(),
            safe_prefixes=set(),
            malicious_keywords=set(),
            is_malicious_context=lambda _: True,
        )
        self._assert_same_decision(o, u)
        assert o.learned_keywords == u.learned_keywords == []


# ============================================================================
# DIMENSION 4: _process_row_purifier comparison (10 tests)
# ============================================================================
class TestProcessRowPurifier:
    """Verify _process_row_purifier produces the same pass/block decision
    as a direct call to our evaluate_keyword_policy with equivalent params."""

    @staticmethod
    def _purifier_pass(row_dict, dynamic_kws):
        """Return True if _process_row_purifier says pass."""
        return _process_row_purifier((row_dict, dynamic_kws))

    @staticmethod
    def _direct_block_reason(row_dict, dynamic_kws):
        """Return block_reason from a direct call mirroring _process_row_purifier."""
        dec = our_ip.evaluate_keyword_policy(
            path=row_dict.get("uri_path", "/"),
            query_keys=row_dict.get("query_keys", []),
            path_exists=False,
            keyword_learning_enabled=False,
            static_keywords=(),
            dynamic_keywords=dynamic_kws,
            legitimate_keywords=set(),
            exempt_keywords=set(),
            safe_prefixes=(),
            malicious_keywords=set(),
            is_malicious_context=_default_malicious_context,
        )
        return dec.block_reason

    def test_clean_path_passes(self):
        row = {"uri_path": "/api/health", "query_keys": []}
        assert self._purifier_pass(row, []) is True
        assert self._direct_block_reason(row, []) is None

    def test_suspicious_keyword_blocks(self):
        row = {"uri_path": "/hack/me", "query_keys": []}
        # "hack" is in INHERENTLY_MALICIOUS_PATTERNS
        purifier_pass = self._purifier_pass(row, [])
        direct_reason = self._direct_block_reason(row, [])
        assert purifier_pass == (direct_reason is None)

    def test_probe_path_blocks(self):
        row = {"uri_path": "/.git/config", "query_keys": []}
        purifier_pass = self._purifier_pass(row, [])
        direct_reason = self._direct_block_reason(row, [])
        assert purifier_pass == (direct_reason is None)

    def test_dynamic_keyword_match_blocks(self):
        row = {"uri_path": "/api/shellupload", "query_keys": []}
        purifier_pass = self._purifier_pass(row, ["shellupload"])
        direct_reason = self._direct_block_reason(row, ["shellupload"])
        assert purifier_pass == (direct_reason is None)
        assert purifier_pass is False  # "shellupload" matches segment

    def test_dynamic_keyword_no_match_passes(self):
        row = {"uri_path": "/api/health", "query_keys": []}
        purifier_pass = self._purifier_pass(row, ["evil"])
        direct_reason = self._direct_block_reason(row, ["evil"])
        assert purifier_pass == (direct_reason is None)
        assert purifier_pass is True  # "health" not in dynamic, not inherent

    def test_missing_uri_path_defaults_to_slash(self):
        row = {"query_keys": []}
        purifier_pass = self._purifier_pass(row, [])
        direct_reason = self._direct_block_reason(row, [])
        # "/" has no segments > 3 chars → pass
        assert purifier_pass is True
        assert direct_reason is None

    def test_inherent_malicious_segment_blocks(self):
        row = {"uri_path": "/exploit/now", "query_keys": []}
        purifier_pass = self._purifier_pass(row, [])
        direct_reason = self._direct_block_reason(row, [])
        assert purifier_pass == (direct_reason is None)
        # "exploit" is inherently malicious → should block
        assert purifier_pass is False

    def test_normal_short_segments_pass(self):
        row = {"uri_path": "/a/b/c/d", "query_keys": []}
        purifier_pass = self._purifier_pass(row, [])
        direct_reason = self._direct_block_reason(row, [])
        assert purifier_pass is True
        assert direct_reason is None

    def test_multiple_segments_one_malicious(self):
        row = {"uri_path": "/api/backdoor/login", "query_keys": []}
        purifier_pass = self._purifier_pass(row, [])
        direct_reason = self._direct_block_reason(row, [])
        assert purifier_pass == (direct_reason is None)

    def test_path_with_query_keys_inherent(self):
        row = {"uri_path": "/xssattack/reflect", "query_keys": ["q", "search"]}
        purifier_pass = self._purifier_pass(row, [])
        direct_reason = self._direct_block_reason(row, [])
        assert purifier_pass == (direct_reason is None)
        # "xssattack" contains "xss" (inherently malicious) → block
        assert purifier_pass is False


# ============================================================================
# DIMENSION 5: Full pipeline equivalence (10 tests)
# ============================================================================
class TestFullPipelineEquivalence:
    """Verify the full transform_raw_log → evaluate pipeline matches direct
    original function calls for keyword decisions."""

    @staticmethod
    def _full_pipeline_keyword_decision(raw_log, dynamic_kws=None):
        """Simulate our full pipeline: transform → evaluate_keyword_policy."""
        if dynamic_kws is None:
            dynamic_kws = []
        std_log = transform_raw_log(raw_log)
        return our_ip.evaluate_keyword_policy(
            path=std_log["uri_path"],
            query_keys=std_log.get("query_keys", []),
            path_exists=False,
            keyword_learning_enabled=False,
            static_keywords=(),
            dynamic_keywords=dynamic_kws,
            legitimate_keywords=set(),
            exempt_keywords=set(),
            safe_prefixes=(),
            malicious_keywords=set(),
            is_malicious_context=_default_malicious_context,
        )

    @staticmethod
    def _direct_original_decision(path, query_keys=None, **extra):
        """Direct call to original evaluate_keyword_policy."""
        kwargs = dict(
            path=path,
            query_keys=query_keys or [],
            path_exists=False,
            keyword_learning_enabled=False,
            static_keywords=(),
            dynamic_keywords=extra.get("dynamic_keywords", []),
            legitimate_keywords=set(),
            exempt_keywords=set(),
            safe_prefixes=(),
            malicious_keywords=set(),
            is_malicious_context=lambda _: False,  # matches _default_malicious_context
        )
        return orig_ip.evaluate_keyword_policy(**kwargs)

    def test_sqli_inject_path_blocks(self):
        """Path containing inherently malicious pattern 'inject' → block."""
        raw = {"client_ip": "1.1.1.1", "uri_path": "/sql/inject/users", "timestamp": time.time()}
        our_dec = self._full_pipeline_keyword_decision(raw)
        orig_dec = self._direct_original_decision("/sql/inject/users")
        assert our_dec.block_reason is not None
        assert orig_dec.block_reason is not None

    def test_xss_keyword_path_blocks(self):
        """Path containing 'xssattack' (contains inherent 'xss') → block."""
        raw = {"client_ip": "2.2.2.2", "uri_path": "/xssattack/reflected", "timestamp": time.time()}
        our_dec = self._full_pipeline_keyword_decision(raw)
        orig_dec = self._direct_original_decision("/xssattack/reflected")
        assert our_dec.block_reason is not None
        assert orig_dec.block_reason is not None

    def test_clean_path_passes(self):
        raw = {"client_ip": "3.3.3.3", "uri_path": "/api/v1/health", "timestamp": time.time()}
        our_dec = self._full_pipeline_keyword_decision(raw)
        orig_dec = self._direct_original_decision("/api/v1/health")
        assert our_dec.block_reason is None
        assert orig_dec.block_reason is None

    def test_attack_segment_blocks(self):
        """'attack' is inherently malicious → block."""
        raw = {"client_ip": "4.4.4.4", "uri_path": "/attack/vector", "timestamp": time.time()}
        our_dec = self._full_pipeline_keyword_decision(raw)
        orig_dec = self._direct_original_decision("/attack/vector")
        assert our_dec.block_reason is not None
        assert orig_dec.block_reason is not None

    def test_exploit_segment_blocks(self):
        """'exploit' is inherently malicious → block."""
        raw = {"client_ip": "5.5.5.5", "uri_path": "/exploit/zero/day", "timestamp": time.time()}
        our_dec = self._full_pipeline_keyword_decision(raw)
        orig_dec = self._direct_original_decision("/exploit/zero/day")
        assert our_dec.block_reason is not None
        assert orig_dec.block_reason is not None

    def test_probe_env_path_blocks(self):
        raw = {"client_ip": "6.6.6.6", "uri_path": "/.env", "timestamp": time.time()}
        our_dec = self._full_pipeline_keyword_decision(raw)
        orig_dec = self._direct_original_decision("/.env")
        assert our_dec.block_reason is not None
        assert orig_dec.block_reason is not None

    def test_legitimate_long_path_passes(self):
        raw = {"client_ip": "7.7.7.7", "uri_path": "/api/users/profile", "timestamp": time.time()}
        our_dec = self._full_pipeline_keyword_decision(raw)
        orig_dec = self._direct_original_decision("/api/users/profile")
        assert our_dec.block_reason is None
        assert orig_dec.block_reason is None

    def test_backdoor_segment_blocks(self):
        raw = {"client_ip": "8.8.8.8", "uri_path": "/backdoor/access", "timestamp": time.time()}
        our_dec = self._full_pipeline_keyword_decision(raw)
        orig_dec = self._direct_original_decision("/backdoor/access")
        assert our_dec.block_reason is not None
        assert orig_dec.block_reason is not None

    def test_dynamic_keyword_pipeline(self):
        raw = {"client_ip": "9.9.9.9", "uri_path": "/shellupload/tools", "timestamp": time.time()}
        our_dec = self._full_pipeline_keyword_decision(raw, dynamic_kws=["shellupload"])
        orig_dec = self._direct_original_decision(
            "/shellupload/tools", dynamic_keywords=["shellupload"]
        )
        assert our_dec.block_reason is not None
        assert orig_dec.block_reason is not None
        assert our_dec.block_reason == orig_dec.block_reason

    def test_pipeline_handles_query_params(self):
        raw = {
            "client_ip": "10.10.10.10",
            "uri_path": "/hack",
            "timestamp": time.time(),
            "query_params": {"q": "search", "page": "1"},
        }
        our_dec = self._full_pipeline_keyword_decision(raw)
        orig_dec = self._direct_original_decision("/hack", query_keys=["q", "page"])
        assert our_dec.block_reason is not None  # "hack" is inherently malicious
        assert orig_dec.block_reason is not None

    def test_pipeline_query_keys_preserved(self):
        """Verify transform_raw_log correctly extracts query_keys."""
        raw = {
            "client_ip": "10.0.0.1",
            "uri_path": "/search",
            "query_params": {"q": "hello", "lang": "en"},
            "timestamp": time.time(),
        }
        std = transform_raw_log(raw)
        assert "q" in std["query_keys"]
        assert "lang" in std["query_keys"]
        assert len(std["query_keys"]) == 2
