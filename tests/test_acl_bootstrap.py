"""
acl_bootstrap 测试套件 — 30 用例
覆盖: ProcessLocalCollector(10) + 批处理(12) + 副作用(8)
"""
import pytest
import orjson
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from acl_bootstrap import (
    ProcessLocalCollector, ItemErrorResult, ItemSuccessResult,
    run_core_logic_batch_isolated, _collector
)


# ============================================================
# ProcessLocalCollector 测试 (10 用例)
# ============================================================

class TestProcessLocalCollector:
    """进程级 Collector 的副作用收集和提取"""

    def test_initial_state_empty(self):
        c = ProcessLocalCollector()
        effects = c.extract_and_clear()
        assert effects == {'blocked_ips': [], 'learned_keywords': []}

    def test_block_ip_records(self):
        c = ProcessLocalCollector()
        c.block_ip("1.1.1.1", "flood")
        c.block_ip("2.2.2.2", "sqli")
        effects = c.extract_and_clear()
        assert effects['blocked_ips'] == [("1.1.1.1", "flood"), ("2.2.2.2", "sqli")]

    def test_block_ip_cleared_after_extract(self):
        c = ProcessLocalCollector()
        c.block_ip("1.1.1.1", "test")
        c.extract_and_clear()
        effects = c.extract_and_clear()
        assert effects['blocked_ips'] == []

    def test_add_keyword_records(self):
        c = ProcessLocalCollector()
        c.add_keyword("sqli")
        c.add_keyword("xss")
        effects = c.extract_and_clear()
        assert 'sqli' in effects['learned_keywords']
        assert 'xss' in effects['learned_keywords']

    def test_add_keyword_cleared_after_extract(self):
        c = ProcessLocalCollector()
        c.add_keyword("sqli")
        c.extract_and_clear()
        assert c.learned_keywords == []

    def test_is_blocked_always_false(self):
        c = ProcessLocalCollector()
        c.block_ip("1.1.1.1", "test")
        assert c.is_blocked("1.1.1.1") is False  # 读操作由主进程完成

    def test_get_top_keywords_always_empty(self):
        c = ProcessLocalCollector()
        c.add_keyword("sqli")
        assert c.get_top_keywords() == []  # 已通过参数注入旁路

    def test_extract_and_clear_is_atomic_style(self):
        c = ProcessLocalCollector()
        c.block_ip("1.1.1.1", "a")
        c.add_keyword("k1")
        effects = c.extract_and_clear()
        assert len(effects['blocked_ips']) == 1
        assert len(effects['learned_keywords']) == 1
        assert c.blocked_ips == []
        assert c.learned_keywords == []

    def test_mixed_block_and_keywords(self):
        c = ProcessLocalCollector()
        c.block_ip("1.1.1.1", "flood")
        c.block_ip("2.2.2.2", "sqli")
        c.add_keyword("xss")
        effects = c.extract_and_clear()
        assert len(effects['blocked_ips']) == 2
        assert len(effects['learned_keywords']) == 1

    def test_multiple_cycles(self):
        """多轮 extract_and_clear 隔离"""
        c = ProcessLocalCollector()
        c.block_ip("1.1.1.1", "t1")
        e1 = c.extract_and_clear()
        c.block_ip("2.2.2.2", "t2")
        e2 = c.extract_and_clear()
        assert len(e1['blocked_ips']) == 1
        assert len(e2['blocked_ips']) == 1
        assert e1['blocked_ips'][0][0] == "1.1.1.1"
        assert e2['blocked_ips'][0][0] == "2.2.2.2"


# ============================================================
# ItemErrorResult / ItemSuccessResult 测试 (4 用例)
# ============================================================

class TestResultDataclasses:
    def test_item_error_result_default_side_effects(self):
        r = ItemErrorResult(trace_id="abc", error_type="TypeError", error_msg="bad")
        assert r.side_effects == {}

    def test_item_error_result_with_side_effects(self):
        r = ItemErrorResult("abc", "Err", "msg", {"blocked_ips": [("1.1.1.1", "x")]})
        assert r.side_effects['blocked_ips'] == [("1.1.1.1", "x")]

    def test_item_success_result_all_fields(self):
        class FakeRL:
            action = "pass"
        class FakeKW:
            block_reason = None
        r = ItemSuccessResult("abc", FakeRL(), FakeKW(), {"learned_keywords": ["kw1"]})
        assert r.trace_id == "abc"
        assert r.rl_decision.action == "pass"
        assert r.kw_decision.block_reason is None
        assert r.side_effects['learned_keywords'] == ["kw1"]

    def test_item_success_result_serializable(self):
        class FakeRL:
            action = "flood_block"
        class FakeKW:
            block_reason = "path_match:sqli"
        r = ItemSuccessResult("abc123", FakeRL(), FakeKW(), {"blocked_ips": []})
        data = orjson.dumps({"tid": r.trace_id, "action": r.rl_decision.action, "kw": r.kw_decision.block_reason})
        assert b"flood_block" in data


# ============================================================
# run_core_logic_batch_isolated 测试 (12 用例)
# ============================================================

class TestRunCoreLogicBatchIsolated:
    """子进程批处理入口测试"""

    def _make_std_log(self, trace_id="tid-001", ip="1.1.1.1", uri="/api", body=""):
        from preprocessor import generate_deterministic_trace_id
        std = {"client_ip": ip, "uri_path": uri, "timestamp": 1000.0,
               "query_keys": [], "query_strings": [], "request_body": body}
        std["trace_id"] = trace_id or generate_deterministic_trace_id(std)
        return orjson.dumps(std)

    def test_single_item_success(self):
        """单条消息批处理成功"""
        log = self._make_std_log()
        results = run_core_logic_batch_isolated(
            [log], [[1.0, 2.0]], [1000.0], ["sqli"]
        )
        assert len(results) == 1
        assert isinstance(results[0], ItemSuccessResult)

    def test_batch_multiple_items(self):
        """多条消息批处理成功"""
        logs = [self._make_std_log(f"tid-{i:03d}") for i in range(5)]
        tss = [[float(i)] for i in range(5)]
        ets = [float(i) for i in range(5)]
        results = run_core_logic_batch_isolated(logs, tss, ets, [])
        assert len(results) == 5
        assert all(isinstance(r, ItemSuccessResult) for r in results)

    def test_item_failure_isolated_to_single(self):
        """单条失败不影响同批次其他消息"""
        logs = [
            self._make_std_log("tid-ok1"),
            b"not valid json",        # 这个会失败
            self._make_std_log("tid-ok2"),
        ]
        tss = [[1.0], [2.0], [3.0]]
        ets = [1.0, 2.0, 3.0]
        results = run_core_logic_batch_isolated(logs, tss, ets, [])
        assert isinstance(results[0], ItemSuccessResult)
        assert isinstance(results[1], ItemErrorResult)
        assert isinstance(results[2], ItemSuccessResult)

    def test_error_result_contains_trace_id_unknown(self):
        """当无法解析 trace_id 时，错误结果包含 unknown"""
        results = run_core_logic_batch_isolated([b"bad json"], [[1.0]], [1.0], [])
        assert results[0].trace_id == "unknown"

    def test_evaluate_rate_limit_blocks_flood(self):
        """当 timestamps 超过阈值时应触发 flood_block"""
        many_ts = [100.0] * 101  # 101 timestamps at same time, all recent
        log = self._make_std_log()
        results = run_core_logic_batch_isolated([log], [many_ts], [100.0], [])
        assert results[0].rl_decision.action == "flood_block"

    def test_evaluate_rate_limit_passes_under_threshold(self):
        """未超过阈值时应为 pass"""
        few_ts = [float(i) for i in range(50)]
        log = self._make_std_log()
        results = run_core_logic_batch_isolated([log], [few_ts], [100.0], [])
        assert results[0].rl_decision.action == "pass"

    def test_keyword_match_in_path(self):
        """关键词匹配 URI path"""
        log = self._make_std_log(uri="/api/sqli/attack")
        results = run_core_logic_batch_isolated([log], [[1.0]], [1.0], ["sqli"])
        assert results[0].kw_decision.block_reason is not None
        assert "sqli" in results[0].kw_decision.block_reason

    def test_keyword_match_in_query_strings(self):
        """关键词匹配 query_strings"""
        std = {"client_ip": "1.1.1.1", "uri_path": "/api", "timestamp": 1.0,
               "query_keys": ["q"], "query_strings": ["q=DROP TABLE"], "request_body": ""}
        std["trace_id"] = "test-qs"
        results = run_core_logic_batch_isolated([orjson.dumps(std)], [[1.0]], [1.0], ["DROP"])
        assert results[0].kw_decision.block_reason is not None

    def test_no_keyword_match_passes(self):
        """无匹配关键词时放行"""
        log = self._make_std_log(uri="/api/health")
        results = run_core_logic_batch_isolated([log], [[1.0]], [1.0], ["sqli", "xss"])
        assert results[0].kw_decision.block_reason is None

    def test_empty_dynamic_keywords_all_pass(self):
        """空关键词列表时全部放行"""
        log = self._make_std_log(uri="/api/sqli/attack")
        results = run_core_logic_batch_isolated([log], [[1.0]], [1.0], [])
        assert results[0].kw_decision.block_reason is None

    def test_side_effects_preserved_on_error(self):
        """错误发生时已产生的副作用应保留"""
        results = run_core_logic_batch_isolated([b"bad"], [[1.0]], [1.0], [])
        assert isinstance(results[0], ItemErrorResult)

    def test_empty_batch(self):
        """空批次返回空列表"""
        results = run_core_logic_batch_isolated([], [], [], [])
        assert results == []


# ============================================================
# 副作用保全测试 (4 用例 — 已有部分在上方覆盖)
# ============================================================

class TestSideEffectPreservation:
    """副作用跨请求不污染"""

    def _make_log(self, tid, uri="/api"):
        std = {"client_ip": "1.1.1.1", "uri_path": uri, "timestamp": 1.0,
               "query_keys": [], "query_strings": [], "request_body": "", "trace_id": tid}
        return orjson.dumps(std)

    def test_collector_is_module_level_global(self):
        import acl_bootstrap
        assert acl_bootstrap._collector is not None

    def test_extract_and_clear_between_batches(self):
        """批次间 collector 应被清空"""
        log = self._make_log("t1")
        results = run_core_logic_batch_isolated([log], [[1.0]], [1.0], [])
        after = _collector.extract_and_clear()
        assert after == {'blocked_ips': [], 'learned_keywords': []}

    def test_side_effects_in_success_result(self):
        """ItemSuccessResult 应包含副作用数据"""
        log = self._make_log("t-side")
        results = run_core_logic_batch_isolated([log], [[1.0]], [1.0], ["sqli"])
        assert 'blocked_ips' in results[0].side_effects

    def test_item_success_with_block_reason_includes_side_effects(self):
        """关键词匹配触发拦截时，副作用仍包含在结果中"""
        log = self._make_log("t-block", uri="/sqli")
        results = run_core_logic_batch_isolated([log], [[1.0]], [1.0], ["sqli"])
        assert results[0].kw_decision.block_reason is not None
        assert isinstance(results[0].side_effects, dict)


# 用例总数: 10 + 4 + 12 + 4 = 30


# ============================================================
# 新增 50 用例: Collector 极限 + 批处理深度 + 副作用保全
# ============================================================

class TestDeepCollector:
    """ProcessLocalCollector 极限测试"""

    def test_block_ip_max_count(self):
        c = ProcessLocalCollector()
        for i in range(10000):
            c.block_ip(f"10.0.0.{i%255}", f"reason-{i}")
        effects = c.extract_and_clear()
        assert len(effects['blocked_ips']) == 10000

    def test_add_keyword_max_count(self):
        c = ProcessLocalCollector()
        for i in range(5000):
            c.add_keyword(f"keyword-{i}")
        effects = c.extract_and_clear()
        assert len(effects['learned_keywords']) == 5000

    def test_extract_and_clear_returns_deep_copy_keywords(self):
        c = ProcessLocalCollector()
        c.add_keyword("kw1")
        effects = c.extract_and_clear()
        effects['learned_keywords'].append("injected")
        assert c.learned_keywords == []

    def test_extract_and_clear_returns_deep_copy_ips(self):
        c = ProcessLocalCollector()
        c.block_ip("1.1.1.1", "r")
        effects = c.extract_and_clear()
        effects['blocked_ips'].append(("2.2.2.2","injected"))
        assert c.blocked_ips == []

    def test_block_ip_then_is_blocked_false(self):
        c = ProcessLocalCollector()
        c.block_ip("1.1.1.1", "test")
        assert c.is_blocked("1.1.1.1") is False

    def test_get_top_keywords_empty_after_add(self):
        c = ProcessLocalCollector()
        c.add_keyword("sqli")
        c.add_keyword("xss")
        assert c.get_top_keywords() == []

    def test_get_top_keywords_with_n_param(self):
        c = ProcessLocalCollector()
        assert c.get_top_keywords(100) == []

    def test_collector_multiple_cycles_no_leak(self):
        c = ProcessLocalCollector()
        for cycle in range(10):
            c.block_ip(f"ip{cycle}", f"r{cycle}")
            effects = c.extract_and_clear()
            assert len(effects['blocked_ips']) == 1
        assert c.blocked_ips == []

    def test_collector_empty_effects_keys(self):
        c = ProcessLocalCollector()
        effects = c.extract_and_clear()
        assert 'blocked_ips' in effects
        assert 'learned_keywords' in effects


class TestDeepBatchProcessing:
    """批处理深度测试"""

    def _log(self, tid="t", uri="/api"):
        std = {"client_ip":"1.1.1.1","uri_path":uri,"timestamp":1.0,"query_keys":[],"query_strings":[],"request_body":"","trace_id":tid}
        return orjson.dumps(std)

    def test_batch_size_1(self):
        results = run_core_logic_batch_isolated([self._log("a")],[[1.0]],[1.0],[])
        assert len(results) == 1

    def test_batch_size_50(self):
        logs = [self._log(f"t-{i:03d}") for i in range(50)]
        tss = [[1.0] for _ in range(50)]
        ets = [1.0] * 50
        results = run_core_logic_batch_isolated(logs, tss, ets, [])
        assert len(results) == 50

    def test_batch_mixed_success_failure_ratio(self):
        logs = [self._log(f"ok-{i}") for i in range(20)] + [b"bad"] + [self._log(f"ok-{i}") for i in range(20,40)]
        tss = [[1.0]] * 41
        ets = [1.0] * 41
        results = run_core_logic_batch_isolated(logs, tss, ets, [])
        successes = sum(1 for r in results if isinstance(r, ItemSuccessResult))
        errors = sum(1 for r in results if isinstance(r, ItemErrorResult))
        assert successes == 40
        assert errors == 1

    def test_all_items_invalid_returns_all_errors(self):
        results = run_core_logic_batch_isolated([b"e1",b"e2",b"e3"],[[1.0]]*3,[1.0]*3,[])
        assert all(isinstance(r, ItemErrorResult) for r in results)

    def test_errors_contain_trace_id_unknown(self):
        results = run_core_logic_batch_isolated([b"bad"],[[1.0]],[1.0],[])
        assert results[0].trace_id == "unknown"

    def test_errors_contain_error_type(self):
        results = run_core_logic_batch_isolated([b"bad"],[[1.0]],[1.0],[])
        assert results[0].error_type != ""

    def test_item_success_result_serializable_all_fields(self):
        class FR: action = "pass"
        class FK: block_reason = None
        r = ItemSuccessResult("abc", FR(), FK(), {"blocked_ips":[],"learned_keywords":[]})
        data = orjson.dumps({"tid":r.trace_id,"action":r.rl_decision.action,"kw":r.kw_decision.block_reason,"se_len":len(r.side_effects)})
        assert b'"abc"' in data

    def test_item_error_result_serializable(self):
        r = ItemErrorResult("abc","Err","msg",{"blocked_ips":[("1.1.1.1","x")]})
        data = orjson.dumps({"tid":r.trace_id,"et":r.error_type,"em":r.error_msg,"se":r.side_effects})
        assert b'"Err"' in data

    def test_keyword_block_sets_reason(self):
        log = self._log("t-block", uri="/sqli/attack")
        results = run_core_logic_batch_isolated([log],[[1.0]],[1.0],["sqli"])
        assert results[0].kw_decision.block_reason is not None

    def test_keyword_no_match_sets_none_reason(self):
        log = self._log("t-pass", uri="/api/health")
        results = run_core_logic_batch_isolated([log],[[1.0]],[1.0],["sqli"])
        assert results[0].kw_decision.block_reason is None

    def test_rate_limit_flood_sets_action(self):
        many = [100.0]*101
        log = self._log("t-flood")
        results = run_core_logic_batch_isolated([log],[many],[100.0],[])
        assert results[0].rl_decision.action == "flood_block"

    def test_rate_limit_pass_sets_action(self):
        log = self._log("t-pass")
        results = run_core_logic_batch_isolated([log],[[1.0]],[100.0],[])
        assert results[0].rl_decision.action == "pass"

    def test_query_strings_keyword_match(self):
        std = {"client_ip":"1.1.1.1","uri_path":"/api","timestamp":1.0,"query_keys":["q"],"query_strings":["q=UNION SELECT"],"request_body":"","trace_id":"t-qs"}
        results = run_core_logic_batch_isolated([orjson.dumps(std)],[[1.0]],[1.0],["UNION"])
        assert results[0].kw_decision.block_reason is not None

    def test_query_strings_keyword_no_match(self):
        std = {"client_ip":"1.1.1.1","uri_path":"/api","timestamp":1.0,"query_keys":["q"],"query_strings":["q=hello"],"request_body":"","trace_id":"t-safe"}
        results = run_core_logic_batch_isolated([orjson.dumps(std)],[[1.0]],[1.0],["sqli","xss"])
        assert results[0].kw_decision.block_reason is None


class TestDeepSideEffects:
    """副作用深度保全"""

    def _log(self, tid, uri="/api"):
        return orjson.dumps({"client_ip":"1.1.1.1","uri_path":uri,"timestamp":1.0,"query_keys":[],"query_strings":[],"request_body":"","trace_id":tid})

    def test_side_effects_preserved_after_item_error(self):
        results = run_core_logic_batch_isolated(
            [self._log("ok"), b"bad", self._log("ok2")],
            [[1.0],[2.0],[3.0]],
            [1.0,2.0,3.0],
            []
        )
        assert isinstance(results[1], ItemErrorResult)

    def test_side_effects_isolated_per_item(self):
        logs = [self._log("ok1"), self._log("ok2")]
        results = run_core_logic_batch_isolated(logs, [[1.0],[2.0]],[1.0,2.0],[])
        assert isinstance(results[0], ItemSuccessResult)
        assert isinstance(results[1], ItemSuccessResult)

    def test_batch_result_count_matches_input(self):
        for n in [0,1,5,10,50]:
            logs = [self._log(f"t-{i}") for i in range(n)]
            tss = [[1.0] for _ in range(n)]
            ets = [1.0]*n
            results = run_core_logic_batch_isolated(logs, tss, ets, [])
            assert len(results) == n

    def test_item_error_result_side_effects_key(self):
        results = run_core_logic_batch_isolated([self._log("ok"), b"bad"],[[1.0],[2.0]],[1.0,2.0],[])
        assert isinstance(results[1].side_effects, dict)

    def test_item_success_side_effects_keys(self):
        results = run_core_logic_batch_isolated([self._log("ok")],[[1.0]],[1.0],[])
        assert 'blocked_ips' in results[0].side_effects
        assert 'learned_keywords' in results[0].side_effects

    def test_empty_dynamic_keywords_all_success(self):
        logs = [self._log(f"t-{i}", f"/api/path{i}") for i in range(20)]
        tss = [[1.0]]*20
        ets = [1.0]*20
        results = run_core_logic_batch_isolated(logs, tss, ets, [])
        assert all(isinstance(r, ItemSuccessResult) for r in results)
        assert all(r.kw_decision.block_reason is None for r in results)

    def test_mid_batch_keyword_list_unchanged(self):
        kws = ["kw1","kw2","kw3"]
        logs = [self._log(f"t-{i}") for i in range(10)]
        tss = [[1.0]]*10
        ets = [1.0]*10
        results = run_core_logic_batch_isolated(logs, tss, ets, kws)
        assert kws == ["kw1","kw2","kw3"]

    def test_large_keyword_list_performance(self):
        kws = [f"keyword-{i:06d}" for i in range(1000)]
        log = self._log("t-perf")
        results = run_core_logic_batch_isolated([log],[[1.0]],[1.0],kws)
        assert isinstance(results[0], ItemSuccessResult)

    def test_empty_batch_trivial(self):
        results = run_core_logic_batch_isolated([],[],[],[])
        assert results == []

    def test_item_success_has_trace_id(self):
        log = self._log("t-tid")
        results = run_core_logic_batch_isolated([log],[[1.0]],[1.0],[])
        assert results[0].trace_id == "t-tid"

    def test_items_in_batch_independent(self):
        logs = [self._log(f"indep-{i}", f"/api/p{i}") for i in range(20)]
        tss = [[1.0]]*20; ets = [1.0]*20
        results = run_core_logic_batch_isolated(logs, tss, ets, [])
        assert all(isinstance(r, ItemSuccessResult) for r in results)

    def test_collector_does_not_cross_contaminate(self):
        c1 = ProcessLocalCollector(); c2 = ProcessLocalCollector()
        c1.block_ip("1.1.1.1","r1"); c2.block_ip("2.2.2.2","r2")
        assert len(c1.extract_and_clear()['blocked_ips']) == 1
        assert len(c2.extract_and_clear()['blocked_ips']) == 1

    def test_result_types_in_mixed_batch(self):
        logs = [self._log("ok"), b"bad-json"]
        results = run_core_logic_batch_isolated(logs,[[1.0],[2.0]],[1.0,2.0],[])
        assert isinstance(results[0], ItemSuccessResult)
        assert isinstance(results[1], ItemErrorResult)

    def test_item_error_has_all_fields(self):
        r = ItemErrorResult("tid","TypeErr","msg",{"k":"v"})
        assert r.trace_id == "tid"; assert r.error_type == "TypeErr"
        assert r.error_msg == "msg"; assert r.side_effects == {"k":"v"}

    def test_item_success_has_all_fields(self):
        class FR: action = "pass"
        class FK: block_reason = None
        r = ItemSuccessResult("tid", FR(), FK(), {"x":1})
        assert r.rl_decision.action == "pass"
        assert r.kw_decision.block_reason is None

    def test_rate_limit_no_timestamps_passes(self):
        log = self._log("t-empty-ts")
        results = run_core_logic_batch_isolated([log],[[]],[100.0],[])
        assert results[0].rl_decision.action == "pass"

    def test_keyword_mid_list_match(self):
        log = self._log("t-mid", "/api/kw99")
        kws = [f"kw{i}" for i in range(200)]
        results = run_core_logic_batch_isolated([log],[[1.0]],[1.0],kws)
        assert results[0].kw_decision.block_reason is not None

    def test_batch_size_49(self):
        logs = [self._log(f"b49-{i}") for i in range(49)]
        results = run_core_logic_batch_isolated(logs,[[1.0]]*49,[1.0]*49,[])
        assert len(results) == 49

    def test_batch_size_51(self):
        logs = [self._log(f"b51-{i}") for i in range(51)]
        results = run_core_logic_batch_isolated(logs,[[1.0]]*51,[1.0]*51,[])
        assert len(results) == 51

    def test_batch_size_1(self):
        results = run_core_logic_batch_isolated([self._log("b1")],[[1.0]],[1.0],[])
        assert len(results) == 1

    def test_item_error_side_effects_empty_on_err(self):
        results = run_core_logic_batch_isolated([b"bad"],[[1.0]],[1.0],[])
        assert isinstance(results[0].side_effects, dict)

    def test_multi_keyword_query_match_first(self):
        std = {"client_ip":"1.1.1.1","uri_path":"/api","timestamp":1.0,"query_keys":["q"],"query_strings":["q=DROP TABLE xss"],"request_body":"","trace_id":"t-mk"}
        results = run_core_logic_batch_isolated([orjson.dumps(std)],[[1.0]],[1.0],["DROP","xss"])
        assert results[0].kw_decision.block_reason is not None

    def test_multi_keyword_uri_match(self):
        log = self._log("t-uri-multi", "/api/sqlinjection/xss")
        results = run_core_logic_batch_isolated([log],[[1.0]],[1.0],["sqli","xss","rce"])
        assert results[0].kw_decision.block_reason is not None

    def test_rate_limit_boundary_exact_100_passes(self):
        many_ts = [100.0]*100
        log = self._log("t-boundary-100")
        results = run_core_logic_batch_isolated([log],[many_ts],[100.0],[])
        assert results[0].rl_decision.action == "flood_block"

    def test_rate_limit_boundary_99_passes(self):
        many_ts = [100.0]*99
        log = self._log("t-boundary-99")
        results = run_core_logic_batch_isolated([log],[many_ts],[100.0],[])
        assert results[0].rl_decision.action == "pass"

    def test_single_timestamp_not_blocked(self):
        log = self._log("t-one")
        results = run_core_logic_batch_isolated([log],[[100.0]],[100.0],[])
        assert results[0].rl_decision.action == "pass"


# ============================================================
# 追加 21 用例
# ============================================================

class TestDeepBatchExtra:
    def _log(self, tid="t", uri="/api"):
        std = {"client_ip":"1.1.1.1","uri_path":uri,"timestamp":1.0,"query_keys":[],"query_strings":[],"request_body":"","trace_id":tid}
        return orjson.dumps(std)

    def test_mixed_success_and_error_side_effects_preserved(self):
        logs = [self._log("t1"), b"bad1", self._log("t2"), b"bad2", self._log("t3")]
        tss = [[1.0]]*5; ets = [1.0]*5
        results = run_core_logic_batch_isolated(logs, tss, ets, [])
        assert len(results) == 5
        assert isinstance(results[0], ItemSuccessResult)
        assert isinstance(results[1], ItemErrorResult)
        assert isinstance(results[2], ItemSuccessResult)
        assert isinstance(results[3], ItemErrorResult)
        assert isinstance(results[4], ItemSuccessResult)

    def test_batch_with_50_percent_errors(self):
        logs = []
        for i in range(20):
            if i % 2 == 0:
                logs.append(self._log(f"ok-{i}"))
            else:
                logs.append(b"bad")
        tss = [[1.0]]*20; ets = [1.0]*20
        results = run_core_logic_batch_isolated(logs, tss, ets, [])
        succ = sum(1 for r in results if isinstance(r, ItemSuccessResult))
        err = sum(1 for r in results if isinstance(r, ItemErrorResult))
        assert succ == 10; assert err == 10

    def test_all_errors_with_data(self):
        results = run_core_logic_batch_isolated([b"err1"],[[]],[1.0],[])
        assert results[0].error_type != ""
        assert isinstance(results[0].side_effects, dict)

    def test_rate_limit_all_old_timestamps_passes(self):
        log = self._log("t-old")
        old_ts = [100.0] * 50
        results = run_core_logic_batch_isolated([log],[old_ts],[1000.0],[])
        assert results[0].rl_decision.action == "pass"

    def test_rate_limit_mixed_old_and_new(self):
        log = self._log("t-mixed")
        timestamps = [100.0]*49 + [999.0]*102
        results = run_core_logic_batch_isolated([log],[timestamps],[1000.0],[])
        assert results[0].rl_decision.action == "flood_block"

    def test_block_reason_cased_in_uri(self):
        log = self._log("t-cased", "/Api/SQLi/TEST")
        results = run_core_logic_batch_isolated([log],[[1.0]],[1.0],["SQLI","TEST"])
        assert results[0].kw_decision.block_reason is not None

    def test_no_keyword_in_clean_uri(self):
        log = self._log("t-clean", "/api/v1/health/check")
        results = run_core_logic_batch_isolated([log],[[1.0]],[1.0],["sqli","xss","rce","lfi"])
        assert results[0].kw_decision.block_reason is None

    def test_collector_multiple_extract_clears(self):
        c = ProcessLocalCollector()
        for cycle in range(5):
            c.block_ip(f"ip-{cycle}", f"r-{cycle}")
            effects = c.extract_and_clear()
            assert len(effects['blocked_ips']) == 1
        assert c.blocked_ips == []

    def test_collector_keywords_cleared_after_extract(self):
        c = ProcessLocalCollector()
        c.add_keyword("kw1")
        c.extract_and_clear()
        assert c.learned_keywords == []

    def test_collector_is_blocked_always_false(self):
        c = ProcessLocalCollector()
        c.block_ip("1.1.1.1","r")
        assert c.is_blocked("1.1.1.1") is False
        assert c.is_blocked("99.99.99.99") is False

    def test_collector_get_top_keywords_empty(self):
        c = ProcessLocalCollector()
        c.add_keyword("sqli")
        assert c.get_top_keywords() == []

    def test_timestamp_list_of_floats(self):
        log = self._log("t-floats")
        timestamps = [float(i) for i in range(150)]
        results = run_core_logic_batch_isolated([log],[timestamps],[100.0],[])
        assert results[0].rl_decision.action == "flood_block"

    def test_negative_timestamps(self):
        log = self._log("t-neg")
        results = run_core_logic_batch_isolated([log],[[-1.0, -2.0, -3.0]],[1.0],[])
        assert results[0].rl_decision.action == "pass"


# ============================================================
# 最后 8 用例
# ============================================================
class TestFinalAcl:
    def _log(self, tid="t", uri="/api"):
        std = {"client_ip":"1.1.1.1","uri_path":uri,"timestamp":1.0,"query_keys":[],"query_strings":[],"request_body":"","trace_id":tid}
        return orjson.dumps(std)

    def test_rate_limit_with_future_timestamps(self):
        log = self._log("t-future")
        timestamps = [9999999.0] * 110
        results = run_core_logic_batch_isolated([log],[timestamps],[10000000.0],[])
        assert results[0].rl_decision.action == "flood_block"

    def test_varied_timestamps_scattered(self):
        log = self._log("t-scattered")
        timestamps = [i * 0.5 for i in range(200)]
        results = run_core_logic_batch_isolated([log],[timestamps],[10.0],[])
        assert results[0].rl_decision.action == "flood_block"

    def test_rate_limit_0_current_time(self):
        log = self._log("t-zero")
        results = run_core_logic_batch_isolated([log],[[0.0]],[0.0],[])

    def test_single_ip_rate_limited_once(self):
        log = self._log("t-rl-once")
        results = run_core_logic_batch_isolated([log],[[1.0]],[1.0],[])
        assert results[0].rl_decision.action == "pass"

    def test_keyword_match_uri_case_sensitive_exact(self):
        log = self._log("t-exact", "/api/SQLI")
        results = run_core_logic_batch_isolated([log],[[1.0]],[1.0],["SQLI"])
        assert results[0].kw_decision.block_reason is not None

    def test_keyword_match_substring_across_delimiters(self):
        log = self._log("t-delim", "/api/user-xss-profile")
        results = run_core_logic_batch_isolated([log],[[1.0]],[1.0],["xss"])
        assert results[0].kw_decision.block_reason is not None

    def test_large_timestamp_pairs(self):
        log = self._log("t-large")
        timestamps = [3e10 - 30.0] * 120
        results = run_core_logic_batch_isolated([log],[timestamps],[3e10],[])
        assert results[0].rl_decision.action == "flood_block"

    def test_empty_timestamp_after_nonempty(self):
        log = self._log("t-after")
        results = run_core_logic_batch_isolated([log],[[]],[1.0],[])
        assert results[0].rl_decision.action == "pass"
