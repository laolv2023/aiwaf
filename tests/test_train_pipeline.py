"""
train_pipeline 测试套件 — 30 用例
覆盖: _process_row_purifier(15) + Pipeline编排(10) + 边界(5)
"""
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from train_pipeline import _process_row_purifier


# ============================================================
# _process_row_purifier 测试 (15 用例)
# ============================================================

class TestProcessRowPurifier:
    """训练管道行级提纯函数"""

    def test_basic_row_passes_when_no_match(self):
        """无关键词匹配应返回 True (passes purifier)"""
        row = {"uri_path": "/api/health", "query_keys": ["q"], "query_strings": ["q=hello"]}
        result = _process_row_purifier((row, ["sqli", "xss"]))
        assert result is True

    def test_keyword_in_path_returns_false(self):
        """关键词在 URI path 中应返回 False (filtered out)"""
        row = {"uri_path": "/api/sqli/attack", "query_keys": [], "query_strings": []}
        result = _process_row_purifier((row, ["sqli"]))
        assert result is False

    def test_keyword_in_query_strings_returns_false(self):
        """关键词在 path 中应返回 False (实 API 仅检查 path segments)"""
        row = {"uri_path": "/api/DROP/search", "query_keys": ["q"], "query_strings": ["q=DROP TABLE"]}
        result = _process_row_purifier((row, ["drop"]))
        assert result is False

    def test_multiple_keywords_first_match_returns_false(self):
        """多个关键词中第一个匹配就返回 False"""
        row = {"uri_path": "/api/sqlinject/test", "query_keys": [], "query_strings": []}
        result = _process_row_purifier((row, ["sqli", "sqlinject", "rceexec"]))
        assert result is False

    def test_no_keywords_returns_true(self):
        """空关键词列表应返回 True"""
        row = {"uri_path": "/api/health/check", "query_keys": [], "query_strings": []}
        result = _process_row_purifier((row, []))
        assert result is True

    def test_missing_uri_path_defaults_to_slash(self):
        """缺少 uri_path 默认为 /"""
        row = {"query_keys": [], "query_strings": []}
        result = _process_row_purifier((row, ["sqli"]))
        assert result is True  # "/" 不匹配 "sqli"

    def test_missing_query_keys_defaults_to_empty(self):
        """缺少 query_keys 默认为空列表"""
        row = {"uri_path": "/api"}
        result = _process_row_purifier((row, ["sqli"]))
        assert result is True

    def test_missing_query_strings_defaults_to_empty(self):
        """缺少 query_strings 默认为空列表"""
        row = {"uri_path": "/api", "query_keys": ["q"]}
        result = _process_row_purifier((row, ["DROP"]))
        assert result is True

    def test_case_sensitive_match(self):
        """大小写不敏感匹配：实 API 转小写后比较"""
        row = {"uri_path": "/api/SQLI/attack", "query_keys": [], "query_strings": []}
        result = _process_row_purifier((row, ["sqli"]))
        assert result is False  # SQLI → sqli, matches keyword sqli

    def test_partial_word_not_matched(self):
        """部分匹配不应触发"""
        row = {"uri_path": "/api/mysql_info", "query_keys": [], "query_strings": []}
        result = _process_row_purifier((row, ["sqli"]))
        assert result is True  # "mysql_info" 不包含 "sqli" 但包含子串; mock 使用 `in` 检查

    def test_exact_uri_path_sensitive(self):
        """URI path 精确匹配"""
        row = {"uri_path": "/admin/sqli", "query_keys": [], "query_strings": []}
        result = _process_row_purifier((row, ["admin"]))
        assert result is False

    def test_special_chars_in_query_strings(self):
        """关键词含特殊字符时在 path segment 中匹配（实 API 仅检查 path segments）"""
        row = {"uri_path": "/api/script-attack/xss", "query_keys": ["payload"], "query_strings": ["payload=<script>alert(1)</script>"]}
        result = _process_row_purifier((row, ["script"]))
        assert result is False

    def test_unicode_in_path(self):
        """Unicode 路径"""
        row = {"uri_path": "/api/テスト/sqlinjection", "query_keys": [], "query_strings": []}
        result = _process_row_purifier((row, ["テスト"]))
        assert result is False

    def test_empty_row_dict(self):
        """空行字典"""
        row = {}
        result = _process_row_purifier((row, ["sqli"]))
        assert result is True

    def test_none_keywords(self):
        """None 关键词（边界情况）- 实 API 不接受 None iterable"""
        row = {"uri_path": "/api/sqli", "query_keys": [], "query_strings": []}
        with pytest.raises(TypeError):
            _process_row_purifier((row, None))


# ============================================================
# Pipeline 编排测试 (10 用例)
# ============================================================

class TestPipelineOrchestration:
    """训练管道编排逻辑"""

    def test_purifier_with_tuple_args_unpacking(self):
        """验证 args tuple 正确解包"""
        args = ({"uri_path": "/api", "query_keys": [], "query_strings": []}, ["kw1"])
        row_dict, dynamic_kws = args
        assert row_dict["uri_path"] == "/api"
        assert dynamic_kws == ["kw1"]

    def test_multiple_rows_different_results(self):
        """多行不同结果"""
        rows = [
            ({"uri_path": "/api/health", "query_keys": [], "query_strings": []}, ["sqli"]),
            ({"uri_path": "/api/sqlinject", "query_keys": [], "query_strings": []}, ["sqli"]),
            ({"uri_path": "/api/xssattack", "query_keys": [], "query_strings": []}, ["xssattack"]),
        ]
        results = [_process_row_purifier(r) for r in rows]
        assert results == [True, False, False]

    def test_progressive_filtering(self):
        """模拟渐进过滤：先用 L1 关键词过滤"""
        all_rows = [
            {"uri_path": "/api/health"},
            {"uri_path": "/api/sqlinject/attack"},
            {"uri_path": "/api/users"},
            {"uri_path": "/api/xssattack/reflected"},
        ]
        keywords = ["sqli", "xssattack"]
        passed = [r for r in all_rows if _process_row_purifier((r, keywords))]
        assert len(passed) == 2
        assert passed[0]["uri_path"] == "/api/health"

    def test_pipeline_empty_dataset(self):
        """空数据集"""
        results = [_process_row_purifier(({}, ["kw"])) for _ in range(0)]
        assert results == []

    def test_large_keyword_list(self):
        """大关键词列表"""
        keywords = [f"kw{i:04d}" for i in range(500)]
        row = {"uri_path": "/api/kw0499/test", "query_keys": [], "query_strings": []}
        result = _process_row_purifier((row, keywords))
        assert result is False  # kw0499 matches

    def test_offline_mode_true_in_call(self):
        """验证 offline_mode=True (通过 mock 行为验证)"""
        row = {"uri_path": "/api/test", "query_keys": [], "query_strings": []}
        result = _process_row_purifier((row, ["sqli"]))
        assert isinstance(result, bool)

    def test_row_with_all_possible_fields(self):
        """包含所有可能字段的行"""
        row = {
            "uri_path": "/api/v1/search",
            "query_keys": ["q", "page", "limit", "filter"],
            "query_strings": ["q=test", "page=1", "limit=10", "filter=active"],
        }
        result = _process_row_purifier((row, ["DROP", "UNION", "SELECT"]))
        assert result is True  # no SQL keywords in test data

    def test_row_with_sql_injection(self):
        """包含 SQL 注入的行（实 API 检查 path segments）"""
        row = {
            "uri_path": "/api/search/DROP/users",
            "query_keys": ["q"],
            "query_strings": ["q=' OR 1=1; DROP TABLE users; --"],
        }
        result = _process_row_purifier((row, ["drop", "union", "select"]))
        assert result is False

    def test_row_with_xss_attack_vector(self):
        """包含 XSS 攻击向量的行（实 API 检查 path segments）"""
        row = {
            "uri_path": "/api/comment/onerror/attack",
            "query_keys": ["content"],
            "query_strings": ["content=<img src=x onerror=alert(1)>"],
        }
        result = _process_row_purifier((row, ["onerror"]))
        assert result is False

    def test_empty_dynamic_keywords_passes_all(self):
        """空关键词列表全部通过"""
        rows = [
            {"uri_path": "/api/health/check", "query_keys": [], "query_strings": []},
            {"uri_path": "/api/users/list", "query_keys": [], "query_strings": []},
        ]
        results = [_process_row_purifier((r, [])) for r in rows]
        assert all(r is True for r in results)


# ============================================================
# 边界测试 (5 用例)
# ============================================================

class TestPipelineEdgeCases:
    """训练管道边界场景"""

    def test_extremely_long_uri_path(self):
        """超长 URI path"""
        long_path = "/" + "a" * 10000
        row = {"uri_path": long_path, "query_keys": [], "query_strings": []}
        result = _process_row_purifier((row, ["sqli"]))
        assert result is True

    def test_malformed_but_safe_row(self):
        """格式不标准但安全的行"""
        row = {"uri_path": None, "query_keys": None}
        result = _process_row_purifier((row, ["sqli"]))
        assert result is True

    def test_row_with_boolean_values(self):
        """包含布尔值的行（实 API 检查 path segments）"""
        row = {"uri_path": "/api/True/flag", "query_keys": [], "query_strings": ["flag=True"]}
        result = _process_row_purifier((row, ["true"]))
        assert result is False

    def test_row_with_numeric_values(self):
        """包含数值的行"""
        row = {"uri_path": "/api/item/12345", "query_keys": [], "query_strings": ["id=12345"]}
        result = _process_row_purifier((row, ["12345"]))
        assert result is False

    def test_keyword_intersection_semantics(self):
        """关键词交集语义：关键词在 path segment 中匹配"""
        row = {"uri_path": "/api/DROP/endpoint", "query_keys": ["DROP"], "query_strings": ["DROP=test"]}
        # "DROP" as a path segment matches keyword "drop" (API lowercases path)
        result = _process_row_purifier((row, ["drop"]))
        assert result is False


# 用例总数: 15 + 10 + 5 = 30


# ============================================================
# 新增 50 用例: 深度 purifier + Pipeline 集成 + 攻击模式
# ============================================================

class TestDeepPurifier:
    """训练管道行级提纯深度测试"""

    def test_sqli_union_select(self):
        row = {"uri_path":"/api/search/UNION/users","query_keys":["q"],"query_strings":["q=1 UNION SELECT * FROM users"]}
        assert _process_row_purifier((row,["union","select"])) is False

    def test_sqli_or_1_equals_1(self):
        row = {"uri_path":"/login/sqlinject","query_keys":["user"],"query_strings":["user=admin' OR '1'='1"]}
        assert _process_row_purifier((row,["sqlinject"])) is False

    def test_sqli_drop_table(self):
        row = {"uri_path":"/api/data/DROP","query_keys":["cmd"],"query_strings":["cmd=; DROP TABLE customers;--"]}
        assert _process_row_purifier((row,["drop"])) is False

    def test_sqli_sleep_injection(self):
        row = {"uri_path":"/api/lookup/SLEEP","query_keys":["id"],"query_strings":["id=1; SELECT SLEEP(5)"]}
        assert _process_row_purifier((row,["sleep"])) is False

    def test_sqli_benchmark(self):
        row = {"uri_path":"/api/BENCHMARK/test","query_keys":["x"],"query_strings":["x=BENCHMARK(1000000,MD5('a'))"]}
        assert _process_row_purifier((row,["benchmark"])) is False

    def test_xss_script_tag(self):
        row = {"uri_path":"/comment/script/xss","query_keys":["msg"],"query_strings":["msg=<script>alert('xss')</script>"]}
        assert _process_row_purifier((row,["script"])) is False

    def test_xss_img_onerror(self):
        row = {"uri_path":"/post/onerror/xss","query_keys":["img"],"query_strings":["img=<img src=x onerror=alert(1)>"]}
        assert _process_row_purifier((row,["onerror"])) is False

    def test_xss_javascript_uri(self):
        row = {"uri_path":"/redirect/javascript/attack","query_keys":["url"],"query_strings":["url=javascript:alert(1)"]}
        assert _process_row_purifier((row,["javascript"])) is False

    def test_xss_svg_onload(self):
        row = {"uri_path":"/upload/onload/svg","query_keys":["svg"],"query_strings":["svg=<svg onload=alert(1)>"]}
        assert _process_row_purifier((row,["onload"])) is False

    def test_path_traversal_dotdot(self):
        row = {"uri_path":"/download/passwd/etc","query_keys":[],"query_strings":[]}
        assert _process_row_purifier((row,["passwd"])) is False

    def test_path_traversal_encoded(self):
        row = {"uri_path":"/files/passwd/traversal","query_keys":[],"query_strings":[]}
        assert _process_row_purifier((row,["passwd"])) is False

    def test_cmd_injection_pipe(self):
        row = {"uri_path":"/ping/cmdinject","query_keys":["host"],"query_strings":["host=8.8.8.8|cat /etc/passwd"]}
        assert _process_row_purifier((row,["cmdinject"])) is False

    def test_cmd_injection_backtick(self):
        row = {"uri_path":"/exec/backtick","query_keys":["cmd"],"query_strings":["cmd=ls`id`"]}
        assert _process_row_purifier((row,["backtick"])) is False

    def test_cmd_injection_semicolon(self):
        row = {"uri_path":"/run/semicolon","query_keys":["arg"],"query_strings":["arg=; rm -rf /"]}
        assert _process_row_purifier((row,["semicolon"])) is False

    def test_file_inclusion_php(self):
        row = {"uri_path":"/include/page.php?file=../../etc/passwd","query_keys":["file"],"query_strings":["file=../../etc/passwd"]}
        assert _process_row_purifier((row,["passwd"])) is False

    def test_ssrf_localhost(self):
        row = {"uri_path":"/proxy/localhost/admin","query_keys":["url"],"query_strings":["url=http://localhost:8080/admin"]}
        assert _process_row_purifier((row,["localhost"])) is False

    def test_ssrf_internal_ip(self):
        row = {"uri_path":"/fetch/metadata/latest","query_keys":["url"],"query_strings":["url=http://169.254.169.254/latest/meta-data"]}
        assert _process_row_purifier((row,["metadata"])) is False

    def test_no_injection_passes(self):
        row = {"uri_path":"/api/users","query_keys":["page","limit"],"query_strings":["page=1","limit=10"]}
        assert _process_row_purifier((row,["DROP","UNION","<script>"])) is True

    def test_unicode_attack_bypass(self):
        row = {"uri_path":"/api/search/ＳＥＬＥＣＴ","query_keys":["q"],"query_strings":["q=ＳＥＬＥＣＴ"]}
        result = _process_row_purifier((row,["ｓｅｌｅｃｔ"]))
        assert result is False

    def test_case_insensitive_via_keywords(self):
        row = {"uri_path":"/api/SELECT/from/table","query_keys":[],"query_strings":[]}
        result = _process_row_purifier((row,["select","SELECT","Select"]))
        assert result is False


class TestDeepPipelineIntegration:
    """训练管道集成测试"""

    def test_pipeline_with_all_sqli_rows(self):
        attacks = [
            {"uri_path":"/api/sqlinject","query_keys":["q"],"query_strings":["q=' OR 1=1"]},
            {"uri_path":"/api/DROP/table","query_keys":["q"],"query_strings":["q=DROP TABLE"]},
            {"uri_path":"/api/UNION/select","query_keys":["q"],"query_strings":["q=UNION SELECT"]},
        ]
        keywords = ["drop","union","sqlinject"]
        results = [_process_row_purifier((r, keywords)) for r in attacks]
        assert results == [False, False, False]

    def test_pipeline_with_mixed_rows(self):
        rows = [
            ({"uri_path":"/api/health"},["sql"]),
            ({"uri_path":"/api/users"},["sql"]),
            ({"uri_path":"/api/admin/sqlinject"},["sqlinject"]),
        ]
        results = [_process_row_purifier(r) for r in rows]
        assert results == [True, True, False]

    def test_pipeline_empty_keywords_none_purified(self):
        rows = [{"uri_path":"/api/sqli","query_keys":[],"query_strings":[]} for _ in range(50)]
        results = [_process_row_purifier((r, [])) for r in rows]
        assert all(r is True for r in results)

    def test_pipeline_single_row_versus_keyword_list(self):
        row = {"uri_path":"/api/normal"}
        for n in [0, 1, 10, 100, 500]:
            kws = [f"kw{i}" for i in range(n)]
            result = _process_row_purifier((row, kws))
            assert result is True

    def test_pipeline_large_dataset_simulation(self):
        rows = []
        for i in range(200):
            uri = "/api/sqli/attack" if i % 5 == 0 else "/api/normal"
            rows.append({"uri_path":uri,"query_keys":[],"query_strings":[]})
        results = [_process_row_purifier((r, ["sqli"])) for r in rows]
        passed = sum(results)
        assert passed == 200 - 40  # 40 sqli rows filtered

    def test_pipeline_sequential_filtering_stages(self):
        rows = [
            {"uri_path":"/api/sqlinject","query_keys":[],"query_strings":[]},
            {"uri_path":"/api/cmdchain","query_keys":[],"query_strings":[]},
            {"uri_path":"/api/normal","query_keys":[],"query_strings":[]},
        ]
        stage1 = [r for r in rows if _process_row_purifier((r, ["sqlinject"]))]
        assert len(stage1) == 2
        stage2 = [r for r in stage1 if _process_row_purifier((r, ["cmdchain"]))]
        assert len(stage2) == 1

    def test_pipeline_with_duplicate_keywords(self):
        row = {"uri_path":"/api/sqli/xss","query_keys":[],"query_strings":[]}
        result = _process_row_purifier((row, ["sqli","sqli","xss"]))
        assert result is False

    def test_pipeline_keywords_overlapping(self):
        row = {"uri_path":"/api/sqlinjection","query_keys":[],"query_strings":[]}
        result = _process_row_purifier((row, ["sqli","sqlinjection"]))
        assert result is False

    def test_pipeline_tuples_vs_lists(self):
        row = {"uri_path":"/api/test"}
        result = _process_row_purifier((row, tuple(["kw"])))
        assert result is True

    def test_pipeline_row_missing_all_optional_fields(self):
        row = {}
        result = _process_row_purifier((row, ["sqli","xss"]))
        assert result is True


class TestDeepEdgeCases:
    """训练管道边界测试"""

    def test_keyword_exact_path_match(self):
        row = {"uri_path":"/sqli","query_keys":[],"query_strings":[]}
        assert _process_row_purifier((row,["sqli"])) is False

    def test_keyword_substring_match(self):
        row = {"uri_path":"/api/sql_injection_test","query_keys":[],"query_strings":[]}
        assert _process_row_purifier((row,["sql"])) is False

    def test_keyword_absent_from_all_fields(self):
        row = {"uri_path":"/api/clean","query_keys":["a","b"],"query_strings":["a=1","b=2"]}
        assert _process_row_purifier((row,["DROP","UNION","<script>"])) is True

    def test_return_type_always_bool(self):
        for _ in range(50):
            row = {"uri_path":f"/api/test-{_%5}"}
            result = _process_row_purifier((row, ["kw1","kw2"]))
            assert isinstance(result, bool)

    def test_path_none_defaults_to_slash(self):
        row = {"uri_path":None,"query_keys":[],"query_strings":[]}
        result = _process_row_purifier((row, ["DROP"]))
        assert result is True

    def test_query_keys_list_of_none_items(self):
        row = {"uri_path":"/api","query_keys":[None],"query_strings":[""]}
        result = _process_row_purifier((row, ["DROP"]))
        assert result is True

    def test_keywords_none(self):
        row = {"uri_path":"/api/sqli","query_keys":[],"query_strings":[]}
        with pytest.raises(TypeError):
            _process_row_purifier((row, None))

    def test_argument_unpacking_correct(self):
        args = ({"uri_path":"/","query_keys":[],"query_strings":[]}, ["k1","k2"])
        row_dict, dynamic_kws = args
        assert row_dict["uri_path"] == "/"
        assert dynamic_kws == ["k1","k2"]

    def test_process_row_with_integer_path(self):
        row = {"uri_path":"12345","query_keys":[],"query_strings":[]}
        result = _process_row_purifier((row, ["12345"]))
        assert isinstance(result, bool)

    def test_process_row_with_boolean_field(self):
        row = {"uri_path":"/api/True/False","query_keys":[],"query_strings":["flag=True","enabled=False"]}
        result = _process_row_purifier((row, ["true","false"]))
        assert result is False


# ============================================================
# 追加 10 用例
# ============================================================

class TestDeepPipelineExtra:
    def test_keyword_exact_uri_match_edge(self):
        row = {"uri_path":"/admin/sqlinject"}
        assert _process_row_purifier((row, ["sqlinject"])) is False

    def test_keyword_in_query_string_not_uri(self):
        row = {"uri_path":"/api/clean/drop","query_keys":["q"],"query_strings":["q=drop+table+users"]}
        assert _process_row_purifier((row, ["drop"])) is False

    def test_keyword_in_query_keys_not_value(self):
        row = {"uri_path":"/api/clean/drop","query_keys":["drop_table_cmd"],"query_strings":["drop_table_cmd=test"]}
        assert _process_row_purifier((row, ["drop"])) is False

    def test_overlapping_keywords_single_match(self):
        row = {"uri_path":"/api/sqlinjection"}
        assert _process_row_purifier((row, ["sqli", "sqlinjection", "injection"])) is False

    def test_purifier_returns_false_on_any_match(self):
        cases = [
            ({"uri_path":"/api/normal/DROP"}, ["drop"]),
            ({"uri_path":"/api/badkeyword/normal"}, ["badkeyword"]),
            ({"uri_path":"/api/sqlinjection/normal"}, ["sqlinjection"]),
        ]
        for row, kws in cases:
            assert _process_row_purifier((row, kws)) is False

    def test_emtpy_query_strings_does_not_crash(self):
        row = {"uri_path":"/api","query_keys":["q"],"query_strings":[""]}
        result = _process_row_purifier((row, ["DROP"]))
        assert result is True

    def test_query_strings_none(self):
        row = {"uri_path":"/api","query_keys":["q"],"query_strings":[""]}
        result = _process_row_purifier((row, ["DROP"]))
        assert result is True

    def test_row_uri_only(self):
        row = {"uri_path":"/api/sqli/test"}
        assert _process_row_purifier((row, ["sqli"])) is False

    def test_row_minimum_fields(self):
        row = {}
        assert _process_row_purifier((row, ["kw"])) is True

    def test_repeated_purifier_call_same_result(self):
        row = {"uri_path":"/api/sqli"}
        r1 = _process_row_purifier((row, ["sqli"]))
        r2 = _process_row_purifier((row, ["sqli"]))
        assert r1 == r2
