"""分析引擎单元测试（不依赖网络/框架）。"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import analyzer, licenses, policies  # noqa: E402


def test_canonicalize_aliases():
    assert licenses.canonicalize("apache2") == "Apache-2.0"
    assert licenses.canonicalize("GPLv3") == "NOASSERTION"
    assert licenses.canonicalize("mit") == "MIT"
    assert licenses.canonicalize("") == "NOASSERTION"
    assert licenses.canonicalize(None) == "NOASSERTION"


def test_matrix_basic_compatibility():
    assert licenses.compatibility("MIT", "MIT") == "allow"
    assert licenses.compatibility("MIT", "GPL-3.0") == "deny"
    assert licenses.compatibility("Apache-2.0", "GPL-2.0") == "deny"
    assert licenses.compatibility("Apache-2.0", "GPL-3.0") == "allow"
    assert licenses.compatibility("GPL-3.0", "Apache-2.0") == "allow"
    assert licenses.compatibility("Proprietary", "AGPL-3.0") == "deny"
    assert licenses.compatibility("Proprietary", "MPL-2.0") == "review"
    assert licenses.compatibility("MIT", "Proprietary") == "review"


def test_spdx_expression_or_takes_best():
    verdict, hit, members = licenses.evaluate_expression("MIT OR GPL-3.0", "MIT")
    assert verdict == "allow"
    assert hit == "MIT"
    assert set(members) == {"MIT", "GPL-3.0"}


def test_spdx_expression_and_takes_worst():
    verdict, hit, _ = licenses.evaluate_expression("MIT AND GPL-3.0", "MIT")
    assert verdict == "deny"
    assert hit == "GPL-3.0"


def test_spdx_expression_nested_and_with():
    verdict, hit, _ = licenses.evaluate_expression(
        "Apache-2.0 AND (MIT OR BSD-3-Clause)", "Apache-2.0"
    )
    assert verdict == "allow"


def test_or_expression_with_copyleft_branch_selectable_permissive():
    # OR 表示被许可方可择一：MIT OR GPL-3.0 选 MIT，策略不应被 GPL 分支误伤
    data = {
        "packages": [
            {"name": "app", "version": "1", "license": "MIT", "dependencies": ["dual"]},
            {"name": "dual", "version": "1", "license": "MIT OR GPL-3.0",
             "dependencies": []},
        ]
    }
    res = analyzer.analyze(data, policies.POLICIES["permissive"])
    dual = next(p for p in res["packages"] if p["id"] == "dual@1")
    assert dual["verdict"] == "allow"
    assert dual["license_members"] == ["MIT", "GPL-3.0"]


def test_or_expression_no_compatible_branch_denied():
    # 两个分支都不兼容时仍判冲突
    data = {
        "packages": [
            {"name": "app", "version": "1", "license": "MIT", "dependencies": ["dual"]},
            {"name": "dual", "version": "1", "license": "GPL-2.0 OR AGPL-3.0",
             "dependencies": []},
        ]
    }
    res = analyzer.analyze(data, policies.POLICIES["permissive"])
    dual = next(p for p in res["packages"] if p["id"] == "dual@1")
    assert dual["verdict"] == "deny"


def test_and_expression_with_copyleft_branch_strict():
    # AND 条款同时适用，含 GPL 分支即按 GPL 处理
    data = {
        "packages": [
            {"name": "app", "version": "1", "license": "MIT", "dependencies": ["dual"]},
            {"name": "dual", "version": "1", "license": "MIT AND GPL-3.0",
             "dependencies": []},
        ]
    }
    res = analyzer.analyze(data, policies.POLICIES["strict"])
    dual = next(p for p in res["packages"] if p["id"] == "dual@1")
    assert dual["verdict"] == "deny"
    assert dual["rule_kind"] == "POLICY_DENY"


def test_policy_deny_overrides_matrix_allow():
    # GPL-3.0 项目 + Apache-2.0 矩阵 allow，但专有策略下改选项目许可证？
    # 这里直接验证：严格白名单策略把 MPL 判 deny（矩阵 MIT+MPL 是 allow）
    data = {
        "packages": [
            {"name": "app", "version": "1", "license": "MIT", "dependencies": ["m"]},
            {"name": "m", "version": "1", "license": "MPL-2.0", "dependencies": []},
        ]
    }
    res = analyzer.analyze(data, policies.POLICIES["strict"])
    pkgs = {p["id"]: p for p in res["packages"]}
    assert pkgs["m@1"]["verdict"] == "deny"
    assert pkgs["m@1"]["rule_kind"] == "POLICY_DENY"


def test_policy_allow_family_overrides_review():
    # 宽松策略：MIT + LGPL 矩阵 review，allow_families 含 weak_copyleft → allow
    data = {
        "packages": [
            {"name": "app", "version": "1", "license": "MIT", "dependencies": ["l"]},
            {"name": "l", "version": "1", "license": "LGPL-2.1", "dependencies": []},
        ]
    }
    res = analyzer.analyze(data, policies.POLICIES["permissive"])
    pkgs = {p["id"]: p for p in res["packages"]}
    assert pkgs["l@1"]["verdict"] == "allow"
    assert pkgs["l@1"]["rule_kind"] == "POLICY_ALLOW"


def test_strict_unknown_denied():
    data = {
        "packages": [
            {"name": "app", "version": "1", "license": "MIT", "dependencies": ["x"]},
            {"name": "x", "version": "1", "license": "Custom-Weird", "dependencies": []},
        ]
    }
    res = analyzer.analyze(data, policies.POLICIES["strict"])
    pkgs = {p["id"]: p for p in res["packages"]}
    assert pkgs["x@1"]["verdict"] == "deny"


def test_permissive_unknown_review():
    data = {
        "packages": [
            {"name": "app", "version": "1", "license": "MIT", "dependencies": ["x"]},
            {"name": "x", "version": "1", "license": "Custom-Weird", "dependencies": []},
        ]
    }
    res = analyzer.analyze(data, policies.POLICIES["permissive"])
    pkgs = {p["id"]: p for p in res["packages"]}
    assert pkgs["x@1"]["verdict"] == "review"
    assert pkgs["x@1"]["severity"] == "warning"


def test_shortest_path_transitive_conflict():
    data = {
        "project": {"name": "demo"},
        "packages": [
            {"name": "root", "version": "1", "license": "MIT",
             "dependencies": ["a", "b"]},
            {"name": "a", "version": "1", "license": "MIT",
             "dependencies": ["gpl-deep"]},
            {"name": "b", "version": "1", "license": "MIT", "dependencies": []},
            {"name": "gpl-deep", "version": "9", "license": "GPL-3.0",
             "dependencies": []},
        ]
    }
    res = analyzer.analyze(data, policies.POLICIES["permissive"])
    gpl = next(p for p in res["packages"] if p["name"] == "gpl-deep")
    assert gpl["verdict"] == "deny"
    assert gpl["shortest_path"] == ["root@1", "a@1", "gpl-deep@9"]
    assert gpl["depth"] == 2
    assert gpl["direct"] is False
    assert "GPL-3.0" in gpl["message"]
    # root/b/a 兼容
    allowed = {p["id"]: p["verdict"] for p in res["packages"]}
    assert allowed["root@1"] == "allow"


def test_explicit_direct_dependencies_and_version_resolution():
    data = {
        "direct_dependencies": ["app"],
        "packages": [
            {"name": "app", "version": "1", "license": "MIT",
             "dependencies": ["lib@2.0.0"]},
            {"name": "lib", "version": "1.0.0", "license": "MIT", "dependencies": []},
            {"name": "lib", "version": "2.0.0", "license": "GPL-3.0",
             "dependencies": []},
        ]
    }
    res = analyzer.analyze(data, policies.POLICIES["permissive"])
    assert res["roots"] == ["app@1"]
    gpl = next(p for p in res["packages"] if p["id"] == "lib@2.0.0")
    assert gpl["shortest_path"] == ["app@1", "lib@2.0.0"]


def test_unresolved_ref_recorded():
    data = {
        "packages": [
            {"name": "app", "version": "1", "license": "MIT",
             "dependencies": ["ghost@9.9.9"]},
        ]
    }
    res = analyzer.analyze(data, policies.POLICIES["permissive"])
    assert "ghost@9.9.9" in res["unresolved_refs"]


def test_cycle_does_not_hang():
    data = {
        "direct_dependencies": ["a"],
        "packages": [
            {"name": "a", "version": "1", "license": "MIT", "dependencies": ["b"]},
            {"name": "b", "version": "1", "license": "MIT", "dependencies": ["a"]},
        ]
    }
    res = analyzer.analyze(data, policies.POLICIES["permissive"])
    assert len(res["cycles"]) == 1
    assert set(res["cycles"][0]) == {"a@1", "b@1"}
    # 二者均可达（a 是根），路径长度有限
    for p in res["packages"]:
        assert p["shortest_path"]


def test_isolated_cycle_unreachable():
    data = {
        "packages": [
            {"name": "app", "version": "1", "license": "MIT", "dependencies": []},
            {"name": "x", "version": "1", "license": "MIT", "dependencies": ["y"]},
            {"name": "y", "version": "1", "license": "MIT", "dependencies": ["x"]},
        ]
    }
    res = analyzer.analyze(data, policies.POLICIES["permissive"])
    assert res["roots"] == ["app@1"]
    unreachable = [p for p in res["packages"] if not p["reachable"]]
    assert {p["id"] for p in unreachable} == {"x@1", "y@1"}


def test_exception_removes_conflict_and_recompute():
    data = {
        "packages": [
            {"name": "app", "version": "1", "license": "MIT", "dependencies": ["g"]},
            {"name": "g", "version": "1", "license": "GPL-3.0", "dependencies": []},
        ]
    }
    policy = policies.POLICIES["permissive"]
    before = analyzer.analyze(data, policy)
    assert before["summary"]["conflicts"] == 1

    after = analyzer.analyze(
        data, policy, exceptions={"g@1": {"note": "法务已批", "approved_at": "t"}}
    )
    g = next(p for p in after["packages"] if p["id"] == "g@1")
    assert g["verdict"] == "exception"
    assert g["exception"]["original_verdict"] == "deny"
    assert after["summary"]["conflicts"] == 0
    assert after["summary"]["exceptions"] == 1
    assert len(after["conflicts"]) == 0


def test_invalid_manifest_raises():
    import pytest

    with pytest.raises(analyzer.ManifestError):
        analyzer.analyze({"packages": []}, policies.POLICIES["permissive"])
    with pytest.raises(analyzer.ManifestError):
        analyzer.analyze({"packages": [{"version": "1", "license": "MIT"}]},
                         policies.POLICIES["permissive"])


def test_project_license_policy_mismatch():
    import pytest

    data = {
        "packages": [
            {"name": "app", "version": "1", "license": "MIT", "dependencies": []},
        ]
    }
    with pytest.raises(analyzer.ManifestError):
        analyzer.analyze(data, policies.POLICIES["strict"], "GPL-3.0")


def test_agpl_network_copyleft_policy():
    data = {
        "packages": [
            {"name": "app", "version": "1", "license": "MIT", "dependencies": ["a"]},
            {"name": "a", "version": "1", "license": "AGPL-3.0", "dependencies": []},
        ]
    }
    res = analyzer.analyze(data, policies.POLICIES["permissive"])
    a = next(p for p in res["packages"] if p["id"] == "a@1")
    assert a["verdict"] == "deny"


def test_example_manifest(tmp_path):
    path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "examples", "manifest.example.json",
    )
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    res = analyzer.analyze(data, policies.POLICIES["permissive"])
    by_id = {p["id"]: p for p in res["packages"]}
    # 加密原语 GPL-3.0 经 network内核 传递引入 → 冲突 + 最短路径
    gpl = by_id["加密原语@2.0.0"]
    assert gpl["verdict"] == "deny"
    assert gpl["shortest_path"][0] == "rpc工具包@5.0.0"
    assert gpl["shortest_path"][-1] == "加密原语@2.0.0"
    # json 工具 SPDX 表达式 (MIT OR Apache-2.0) → 选 MIT 兼容
    assert by_id["json工具@1.0.0"]["verdict"] == "allow"
    # 自定义许可证 → review
    assert by_id["内部工具@0.1.0"]["verdict"] == "review"
    # 未被任何包引用且无 direct_dependencies 指向 → 不可达，仍是 review
    assert by_id["内部工具@0.1.0"]["reachable"] is False
