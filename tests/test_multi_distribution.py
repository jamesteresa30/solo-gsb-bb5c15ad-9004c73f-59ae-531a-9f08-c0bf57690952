"""多制品（distributions）审查测试：分析引擎层。"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import analyzer, policies  # noqa: E402


MULTI = {
    "project": {"name": "monorepo", "version": "1.0"},
    "packages": [
        # sdk 根：gpl3 经 core 可达；shared 不可达
        {"name": "core", "version": "1", "license": "MIT", "dependencies": ["gpl3"]},
        # cli 根：gpl3 与 mpl 可达
        {"name": "climain", "version": "1", "license": "MIT",
         "dependencies": ["gpl3", "mpl"]},
        {"name": "gpl3", "version": "1", "license": "GPL-2.0", "dependencies": []},
        {"name": "mpl", "version": "1", "license": "MPL-2.0", "dependencies": []},
        {"name": "orphan", "version": "1", "license": "GPL-3.0", "dependencies": []},
    ],
    "distributions": [
        # GPL-3.0 制品：GPL-2.0 only 依赖矩阵 review
        {"name": "sdk", "project_license": "GPL-3.0", "direct_dependencies": ["core"]},
        # GPL-2.0 制品：GPL-2.0 自身兼容
        {"name": "cli", "project_license": "GPL-2.0",
         "direct_dependencies": ["climain", "ghost@9"]},
    ],
}


def analyze(exceptions=None, policy="copyleft"):
    return analyzer.analyze(
        MULTI, policies.POLICIES[policy], exceptions=exceptions
    )


def test_multi_mode_envelope():
    res = analyze()
    assert res["mode"] == "multi"
    names = [d["name"] for d in res["distributions"]]
    assert names == ["sdk", "cli"]
    assert res["overview"]["distribution_names"] == ["sdk", "cli"]


def test_per_distribution_license_and_reachability():
    res = analyze()
    sdk = next(d for d in res["distributions"] if d["name"] == "sdk")
    cli = next(d for d in res["distributions"] if d["name"] == "cli")

    assert sdk["project_license"] == "GPL-3.0"
    assert cli["project_license"] == "GPL-2.0"
    assert sdk["roots"] == ["core@1"]
    assert cli["roots"] == ["climain@1"]

    # 只统计该制品可达的包
    assert {p["id"] for p in sdk["packages"]} == {"core@1", "gpl3@1"}
    assert {p["id"] for p in cli["packages"]} == {"climain@1", "gpl3@1", "mpl@1"}

    # 各自独立的路径与结论
    gpl_sdk = next(p for p in sdk["packages"] if p["id"] == "gpl3@1")
    gpl_cli = next(p for p in cli["packages"] if p["id"] == "gpl3@1")
    assert gpl_sdk["shortest_path"] == ["core@1", "gpl3@1"]
    assert gpl_cli["shortest_path"] == ["climain@1", "gpl3@1"]
    assert gpl_sdk["verdict"] == "review"
    assert gpl_cli["verdict"] == "allow"
    assert gpl_sdk["rule"] != gpl_cli["rule"]


def test_dangling_root_located_to_distribution():
    res = analyze()
    cli = next(d for d in res["distributions"] if d["name"] == "cli")
    assert cli["unresolved_roots"] == ["ghost@9"]
    assert "ghost@9" in res["unresolved_refs"]
    sdk = next(d for d in res["distributions"] if d["name"] == "sdk")
    assert sdk["unresolved_roots"] == []


def test_unreachable_packages_listed():
    res = analyze()
    assert res["unreachable_packages"] == ["orphan@1"]
    # 总览中不可达包单列
    unr = [p for p in res["overview"]["packages"] if p["verdict"] == "unreachable"]
    assert [p["id"] for p in unr] == ["orphan@1"]
    assert res["overview"]["summary"]["unreachable"] == 1


def test_overview_aggregates_worst_and_lists_affected():
    res = analyze()
    ov = res["overview"]
    gpl = next(p for p in ov["packages"] if p["id"] == "gpl3@1")
    # 最严重结论：sdk review > cli allow
    assert gpl["verdict"] == "review"
    assert {a["distribution"]: a["verdict"] for a in gpl["affected"]} == {
        "sdk": "review", "cli": "allow"
    }
    # 每个受影响制品保留独立路径与规则
    aff_sdk = next(a for a in gpl["affected"] if a["distribution"] == "sdk")
    aff_cli = next(a for a in gpl["affected"] if a["distribution"] == "cli")
    assert aff_sdk["shortest_path"] == ["core@1", "gpl3@1"]
    assert aff_cli["shortest_path"] == ["climain@1", "gpl3@1"]
    assert aff_sdk["rule"] != aff_cli["rule"]

    # mpl 只被 cli 可达
    mpl = next(p for p in ov["packages"] if p["id"] == "mpl@1")
    assert [a["distribution"] for a in mpl["affected"]] == ["cli"]

    # 总览摘要按最严重结论计数
    assert ov["summary"]["review"] == 1
    assert ov["summary"]["conflicts"] == 1
    assert [p["id"] for p in ov["conflicts"]] == ["gpl3@1"]


def test_distribution_summary_counts_only_reachable():
    res = analyze()
    sdk = next(d for d in res["distributions"] if d["name"] == "sdk")
    cli = next(d for d in res["distributions"] if d["name"] == "cli")
    assert sdk["summary"]["total"] == 2
    assert sdk["summary"]["review"] == 1
    assert cli["summary"]["total"] == 3
    assert cli["summary"]["conflicts"] == 0


def test_exception_scoped_by_package_and_rule():
    res = analyze()
    sdk = next(d for d in res["distributions"] if d["name"] == "sdk")
    rule_sdk = next(p for p in sdk["packages"] if p["id"] == "gpl3@1")["rule"]

    # 仅保存 sdk 下的触发规则
    res2 = analyze(exceptions=[{
        "package_id": "gpl3@1", "note": "法务批准", "approved_at": "t",
        "rule": rule_sdk, "distribution": "sdk",
    }])
    sdk2 = next(d for d in res2["distributions"] if d["name"] == "sdk")
    cli2 = next(d for d in res2["distributions"] if d["name"] == "cli")
    g_sdk = next(p for p in sdk2["packages"] if p["id"] == "gpl3@1")
    g_cli = next(p for p in cli2["packages"] if p["id"] == "gpl3@1")
    assert g_sdk["verdict"] == "exception"
    assert g_sdk["exception"]["rule"] == rule_sdk
    assert g_sdk["exception"]["distribution"] == "sdk"
    # cli 的同包结论规则不同，不被覆盖
    assert g_cli["verdict"] == "allow"
    assert sdk2["summary"]["exceptions"] == 1
    assert cli2["summary"]["exceptions"] == 0

    # 规则不匹配的例外记录不生效
    res3 = analyze(exceptions=[{
        "package_id": "gpl3@1", "note": "x", "approved_at": "t",
        "rule": "MATRIX:GPL-3.0!GPL-2.0", "distribution": "sdk",
    }])
    sdk3 = next(d for d in res3["distributions"] if d["name"] == "sdk")
    assert next(p for p in sdk3["packages"] if p["id"] == "gpl3@1")["verdict"] == "review"


def test_same_rule_exception_covers_all_matching_distributions():
    # 两个制品项目许可证相同、规则相同：一条例外同时覆盖
    data = {
        "packages": [
            {"name": "a", "version": "1", "license": "MIT", "dependencies": ["g"]},
            {"name": "b", "version": "1", "license": "MIT", "dependencies": ["g"]},
            {"name": "g", "version": "1", "license": "GPL-2.0", "dependencies": []},
        ],
        "distributions": [
            {"name": "d1", "project_license": "GPL-3.0", "direct_dependencies": ["a"]},
            {"name": "d2", "project_license": "GPL-3.0", "direct_dependencies": ["b"]},
        ],
    }
    res = analyzer.analyze(data, policies.POLICIES["copyleft"])
    rule = next(
        p for p in res["distributions"][0]["packages"] if p["id"] == "g@1"
    )["rule"]
    res2 = analyzer.analyze(
        data, policies.POLICIES["copyleft"],
        exceptions=[{"package_id": "g@1", "rule": rule, "note": "ok",
                     "approved_at": "t", "distribution": "d1"}],
    )
    for d in res2["distributions"]:
        g = next(p for p in d["packages"] if p["id"] == "g@1")
        assert g["verdict"] == "exception"


def test_invalid_distributions():
    base_pkgs = MULTI["packages"]
    cases = [
        ({"packages": base_pkgs, "distributions": []}, "非空数组"),
        ({"packages": base_pkgs, "distributions": "nope"}, "非空数组"),
        ({"packages": base_pkgs, "distributions": [
            {"name": "a", "direct_dependencies": ["core"]},
            {"name": "a", "direct_dependencies": ["core"]},
        ]}, "重复"),
        ({"packages": base_pkgs, "distributions": [
            {"name": "a"}
        ]}, "direct_dependencies"),
        ({"packages": base_pkgs, "distributions": [
            {"name": "a", "direct_dependencies": []}
        ]}, "direct_dependencies"),
        ({"packages": base_pkgs, "distributions": [
            {"name": "a", "direct_dependencies": ["core"], "project_license": "Not-A-License"}
        ]}, "无法识别"),
    ]
    for manifest, frag in cases:
        with pytest.raises(analyzer.ManifestError) as ei:
            analyzer.analyze(manifest, policies.POLICIES["copyleft"])
        assert frag in str(ei.value)


def test_distribution_license_policy_mismatch():
    data = {
        "packages": MULTI["packages"],
        "distributions": [
            {"name": "a", "project_license": "MIT", "direct_dependencies": ["core"]},
        ],
    }
    with pytest.raises(analyzer.ManifestError) as ei:
        analyzer.analyze(data, policies.POLICIES["copyleft"])
    assert "策略" in str(ei.value)


def test_multi_rejects_unified_license_override():
    with pytest.raises(analyzer.ManifestError) as ei:
        analyzer.analyze(MULTI, policies.POLICIES["copyleft"],
                         license_override="GPL-3.0")
    assert "不支持统一覆盖" in str(ei.value)


def test_distribution_defaults_to_top_level_project_license():
    data = {
        "project_license": "GPL-3.0",
        "packages": [
            {"name": "a", "version": "1", "license": "MIT", "dependencies": ["g"]},
            {"name": "g", "version": "1", "license": "GPL-2.0", "dependencies": []},
        ],
        "distributions": [
            {"name": "d", "direct_dependencies": ["a"]},
        ],
    }
    res = analyzer.analyze(data, policies.POLICIES["copyleft"])
    assert res["distributions"][0]["project_license"] == "GPL-3.0"


def test_legacy_dict_exceptions_still_work_single_mode():
    # 旧形态字典例外在单制品模式下照常生效
    data = {
        "packages": [
            {"name": "app", "version": "1", "license": "MIT", "dependencies": ["g"]},
            {"name": "g", "version": "1", "license": "GPL-3.0", "dependencies": []},
        ]
    }
    res = analyzer.analyze(
        data, policies.POLICIES["permissive"],
        exceptions={"g@1": {"note": "旧格式", "approved_at": "t"}},
    )
    assert res["mode"] == "single"
    assert next(p for p in res["packages"] if p["id"] == "g@1")["verdict"] == "exception"


def test_single_manifest_without_distributions_unchanged():
    res = analyzer.analyze(
        {"packages": [
            {"name": "app", "version": "1", "license": "MIT", "dependencies": []}]},
        policies.POLICIES["permissive"],
    )
    assert res["mode"] == "single"
    assert "distributions" not in res
    assert "overview" not in res
    assert res["roots"] == ["app@1"]
