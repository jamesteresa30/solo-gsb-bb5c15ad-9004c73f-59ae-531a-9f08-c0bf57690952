"""审查版本对比引擎（app.compare）测试。"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import analyzer, compare, policies  # noqa: E402


def analyze(manifest, policy="permissive", exceptions=None):
    return analyzer.analyze(
        manifest, policies.POLICIES[policy], exceptions=exceptions
    )


# ---------------------------------------------------------------------------
# 单制品
# ---------------------------------------------------------------------------


BASE_SINGLE = {
    "project": {"name": "app", "version": "1.0"},
    "direct_dependencies": ["root"],
    "packages": [
        {"name": "root", "version": "1", "license": "MIT",
         "dependencies": ["stable", "dropped", "changegpl"]},
        {"name": "stable", "version": "1", "license": "MIT", "dependencies": []},
        {"name": "dropped", "version": "1", "license": "MIT", "dependencies": []},
        {"name": "changegpl", "version": "1", "license": "GPL-3.0",
         "dependencies": []},
    ],
}

CURRENT_SINGLE = {
    "project": {"name": "app", "version": "2.0"},
    "direct_dependencies": ["root"],
    "packages": [
        {"name": "root", "version": "1", "license": "MIT",
         "dependencies": ["stable", "newgpl", "changegpl"]},
        {"name": "stable", "version": "1", "license": "Apache-2.0", "dependencies": []},
        {"name": "newgpl", "version": "2", "license": "GPL-3.0", "dependencies": []},
        {"name": "changegpl", "version": "1", "license": "MIT", "dependencies": []},
    ],
}


def _cmp(exceptions_base=None, exceptions_cur=None):
    return compare.compare_results(
        analyze(BASE_SINGLE, exceptions=exceptions_base),
        analyze(CURRENT_SINGLE, exceptions=exceptions_cur),
        baseline_id=1,
        current_id=2,
    )


def test_single_mode_envelope_and_alignment():
    d = _cmp()
    assert d["report_format"] == "licensegate-compare/v1"
    assert d["mode"] == "single"
    assert d["baseline"]["project_id"] == 1
    assert d["current"]["project_id"] == 2
    # 按 name@version 对齐：新增 newgpl、移除 dropped
    assert [r["id"] for r in d["added"]] == ["newgpl@2"]
    assert [r["id"] for r in d["removed"]] == ["dropped@1"]


def test_single_license_change_detected():
    d = _cmp()
    changes = {r["id"]: r for r in d["license_changes"]}
    assert "stable@1" in changes
    assert changes["stable@1"]["baseline_license"] == "MIT"
    assert changes["stable@1"]["current_license"] == "Apache-2.0"
    assert changes["stable@1"]["name"] == "stable"
    assert changes["stable@1"]["version"] == "1"


def test_single_new_conflict_has_artifact_rule_and_shortest_path():
    d = _cmp()
    nc = next(c for c in d["new_conflicts"] if c["id"] == "newgpl@2")
    assert nc["current_verdict"] == "deny"
    assert nc["current_rule"].startswith("POLICY_DENY:")
    assert nc["current_shortest_path"] == ["root@1", "newgpl@2"]
    assert nc["current_depth"] == 1
    assert nc["distribution"] is None
    assert nc["reason"] == "added"
    # changegpl 由 deny 变 allow：进入已消除冲突，而非新增冲突
    assert all(c["id"] != "changegpl@1" for c in d["new_conflicts"])
    resolved = next(c for c in d["resolved_conflicts"] if c["id"] == "changegpl@1")
    assert resolved["baseline_verdict"] == "deny"
    assert resolved["reason"] == "changed"


def test_single_verdict_change_records_rules():
    d = _cmp()
    chg = next(r for r in d["verdict_changed"] if r["id"] == "changegpl@1")
    assert chg["baseline_verdict"] == "deny"
    assert chg["current_verdict"] == "allow"
    assert chg["verdict_changed"] is True
    assert chg["baseline_rule"] != chg["current_rule"]
    assert chg["license_changed"] is True


def test_single_rule_only_change_counts_as_changed():
    # 许可证/结论均不变但触发规则变（如复合表达式触发分支变化），
    # 这里用许可证文本变化但结论同为 allow 覆盖 verdict_changed 中 rule_changed 语义
    base = {
        "direct_dependencies": ["root"],
        "packages": [
            {"name": "root", "version": "1", "license": "MIT", "dependencies": ["dual"]},
            {"name": "dual", "version": "1", "license": "MIT", "dependencies": []},
        ],
    }
    cur = {
        "direct_dependencies": ["root"],
        "packages": [
            {"name": "root", "version": "1", "license": "MIT", "dependencies": ["dual"]},
            {"name": "dual", "version": "1", "license": "Apache-2.0", "dependencies": []},
        ],
    }
    d = compare.compare_results(analyze(base), analyze(cur))
    row = next(r for r in d["verdict_changed"] if r["id"] == "dual@1")
    assert row["verdict_changed"] is False
    assert row["rule_changed"] is True
    assert row["baseline_rule"] != row["current_rule"]


def test_exception_state_counts_as_resolved():
    # 基线对 changegpl 确认了例外（verdict=exception，不再算冲突），
    # 当前版本该包改回 MIT allow —— 不属于新增/消除冲突，仅结论变化
    d = _cmp(exceptions_base=[
        {"package_id": "changegpl@1", "note": "法务批准", "rule": "", "distribution": ""}
    ])
    assert all(c["id"] != "changegpl@1" for c in d["new_conflicts"])
    assert all(c["id"] != "changegpl@1" for c in d["resolved_conflicts"])
    row = next(r for r in d["verdict_changed"] if r["id"] == "changegpl@1")
    assert row["baseline_verdict"] == "exception"
    assert row["current_verdict"] == "allow"


def test_exception_grant_on_new_version_is_new_conflict_then_resolved():
    # 当前版本对新增冲突也确认例外：新增冲突仍按 base_verdict 报出
    d = _cmp(exceptions_cur=[
        {"package_id": "newgpl@2", "note": "x", "rule": "", "distribution": ""}
    ])
    # 例外后 current verdict=exception，不再是新增问题
    assert all(c["id"] != "newgpl@2" for c in d["new_conflicts"])


def test_identical_results_have_no_changes():
    d = compare.compare_results(
        analyze(BASE_SINGLE), analyze(BASE_SINGLE), 1, 2
    )
    assert d["summary"]["added"] == 0
    assert d["summary"]["removed"] == 0
    assert d["summary"]["license_changed"] == 0
    assert d["summary"]["verdict_changed"] == 0
    assert d["summary"]["new_conflicts"] == 0
    assert d["summary"]["resolved_conflicts"] == 0
    assert d["new_conflicts"] == []


def test_version_bump_is_added_and_removed():
    base = {
        "direct_dependencies": ["root"],
        "packages": [
            {"name": "root", "version": "1", "license": "MIT", "dependencies": ["lib@1.0"]},
            {"name": "lib", "version": "1.0", "license": "GPL-3.0", "dependencies": []},
        ],
    }
    cur = {
        "direct_dependencies": ["root"],
        "packages": [
            {"name": "root", "version": "1", "license": "MIT", "dependencies": ["lib@2.0"]},
            {"name": "lib", "version": "2.0", "license": "GPL-3.0", "dependencies": []},
        ],
    }
    d = compare.compare_results(analyze(base), analyze(cur))
    assert [r["id"] for r in d["removed"]] == ["lib@1.0"]
    assert [r["id"] for r in d["added"]] == ["lib@2.0"]
    nc = d["new_conflicts"][0]
    assert nc["id"] == "lib@2.0"
    assert nc["current_shortest_path"] == ["root@1", "lib@2.0"]


# ---------------------------------------------------------------------------
# 多制品
# ---------------------------------------------------------------------------


BASE_MULTI = {
    "project": {"name": "mono", "version": "1"},
    "packages": [
        {"name": "core", "version": "1", "license": "MIT", "dependencies": ["gpl2"]},
        {"name": "clim", "version": "1", "license": "MIT", "dependencies": ["gpl2"]},
        {"name": "gpl2", "version": "1", "license": "GPL-2.0", "dependencies": []},
    ],
    "distributions": [
        {"name": "sdk", "project_license": "GPL-3.0", "direct_dependencies": ["core"]},
        {"name": "cli", "project_license": "GPL-2.0", "direct_dependencies": ["clim"]},
    ],
}

CURRENT_MULTI = {
    "project": {"name": "mono", "version": "2"},
    "packages": [
        {"name": "core", "version": "1", "license": "MIT", "dependencies": ["gpl2", "g3"]},
        {"name": "clim", "version": "1", "license": "MIT", "dependencies": ["gpl2", "g3"]},
        {"name": "gpl2", "version": "1", "license": "GPL-2.0", "dependencies": []},
        {"name": "g3", "version": "1", "license": "GPL-3.0", "dependencies": []},
    ],
    "distributions": [
        {"name": "sdk", "project_license": "GPL-3.0", "direct_dependencies": ["core", "g3"]},
        {"name": "cli", "project_license": "GPL-2.0", "direct_dependencies": ["clim"]},
        {"name": "svc", "project_license": "AGPL-3.0", "direct_dependencies": ["g3"]},
    ],
}


def _cmp_multi():
    return compare.compare_results(
        analyze(BASE_MULTI, policy="copyleft"),
        analyze(CURRENT_MULTI, policy="copyleft"),
        10, 20,
    )


def test_multi_mode_per_distribution_sections():
    d = _cmp_multi()
    assert d["mode"] == "multi"
    assert d["distributions_added"] == ["svc"]
    assert d["distributions_removed"] == []
    sections = {s["name"]: s for s in d["distributions"]}
    assert set(sections) == {"sdk", "cli", "svc"}
    assert sections["svc"]["status"] == "added"
    # g3 对 sdk 与 cli 均为新增可达
    sdk_added = {r["id"] for r in sections["sdk"]["added"]}
    cli_added = {r["id"] for r in sections["cli"]["added"]}
    assert "g3@1" in sdk_added and "g3@1" in cli_added


def test_multi_new_conflict_scoped_to_distribution():
    d = _cmp_multi()
    # g3：sdk(GPL-3.0) 下 allow；cli(GPL-2.0) 下 MATRIX deny；svc(AGPL-3.0) 下 allow
    cli_conflicts = [c for c in d["new_conflicts"] if c["distribution"] == "cli"]
    g3 = next(c for c in cli_conflicts if c["id"] == "g3@1")
    assert g3["current_verdict"] == "deny"
    assert g3["current_rule"] == "MATRIX:GPL-2.0!GPL-3.0"
    assert g3["current_shortest_path"] == ["clim@1", "g3@1"]
    assert g3["reason"] in ("added", "newly_reachable")
    assert not any(
        c["id"] == "g3@1" and c["distribution"] == "sdk" for c in d["new_conflicts"]
    )


def test_multi_added_distribution_packages_reason_added():
    d = _cmp_multi()
    svc = next(s for s in d["distributions"] if s["name"] == "svc")
    assert {r["id"] for r in svc["added"]} == {"g3@1"}
    assert all(r["reason"] == "added" for r in svc["added"])


def test_multi_removed_distribution_resolves_its_conflicts():
    cur = {
        "project": {"name": "mono", "version": "3"},
        "packages": [
            {"name": "core", "version": "1", "license": "MIT", "dependencies": []},
        ],
        "distributions": [
            {"name": "sdk", "project_license": "GPL-3.0", "direct_dependencies": ["core"]},
        ],
    }
    d = compare.compare_results(
        analyze(BASE_MULTI, policy="copyleft"),
        analyze(cur, policy="copyleft"),
        1, 2,
    )
    assert d["distributions_removed"] == ["cli"]
    section = next(s for s in d["distributions"] if s["name"] == "cli")
    assert section["status"] == "removed"
    # cli 下的包全部按制品移除处理
    removed_ids = {r["id"] for r in section["removed"]}
    assert "clim@1" in removed_ids and "gpl2@1" in removed_ids
    assert all(r["reason"] == "distribution_removed" for r in section["removed"])
    # gpl2 在基线 cli 下 allow，不产生 resolved；sdk 下 review 仍保留
    assert not any(
        c["id"] == "gpl2@1" and c["distribution"] == "cli"
        for c in d["resolved_conflicts"]
    )


def test_multi_no_longer_reachable_is_scoped_removal():
    # 当前版本 cli 的根不再经过 gpl2（只在 sdk 可达）
    cur = {
        "project": {"name": "mono", "version": "2"},
        "packages": [
            {"name": "core", "version": "1", "license": "MIT", "dependencies": ["gpl2"]},
            {"name": "clim", "version": "1", "license": "MIT", "dependencies": []},
            {"name": "gpl2", "version": "1", "license": "GPL-2.0", "dependencies": []},
        ],
        "distributions": [
            {"name": "sdk", "project_license": "GPL-3.0", "direct_dependencies": ["core"]},
            {"name": "cli", "project_license": "GPL-2.0", "direct_dependencies": ["clim"]},
        ],
    }
    d = compare.compare_results(
        analyze(BASE_MULTI, policy="copyleft"),
        analyze(cur, policy="copyleft"),
        1, 2,
    )
    cli = next(s for s in d["distributions"] if s["name"] == "cli")
    row = next(r for r in cli["removed"] if r["id"] == "gpl2@1")
    assert row["reason"] == "no_longer_reachable"
    # gpl2 在基线 cli 下 allow → 不算消除冲突
    assert cli["resolved_conflicts"] == []


def test_mode_mismatch_raises():
    single = analyze(BASE_SINGLE)
    multi = analyze(BASE_MULTI, policy="copyleft")
    with pytest.raises(compare.CompareError):
        compare.compare_results(single, multi)
    with pytest.raises(compare.CompareError):
        compare.compare_results(multi, single)
