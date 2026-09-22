"""依赖裁剪模拟（只读试算）引擎测试：app.trial.simulate。"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import analyzer, policies, trial


def simulate(manifest, edges, policy="permissive", exceptions=None):
    pol = policies.get_policy(policy)
    baseline = analyzer.analyze(manifest, pol, None, exceptions or {})
    return trial.simulate(manifest, pol, baseline, exceptions or {}, edges)


# app -> a -> gpl(冲突)，app -> b -> gpl（同一冲突包有两条路径）
MULTI_PATH = {
    "project": {"name": "multi-path", "version": "1"},
    "direct_dependencies": ["app"],
    "packages": [
        {"name": "app", "version": "1", "license": "MIT", "dependencies": ["a", "b"]},
        {"name": "a", "version": "1", "license": "MIT", "dependencies": ["gpl"]},
        {"name": "b", "version": "1", "license": "MIT", "dependencies": ["gpl", "fine"]},
        {"name": "gpl", "version": "1", "license": "GPL-3.0", "dependencies": []},
        {"name": "fine", "version": "1", "license": "MIT", "dependencies": []},
    ],
}


def test_conflict_with_alternative_path_not_falsely_resolved():
    # 只删 a -> gpl：gpl 仍可经 app -> b -> gpl 到达，不得报为已消除
    d = simulate(MULTI_PATH, [{"from": "a@1", "to": "gpl@1"}])
    assert d["report_format"] == "licensegate-trial/v1"
    assert d["mode"] == "single"
    assert d["read_only"] is True
    scope = d["scopes"][0]
    assert [r["id"] for r in scope["resolved_conflicts"]] == []
    assert [r["id"] for r in scope["dropped_packages"]] == []
    remaining = scope["remaining_conflicts"]
    assert len(remaining) == 1
    row = remaining[0]
    assert row["id"] == "gpl@1"
    assert row["verdict"] == "deny"
    assert row["baseline_shortest_path"] == ["app@1", "a@1", "gpl@1"]
    # 改走另一条路径
    assert row["trimmed_shortest_path"] == ["app@1", "b@1", "gpl@1"]
    assert row["path_changed"] is True
    assert d["summary"]["resolved_conflicts"] == 0
    assert d["summary"]["remaining_conflicts"] == 1


def test_remove_all_paths_resolves_conflict_and_drops_chain():
    # 删掉两条进入 gpl 的边：冲突消除，gpl 不再纳入审查
    d = simulate(MULTI_PATH, [
        {"from": "a@1", "to": "gpl@1"},
        {"from": "b@1", "to": "gpl@1"},
    ])
    scope = d["scopes"][0]
    assert scope["remaining_conflicts"] == []
    resolved = scope["resolved_conflicts"]
    assert [r["id"] for r in resolved] == ["gpl@1"]
    assert resolved[0]["baseline_shortest_path"] == ["app@1", "a@1", "gpl@1"]
    assert resolved[0]["baseline_verdict"] == "deny"
    assert [r["id"] for r in scope["dropped_packages"]] == ["gpl@1"]
    assert scope["summary"]["trimmed_reachable"] == 4  # app/a/b/fine
    assert scope["summary"]["baseline_reachable"] == 5


def test_chain_removal_drops_downstream_allow_packages():
    # app -> bad(冲突) -> util(兼容)；删 app -> bad 后 bad、util 一并失达
    manifest = {
        "project": {"name": "chain", "version": "1"},
        "direct_dependencies": ["app"],
        "packages": [
            {"name": "app", "version": "1", "license": "MIT", "dependencies": ["bad"]},
            {"name": "bad", "version": "1", "license": "GPL-3.0", "dependencies": ["util"]},
            {"name": "util", "version": "1", "license": "MIT", "dependencies": []},
        ],
    }
    d = simulate(manifest, [{"from": "app@1", "to": "bad@1"}])
    scope = d["scopes"][0]
    dropped = {r["id"]: r for r in scope["dropped_packages"]}
    assert set(dropped) == {"bad@1", "util@1"}
    assert dropped["bad@1"]["was_conflict"] is True
    assert dropped["util@1"]["was_conflict"] is False
    assert [r["id"] for r in scope["resolved_conflicts"]] == ["bad@1"]


def test_shortest_path_rerouted_for_still_reachable_packages():
    # app -> x -> leaf 较短；删 x -> leaf 后 leaf 改走 app -> y -> z -> leaf
    manifest = {
        "project": {"name": "reroute", "version": "1"},
        "direct_dependencies": ["app"],
        "packages": [
            {"name": "app", "version": "1", "license": "MIT", "dependencies": ["x", "y"]},
            {"name": "x", "version": "1", "license": "MIT", "dependencies": ["leaf"]},
            {"name": "y", "version": "1", "license": "MIT", "dependencies": ["z"]},
            {"name": "z", "version": "1", "license": "MIT", "dependencies": ["leaf"]},
            {"name": "leaf", "version": "1", "license": "MIT", "dependencies": []},
        ],
    }
    d = simulate(manifest, [{"from": "x@1", "to": "leaf@1"}])
    scope = d["scopes"][0]
    changed = {r["id"]: r for r in scope["path_changed"]}
    assert "leaf@1" in changed
    assert changed["leaf@1"]["baseline_shortest_path"] == ["app@1", "x@1", "leaf@1"]
    assert changed["leaf@1"]["trimmed_shortest_path"] == ["app@1", "y@1", "z@1", "leaf@1"]


def test_roots_stay_fixed_when_indegree_becomes_zero():
    # 显式根 app 即使在裁剪后入度变化（此处无影响），根集合仍固定；
    # 更关键：未声明 direct_dependencies 时，裁剪也不会让某个包"变成根"
    manifest = {
        "project": {"name": "roots", "version": "1"},
        "packages": [
            {"name": "app", "version": "1", "license": "MIT", "dependencies": ["gpl"]},
            {"name": "gpl", "version": "1", "license": "GPL-3.0", "dependencies": []},
        ],
    }
    # 无 direct_dependencies：入度为 0 的 app 是根
    d = simulate(manifest, [{"from": "app@1", "to": "gpl@1"}])
    scope = d["scopes"][0]
    assert scope["roots"] == ["app@1"]
    assert [r["id"] for r in scope["resolved_conflicts"]] == ["gpl@1"]
    # gpl 入度为 0 也不应在试算后被当作根重新纳入
    assert scope["summary"]["trimmed_reachable"] == 1


def test_invalid_edge_rejected():
    import pytest
    with pytest.raises(trial.TrialError):
        simulate(MULTI_PATH, [{"from": "a@1", "to": "ghost@9"}])
    with pytest.raises(trial.TrialError):
        simulate(MULTI_PATH, [])
    with pytest.raises(trial.TrialError):
        simulate(MULTI_PATH, [{"from": "ghost@1", "to": "gpl@1"}])


def test_duplicate_edges_deduped():
    d = simulate(MULTI_PATH, [
        {"from": "a@1", "to": "gpl@1"},
        {"from": "a@1", "to": "gpl@1"},
    ])
    assert d["removed_edges"] == [{"from": "a@1", "to": "gpl@1"}]


def test_exceptioned_conflict_excluded_from_baseline_conflicts():
    # gpl 已确认例外：裁掉后不计入"被消除的冲突"，但仍在 dropped_packages
    d = simulate(
        MULTI_PATH,
        [{"from": "a@1", "to": "gpl@1"}, {"from": "b@1", "to": "gpl@1"}],
        exceptions=[{"package_id": "gpl@1", "note": "已批准", "approved_at": "t",
                     "rule": "POLICY_DENY:strong_copyleft", "distribution": ""}],
    )
    scope = d["scopes"][0]
    assert scope["summary"]["baseline_conflicts"] == 0
    assert scope["resolved_conflicts"] == []
    assert {r["id"] for r in scope["dropped_packages"]} == {"gpl@1"}


MULTI_MANIFEST = {
    "project": {"name": "mono", "version": "1"},
    "packages": [
        {"name": "sdk-main", "version": "1", "license": "MIT", "dependencies": ["shared-gpl"]},
        {"name": "cli-main", "version": "1", "license": "MIT", "dependencies": ["shared-gpl"]},
        {"name": "shared-gpl", "version": "1", "license": "GPL-2.0", "dependencies": []},
        {"name": "sdk-only", "version": "1", "license": "GPL-3.0", "dependencies": []},
    ],
    "distributions": [
        {"name": "sdk", "project_license": "GPL-3.0", "direct_dependencies": ["sdk-main", "sdk-only"]},
        {"name": "cli", "project_license": "GPL-2.0", "direct_dependencies": ["cli-main"]},
    ],
}


def test_multi_mode_per_distribution_roots():
    # sdk（GPL-3.0 项目）下 shared-gpl(GPL-2.0) 冲突；cli（GPL-2.0）下兼容
    d = simulate(MULTI_MANIFEST, [{"from": "sdk-main@1", "to": "shared-gpl@1"}],
                 policy="copyleft")
    assert d["mode"] == "multi"
    by_name = {s["name"]: s for s in d["scopes"]}
    sdk, cli = by_name["sdk"], by_name["cli"]
    assert [r["id"] for r in sdk["resolved_conflicts"]] == ["shared-gpl@1"]
    assert sdk["resolved_conflicts"][0]["baseline_shortest_path"] == [
        "sdk-main@1", "shared-gpl@1"
    ]
    assert sdk["summary"]["baseline_conflicts"] == 1
    # cli 不经过 sdk-main -> shared-gpl 这条边，结果不变
    assert cli["summary"]["dropped_packages"] == 0
    assert cli["summary"]["baseline_conflicts"] == 0
    # sdk-only 仍可达
    assert sdk["summary"]["trimmed_reachable"] == 2
    assert d["summary"]["resolved_conflicts"] == 1
    assert d["summary"]["remaining_conflicts"] == 0
