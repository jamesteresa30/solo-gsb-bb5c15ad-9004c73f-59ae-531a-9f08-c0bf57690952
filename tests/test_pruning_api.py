"""依赖裁剪试算（pruning-sim）端到端 API 测试（使用内存 SQLite）。"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ["LICENSEGATE_DB"] = ":memory:"

from fastapi.testclient import TestClient  # noqa: E402

from app import main  # noqa: E402

client = TestClient(main.app)


def upload(manifest, policy="permissive"):
    return client.post(
        "/api/projects",
        files={"file": ("m.json", json.dumps(manifest).encode(), "application/json")},
        data={"policy_key": policy},
    )


# ---------------------------------------------------------------------------
# 单制品
# ---------------------------------------------------------------------------

# app → mid → gpl；app → safe → gpl（gpl 有两条路径）；另 app → ok
MANIFEST_TWO_PATHS = {
    "direct_dependencies": ["app"],
    "packages": [
        {"name": "app", "version": "1", "license": "MIT",
         "dependencies": ["mid", "safe", "ok"]},
        {"name": "mid", "version": "1", "license": "MIT", "dependencies": ["gpl"]},
        {"name": "safe", "version": "1", "license": "MIT", "dependencies": ["gpl"]},
        {"name": "gpl", "version": "1", "license": "GPL-3.0", "dependencies": []},
        {"name": "ok", "version": "1", "license": "MIT", "dependencies": []},
    ],
}


def sim(pid, edges):
    return client.post(
        f"/api/projects/{pid}/pruning-sim", json={"edges": edges}
    )


def test_single_alternative_path_not_falsely_eliminated():
    pid = upload(MANIFEST_TWO_PATHS).json()["project_id"]
    # 只裁 mid→gpl：gpl 仍可经 safe 到达 → 不得报消除，只报路径变化
    res = sim(pid, [{"from": "mid@1", "to": "gpl@1"}])
    assert res.status_code == 200, res.text
    d = res.json()
    assert d["report_format"] == "licensegate-pruning/v1"
    assert d["mode"] == "single"
    assert d["read_only"] is True
    assert d["removed_edges"] == [{"from": "mid@1", "to": "gpl@1"}]
    assert d["summary"]["eliminated_conflicts"] == 0
    assert d["summary"]["remaining_conflicts"] == 1
    assert d["summary"]["dropped_packages"] == 0

    sc = d["scopes"][0]
    assert sc["name"] is None
    rem = sc["remaining_conflicts"][0]
    assert rem["id"] == "gpl@1"
    assert rem["verdict"] == "deny"
    assert rem["before_shortest_path"] == ["app@1", "mid@1", "gpl@1"]
    assert rem["after_shortest_path"] == ["app@1", "safe@1", "gpl@1"]
    changed = [r for r in sc["changed_paths"] if r["id"] == "gpl@1"]
    assert len(changed) == 1

    # 试算结果内附带的模拟结果：gpl 仍可达
    sim_pkgs = {p["id"]: p for p in d["simulated"]["packages"]}
    assert sim_pkgs["gpl@1"]["reachable"] is True
    assert sim_pkgs["gpl@1"]["verdict"] == "deny"


def test_single_cut_all_paths_eliminates_conflict():
    pid = upload(MANIFEST_TWO_PATHS).json()["project_id"]
    res = sim(pid, [
        {"from": "mid@1", "to": "gpl@1"},
        {"from": "safe@1", "to": "gpl@1"},
    ])
    assert res.status_code == 200, res.text
    d = res.json()
    assert d["summary"]["eliminated_conflicts"] == 1
    assert d["summary"]["remaining_conflicts"] == 0
    assert d["summary"]["dropped_packages"] == 1
    assert d["newly_unreachable_packages"] == ["gpl@1"]

    sc = d["scopes"][0]
    item = sc["eliminated_conflicts"][0]
    assert item["id"] == "gpl@1"
    assert item["verdict"] == "deny"
    assert item["before_shortest_path"] == ["app@1", "mid@1", "gpl@1"]
    assert item["after_shortest_path"] == []
    assert item["after_depth"] is None
    assert sc["dropped_packages"][0]["id"] == "gpl@1"
    # 模拟结果中 gpl 不可达（单制品 summary 仍按既有行为统计不可达包，
    # 试算报告自身的 scope summary 以可达为准，冲突为 0）
    assert sc["summary"]["conflicts_after"] == 0
    sim_gpl = next(p for p in d["simulated"]["packages"] if p["id"] == "gpl@1")
    assert sim_gpl["reachable"] is False

    # 基线结果不受影响：原项目仍是 1 个冲突
    got = client.get(f"/api/projects/{pid}").json()
    assert got["summary"]["conflicts"] == 1
    # 原始清单未被改写
    manifest = main.db.get_project(pid)["manifest"]
    mid = next(p for p in manifest["packages"] if p["name"] == "mid")
    assert "gpl" in mid["dependencies"]


def test_simulation_does_not_touch_exceptions():
    pid = upload(MANIFEST_TWO_PATHS).json()["project_id"]
    # 先确认一个例外，再试算：例外必须原样保留
    client.post(f"/api/projects/{pid}/exceptions/gpl@1", json={"note": "已审批"})
    res = sim(pid, [{"from": "mid@1", "to": "gpl@1"}])
    assert res.status_code == 200
    d = res.json()
    # gpl 仍可达但已是例外，因此不进"仍存在冲突"
    assert d["summary"]["remaining_conflicts"] == 0
    excs = main.db.list_exceptions(pid)
    assert len(excs) == 1 and excs[0]["note"] == "已审批"
    # 原结果依旧是例外状态
    got = client.get(f"/api/projects/{pid}").json()
    gpl = next(p for p in got["packages"] if p["id"] == "gpl@1")
    assert gpl["verdict"] == "exception"


def test_nonexistent_edges_rejected():
    pid = upload(MANIFEST_TWO_PATHS).json()["project_id"]
    # 反向边不存在
    res = sim(pid, [{"from": "gpl@1", "to": "mid@1"}])
    assert res.status_code == 400
    assert "不存在" in res.json()["detail"]
    # 包不存在
    res = sim(pid, [{"from": "mid@1", "to": "ghost@9"}])
    assert res.status_code == 400
    # 缺少字段
    res = client.post(
        f"/api/projects/{pid}/pruning-sim", json={"edges": [{"from": "mid@1"}]}
    )
    assert res.status_code == 422
    # 重复边
    res = sim(pid, [
        {"from": "mid@1", "to": "gpl@1"},
        {"from": "mid@1", "to": "gpl@1"},
    ])
    assert res.status_code == 400


def test_empty_edges_is_neutral_trial():
    pid = upload(MANIFEST_TWO_PATHS).json()["project_id"]
    res = sim(pid, [])
    assert res.status_code == 200
    d = res.json()
    assert d["summary"]["edges_removed"] == 0
    assert d["summary"]["eliminated_conflicts"] == 0
    assert d["summary"]["remaining_conflicts"] == 1
    assert d["simulated"]["summary"] == d["baseline"]["summary"]


def test_pruning_project_not_found():
    res = client.post("/api/projects/99999/pruning-sim", json={"edges": []})
    assert res.status_code == 404


def test_implicit_roots_are_frozen_when_edge_removed():
    # 未声明 direct_dependencies：app 是唯一入度 0 的根；
    # 裁掉 app→mid 后 mid 不应因入度变为 0 而"晋升"为新根。
    manifest = {
        "packages": [
            {"name": "app", "version": "1", "license": "MIT", "dependencies": ["mid"]},
            {"name": "mid", "version": "1", "license": "MIT", "dependencies": ["gpl"]},
            {"name": "gpl", "version": "1", "license": "GPL-3.0", "dependencies": []},
        ],
    }
    pid = upload(manifest).json()["project_id"]
    res = sim(pid, [{"from": "app@1", "to": "mid@1"}])
    assert res.status_code == 200, res.text
    d = res.json()
    assert d["simulated"]["roots"] == ["app@1"]
    assert d["summary"]["eliminated_conflicts"] == 1
    assert sorted(d["newly_unreachable_packages"]) == ["gpl@1", "mid@1"]


def test_explicit_roots_resolve_merged_duplicate_package_refs():
    # 合并包：两个同名同版本声明合并依赖边；裁剪须从合并后的引用中移除
    manifest = {
        "direct_dependencies": ["app"],
        "packages": [
            {"name": "app", "version": "1", "license": "MIT", "dependencies": ["gpl"]},
            {"name": "app", "version": "1", "license": "MIT", "dependencies": []},
            {"name": "gpl", "version": "1", "license": "GPL-3.0", "dependencies": []},
        ],
    }
    pid = upload(manifest).json()["project_id"]
    res = sim(pid, [{"from": "app@1", "to": "gpl@1"}])
    assert res.status_code == 200, res.text
    d = res.json()
    assert d["summary"]["eliminated_conflicts"] == 1
    # 模拟图中 app→gpl 边已不存在
    assert d["simulated"]["edges"] == []


# ---------------------------------------------------------------------------
# 多制品
# ---------------------------------------------------------------------------

MULTI_MANIFEST = {
    "packages": [
        {"name": "core", "version": "1", "license": "MIT", "dependencies": ["gpl2"]},
        {"name": "climain", "version": "1", "license": "MIT", "dependencies": ["gpl2"]},
        {"name": "gpl2", "version": "1", "license": "GPL-2.0", "dependencies": []},
        {"name": "orphan", "version": "1", "license": "GPL-3.0", "dependencies": []},
    ],
    "distributions": [
        {"name": "sdk", "project_license": "GPL-3.0", "direct_dependencies": ["core"]},
        {"name": "cli", "project_license": "GPL-2.0", "direct_dependencies": ["climain"]},
    ],
}


def test_multi_pruning_per_distribution():
    pid = upload(MULTI_MANIFEST, policy="copyleft").json()["project_id"]
    # 只裁 sdk 的 core→gpl2：sdk 冲突消除，cli 不受影响
    res = sim(pid, [{"from": "core@1", "to": "gpl2@1"}])
    assert res.status_code == 200, res.text
    d = res.json()
    assert d["mode"] == "multi"
    assert [s["name"] for s in d["scopes"]] == ["sdk", "cli"]
    sdk, cli = d["scopes"]
    assert sdk["summary"]["eliminated_conflicts"] == 1
    assert sdk["summary"]["conflicts_before"] == 1
    assert sdk["summary"]["conflicts_after"] == 0
    assert sdk["dropped_packages"][0]["id"] == "gpl2@1"
    assert sdk["eliminated_conflicts"][0]["distribution"] == "sdk"
    assert sdk["eliminated_conflicts"][0]["before_shortest_path"] == [
        "core@1", "gpl2@1"
    ]
    # cli 下 gpl2 本就 allow，依旧可达，无消除/丢弃
    assert cli["summary"]["eliminated_conflicts"] == 0
    assert cli["summary"]["dropped_packages"] == 0
    # gpl2 仍被 cli 触达：图级别不算不可达
    assert d["newly_unreachable_packages"] == []
    # 总览变化：review → allow
    chg = next(c for c in d["overview"]["changes"] if c["id"] == "gpl2@1")
    assert chg["before_verdict"] == "review"
    assert chg["after_verdict"] == "allow"
    assert set(chg["reachable_distributions_after"]) == {"cli"}

    # 模拟结果仍是多制品，sdk 下 gpl2 不在包列表
    sim_sdk = next(x for x in d["simulated"]["distributions"] if x["name"] == "sdk")
    assert all(p["id"] != "gpl2@1" for p in sim_sdk["packages"])
    sim_cli = next(x for x in d["simulated"]["distributions"] if x["name"] == "cli")
    assert any(p["id"] == "gpl2@1" for p in sim_cli["packages"])
    # 原本就不可达的 orphan 仍在 unreachable 列表
    assert "orphan@1" in d["simulated"]["unreachable_packages"]


def test_multi_cut_all_distribution_paths():
    pid = upload(MULTI_MANIFEST, policy="copyleft").json()["project_id"]
    res = sim(pid, [
        {"from": "core@1", "to": "gpl2@1"},
        {"from": "climain@1", "to": "gpl2@1"},
    ])
    assert res.status_code == 200
    d = res.json()
    assert d["newly_unreachable_packages"] == ["gpl2@1"]
    # sdk 消除 1 条 review 冲突；cli 下 gpl2 仅进入 dropped（原本 allow）
    sdk, cli = d["scopes"]
    assert sdk["summary"]["eliminated_conflicts"] == 1
    assert cli["summary"]["eliminated_conflicts"] == 0
    assert cli["summary"]["dropped_packages"] == 1
    ov = next(c for c in d["overview"]["changes"] if c["id"] == "gpl2@1")
    assert ov["after_verdict"] == "unreachable"
