"""依赖裁剪模拟 API（POST /api/projects/{id}/trial）端到端测试。"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ["LICENSEGATE_DB"] = ":memory:"

from fastapi.testclient import TestClient  # noqa: E402

from app import main  # noqa: E402

client = TestClient(main.app)


def upload(manifest, policy="permissive"):
    res = client.post(
        "/api/projects",
        files={"file": ("m.json", json.dumps(manifest).encode(), "application/json")},
        data={"policy_key": policy},
    )
    assert res.status_code == 200, res.text
    return res.json()["project_id"]


MANIFEST = {
    "project": {"name": "svc", "version": "1.0"},
    "direct_dependencies": ["app"],
    "packages": [
        {"name": "app", "version": "1", "license": "MIT",
         "dependencies": ["gpl-a", "gpl-b"]},
        {"name": "gpl-a", "version": "1", "license": "GPL-3.0",
         "dependencies": ["leaf"]},
        {"name": "gpl-b", "version": "1", "license": "AGPL-3.0",
         "dependencies": ["leaf"]},
        {"name": "leaf", "version": "1", "license": "MIT", "dependencies": []},
    ],
}


def trial(pid, edges):
    return client.post(f"/api/projects/{pid}/trial", json={"edges": edges})


def test_trial_resolves_and_remaining_conflicts():
    pid = upload(MANIFEST)
    res = trial(pid, [
        {"from": "app@1", "to": "gpl-a@1"},
        {"from": "app@1", "to": "gpl-b@1"},
    ])
    assert res.status_code == 200, res.text
    d = res.json()
    assert d["report_format"] == "licensegate-trial/v1"
    assert d["project_id"] == pid
    assert d["read_only"] is True
    assert d["generated_at"]
    assert len(d["removed_edges"]) == 2
    assert d["mode"] == "single"
    scope = d["scopes"][0]
    assert scope["name"] is None
    assert {r["id"] for r in scope["resolved_conflicts"]} == {"gpl-a@1", "gpl-b@1"}
    assert scope["remaining_conflicts"] == []
    # leaf 失去两条来源路径，不再纳入审查（非冲突包）
    dropped = {r["id"] for r in scope["dropped_packages"]}
    assert dropped == {"gpl-a@1", "gpl-b@1", "leaf@1"}
    assert scope["summary"]["trimmed_reachable"] == 1  # 仅 app
    # 给出变化前最短路径
    ga = next(r for r in scope["resolved_conflicts"] if r["id"] == "gpl-a@1")
    assert ga["baseline_shortest_path"] == ["app@1", "gpl-a@1"]


def test_trial_alternative_path_keeps_conflict():
    # gpl 同时被 a、b 引用：只删一条边不会误报消除
    manifest = {
        "project": {"name": "alt", "version": "1"},
        "direct_dependencies": ["app"],
        "packages": [
            {"name": "app", "version": "1", "license": "MIT", "dependencies": ["a", "b"]},
            {"name": "a", "version": "1", "license": "MIT", "dependencies": ["gpl"]},
            {"name": "b", "version": "1", "license": "MIT", "dependencies": ["gpl"]},
            {"name": "gpl", "version": "1", "license": "GPL-3.0", "dependencies": []},
        ],
    }
    pid = upload(manifest)
    d = trial(pid, [{"from": "a@1", "to": "gpl@1"}]).json()
    scope = d["scopes"][0]
    assert [r["id"] for r in scope["remaining_conflicts"]] == ["gpl@1"]
    assert scope["resolved_conflicts"] == []
    row = scope["remaining_conflicts"][0]
    assert row["baseline_shortest_path"] == ["app@1", "a@1", "gpl@1"]
    assert row["trimmed_shortest_path"] == ["app@1", "b@1", "gpl@1"]
    assert row["path_changed"] is True


def test_trial_rejects_nonexistent_edge():
    pid = upload(MANIFEST)
    res = trial(pid, [{"from": "app@1", "to": "leaf@1"}])  # app 不直接依赖 leaf
    assert res.status_code == 400
    assert "不存在" in res.json()["detail"]

    res = trial(pid, [{"from": "nope@1", "to": "leaf@1"}])
    assert res.status_code == 400

    res = client.post(f"/api/projects/{pid}/trial", json={"edges": []})
    assert res.status_code == 422


def test_trial_missing_project_404():
    res = trial(999999, [{"from": "app@1", "to": "gpl-a@1"}])
    assert res.status_code == 404


def test_trial_is_read_only():
    pid = upload(MANIFEST)
    before = client.get(f"/api/projects/{pid}").json()
    trial(pid, [{"from": "app@1", "to": "gpl-a@1"}])
    after = client.get(f"/api/projects/{pid}").json()
    # 试算后重新查询：结果与清单完全不变
    assert after["summary"] == before["summary"]
    assert after["edges"] == before["edges"]
    assert [p["id"] for p in after["conflicts"]] == [p["id"] for p in before["conflicts"]]
    # 不产生例外记录
    export = client.get(f"/api/projects/{pid}/export").json()
    assert export["exceptions"] == []


def test_trial_respects_saved_exceptions():
    pid = upload(MANIFEST)
    client.post(f"/api/projects/{pid}/exceptions/gpl-a@1", json={"note": "批准"})
    d = trial(pid, [{"from": "app@1", "to": "gpl-a@1"}]).json()
    scope = d["scopes"][0]
    # gpl-a 基线已是例外，不计入"被消除冲突"
    assert all(r["id"] != "gpl-a@1" for r in scope["resolved_conflicts"])
    assert any(r["id"] == "gpl-a@1" for r in scope["dropped_packages"])
    # gpl-b 不受影响，仍是剩余冲突
    assert [r["id"] for r in scope["remaining_conflicts"]] == ["gpl-b@1"]


def test_trial_multi_distribution():
    manifest = {
        "project": {"name": "mono", "version": "1"},
        "packages": [
            {"name": "sdk-main", "version": "1", "license": "MIT",
             "dependencies": ["gpl2"]},
            {"name": "cli-main", "version": "1", "license": "MIT",
             "dependencies": ["gpl2"]},
            {"name": "gpl2", "version": "1", "license": "GPL-2.0", "dependencies": []},
        ],
        "distributions": [
            {"name": "sdk", "project_license": "GPL-3.0",
             "direct_dependencies": ["sdk-main"]},
            {"name": "cli", "project_license": "GPL-2.0",
             "direct_dependencies": ["cli-main"]},
        ],
    }
    pid = upload(manifest, policy="copyleft")
    d = trial(pid, [{"from": "sdk-main@1", "to": "gpl2@1"}]).json()
    assert d["mode"] == "multi"
    sdk = next(s for s in d["scopes"] if s["name"] == "sdk")
    cli = next(s for s in d["scopes"] if s["name"] == "cli")
    assert [r["id"] for r in sdk["resolved_conflicts"]] == ["gpl2@1"]
    assert sdk["resolved_conflicts"][0]["baseline_rule"] == "MATRIX:GPL-3.0~GPL-2.0"
    assert cli["summary"]["dropped_packages"] == 0
    assert cli["summary"]["remaining_conflicts"] == 0
    assert d["summary"]["resolved_conflicts"] == 1
    assert d["unreachable_packages"] == []
