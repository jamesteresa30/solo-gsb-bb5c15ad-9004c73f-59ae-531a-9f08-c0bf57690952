"""审查版本对比 API（POST /api/compare）端到端测试。"""
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


BASE = {
    "project": {"name": "svc", "version": "1.0"},
    "direct_dependencies": ["app"],
    "packages": [
        {"name": "app", "version": "1", "license": "MIT",
         "dependencies": ["keep", "oldlib"]},
        {"name": "keep", "version": "1", "license": "MIT", "dependencies": []},
        {"name": "oldlib", "version": "1", "license": "GPL-3.0", "dependencies": []},
    ],
}

CURRENT = {
    "project": {"name": "svc", "version": "2.0"},
    "direct_dependencies": ["app"],
    "packages": [
        {"name": "app", "version": "1", "license": "MIT",
         "dependencies": ["keep", "newlib"]},
        {"name": "keep", "version": "1", "license": "MIT", "dependencies": []},
        {"name": "newlib", "version": "2", "license": "AGPL-3.0", "dependencies": []},
    ],
}


def compare_ids(bid, cid):
    return client.post("/api/compare", json={"baseline_id": bid, "current_id": cid})


def test_compare_happy_path_single():
    bid = upload(BASE)
    cid = upload(CURRENT)
    res = compare_ids(bid, cid)
    assert res.status_code == 200, res.text
    d = res.json()
    assert d["report_format"] == "licensegate-compare/v1"
    assert d["mode"] == "single"
    assert d["baseline"]["project_id"] == bid
    assert d["baseline"]["version"] == "1.0"
    assert d["current"]["project_id"] == cid
    assert d["current"]["version"] == "2.0"
    assert d["generated_at"]
    # 新增 newlib（AGPL-3.0 在 permissive 下 deny），移除 oldlib
    nc = next(x for x in d["new_conflicts"] if x["id"] == "newlib@2")
    assert nc["current_verdict"] == "deny"
    assert nc["current_rule"].startswith("POLICY_DENY:")
    assert nc["current_shortest_path"] == ["app@1", "newlib@2"]
    assert nc["distribution"] is None
    assert [x["id"] for x in d["added"]] == ["newlib@2"]
    assert [x["id"] for x in d["removed"]] == ["oldlib@1"]
    assert any(x["id"] == "oldlib@1" for x in d["resolved_conflicts"])


def test_compare_respects_saved_exceptions():
    bid = upload(BASE)
    # 基线唯一冲突 oldlib 已确认例外
    client.post(f"/api/projects/{bid}/exceptions/oldlib@1", json={"note": "批准"})
    cid = upload(CURRENT)
    d = compare_ids(bid, cid).json()
    # oldlib 在基线已是例外：移除时不计入“消除冲突”
    assert all(x["id"] != "oldlib@1" for x in d["resolved_conflicts"])
    # 但仍在移除依赖中
    assert [x["id"] for x in d["removed"]] == ["oldlib@1"]


def test_compare_rejects_same_project():
    bid = upload(BASE)
    res = compare_ids(bid, bid)
    assert res.status_code == 400


def test_compare_missing_project_404():
    bid = upload(BASE)
    assert compare_ids(bid, 999999).status_code == 404
    assert compare_ids(999999, bid).status_code == 404


def test_compare_mode_mismatch_400():
    bid = upload(BASE)
    multi = {
        "packages": [
            {"name": "a", "version": "1", "license": "MIT", "dependencies": []},
            {"name": "b", "version": "1", "license": "MIT", "dependencies": []},
        ],
        "distributions": [
            {"name": "d1", "project_license": "GPL-3.0", "direct_dependencies": ["a"]},
        ],
    }
    mid = upload(multi, policy="copyleft")
    res = compare_ids(bid, mid)
    assert res.status_code == 400
    assert "模式" in res.json()["detail"]


def test_compare_multi_per_distribution():
    base = {
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
    current = {
        "project": {"name": "mono", "version": "2"},
        "packages": [
            {"name": "core", "version": "1", "license": "MIT", "dependencies": ["gpl2", "ag"]},
            {"name": "clim", "version": "1", "license": "MIT", "dependencies": ["gpl2", "ag"]},
            {"name": "gpl2", "version": "1", "license": "GPL-2.0", "dependencies": []},
            {"name": "ag", "version": "1", "license": "AGPL-3.0", "dependencies": []},
        ],
        "distributions": [
            {"name": "sdk", "project_license": "GPL-3.0", "direct_dependencies": ["core"]},
            {"name": "cli", "project_license": "GPL-2.0", "direct_dependencies": ["clim"]},
        ],
    }
    bid = upload(base, policy="copyleft")
    cid = upload(current, policy="copyleft")
    d = compare_ids(bid, cid).json()
    assert d["mode"] == "multi"
    # AGPL-3.0：GPL-3.0 制品 allow（AGPL 与 GPL-3.0 兼容），GPL-2.0 制品 deny
    new = {(x["distribution"], x["id"]): x for x in d["new_conflicts"]}
    assert ("cli", "ag@1") in new
    assert ("sdk", "ag@1") not in new
    item = new[("cli", "ag@1")]
    assert item["current_rule"] == "MATRIX:GPL-2.0!AGPL-3.0"
    assert item["current_shortest_path"] == ["clim@1", "ag@1"]
    # 分制品 section 中 sdk 的新增 ag 是 allow
    sdk = next(s for s in d["distributions"] if s["name"] == "sdk")
    ag = next(r for r in sdk["added"] if r["id"] == "ag@1")
    assert ag["current_verdict"] == "allow"
