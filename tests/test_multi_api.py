"""多制品（distributions）端到端 API 测试（使用内存 SQLite）。"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ["LICENSEGATE_DB"] = ":memory:"

from fastapi.testclient import TestClient  # noqa: E402

from app import main  # noqa: E402

client = TestClient(main.app)

# GPL-2.0 依赖：在 GPL-3.0 制品下 review，在 GPL-2.0 制品下 allow
MANIFEST = {
    "project": {"name": "mono-api", "version": "2.0"},
    "packages": [
        {"name": "core", "version": "1", "license": "MIT", "dependencies": ["gpl2"]},
        {"name": "climain", "version": "1", "license": "MIT", "dependencies": ["gpl2"]},
        {"name": "gpl2", "version": "1", "license": "GPL-2.0", "dependencies": []},
        {"name": "orphan", "version": "1", "license": "GPL-3.0", "dependencies": []},
    ],
    "distributions": [
        {"name": "sdk", "project_license": "GPL-3.0", "direct_dependencies": ["core", "ghost@1"]},
        {"name": "cli", "project_license": "GPL-2.0", "direct_dependencies": ["climain"]},
    ],
}


def upload_multi(manifest=MANIFEST, policy="copyleft"):
    return client.post(
        "/api/projects",
        files={"file": ("m.json", json.dumps(manifest).encode(), "application/json")},
        data={"policy_key": policy},
    )


def test_upload_multi_result_shape():
    res = upload_multi()
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["mode"] == "multi"
    assert [d["name"] for d in data["distributions"]] == ["sdk", "cli"]
    sdk = data["distributions"][0]
    assert sdk["unresolved_roots"] == ["ghost@1"]
    assert "ghost@1" in data["unresolved_refs"]
    # sdk 下 gpl2 待审查，cli 下兼容
    g_sdk = next(p for p in sdk["packages"] if p["id"] == "gpl2@1")
    assert g_sdk["verdict"] == "review"
    cli = data["distributions"][1]
    assert next(p for p in cli["packages"] if p["id"] == "gpl2@1")["verdict"] == "allow"
    # 总览最严重为 review，且列出受影响制品
    g_ov = next(p for p in data["overview"]["packages"] if p["id"] == "gpl2@1")
    assert g_ov["verdict"] == "review"
    assert {a["distribution"] for a in g_ov["affected"]} == {"sdk", "cli"}
    assert data["unreachable_packages"] == ["orphan@1"]


def test_multi_invalid_manifest_rejected():
    bad = {"packages": MANIFEST["packages"], "distributions": []}
    res = upload_multi(bad)
    assert res.status_code == 400


def test_multi_exception_workflow_scoped_to_distribution():
    pid = upload_multi().json()["project_id"]

    # 未指定制品时，POST 400（无法定位具体制品）
    res = client.post(f"/api/projects/{pid}/exceptions/gpl2@1", json={"note": "x"})
    assert res.status_code == 400

    # 在 cli（allow）制品上确认例外应被拒绝（无冲突）
    res = client.post(
        f"/api/projects/{pid}/exceptions/gpl2@1",
        json={"note": "x", "distribution": "cli"},
    )
    assert res.status_code == 400

    # 在 sdk（review）制品上确认例外
    res = client.post(
        f"/api/projects/{pid}/exceptions/gpl2@1",
        json={"note": "已确认 GPL 升级路径", "distribution": "sdk"},
    )
    assert res.status_code == 200, res.text
    data = res.json()
    sdk = next(d for d in data["distributions"] if d["name"] == "sdk")
    cli = next(d for d in data["distributions"] if d["name"] == "cli")
    assert next(p for p in sdk["packages"] if p["id"] == "gpl2@1")["verdict"] == "exception"
    assert next(p for p in cli["packages"] if p["id"] == "gpl2@1")["verdict"] == "allow"
    assert sdk["summary"]["conflicts"] == 0
    # 总览不再有未处理冲突
    assert data["overview"]["summary"]["conflicts"] == 0

    # 不可达包不能确认例外
    res = client.post(
        f"/api/projects/{pid}/exceptions/orphan@1",
        json={"note": "x", "distribution": "sdk"},
    )
    assert res.status_code == 404

    # 撤销需要指定制品
    res = client.delete(f"/api/projects/{pid}/exceptions/gpl2@1")
    assert res.status_code == 400

    res = client.delete(
        f"/api/projects/{pid}/exceptions/gpl2@1?distribution=sdk"
    )
    assert res.status_code == 200
    data = res.json()
    sdk = next(d for d in data["distributions"] if d["name"] == "sdk")
    assert next(p for p in sdk["packages"] if p["id"] == "gpl2@1")["verdict"] == "review"
    assert data["overview"]["summary"]["conflicts"] == 1


def test_multi_exception_persists_on_reload():
    pid = upload_multi().json()["project_id"]
    client.post(
        f"/api/projects/{pid}/exceptions/gpl2@1",
        json={"note": "持久化", "distribution": "sdk"},
    )
    data = client.get(f"/api/projects/{pid}").json()
    sdk = next(d for d in data["distributions"] if d["name"] == "sdk")
    assert next(p for p in sdk["packages"] if p["id"] == "gpl2@1")["verdict"] == "exception"


def test_multi_reanalyze_same_policy_and_switch_rejected():
    pid = upload_multi().json()["project_id"]
    # 同策略重新计算：保持多制品结果
    res = client.post(
        f"/api/projects/{pid}/reanalyze",
        json={"policy_key": "copyleft"},
    )
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["mode"] == "multi"
    sdk = next(d for d in data["distributions"] if d["name"] == "sdk")
    assert next(p for p in sdk["packages"] if p["id"] == "gpl2@1")["verdict"] == "review"

    # 制品项目许可证（GPL 系）与 permissive 策略互斥 → 400
    res = client.post(
        f"/api/projects/{pid}/reanalyze",
        json={"policy_key": "permissive"},
    )
    assert res.status_code == 400

    # 多制品模式忽略/拒绝 project_license 统一覆盖
    res = client.post(
        f"/api/projects/{pid}/reanalyze",
        json={"policy_key": "copyleft", "project_license": "GPL-2.0"},
    )
    assert res.status_code == 400


def test_multi_export_payload():
    pid = upload_multi().json()["project_id"]
    client.post(
        f"/api/projects/{pid}/exceptions/gpl2@1",
        json={"note": "导出验证", "distribution": "sdk"},
    )
    res = client.get(f"/api/projects/{pid}/export")
    assert res.status_code == 200
    payload = res.json()
    assert payload["mode"] == "multi"
    assert {d["name"] for d in payload["distributions"]} == {"sdk", "cli"}
    # 分制品明细中保留独立路径
    sdk = next(d for d in payload["distributions"] if d["name"] == "sdk")
    g = next(p for p in sdk["packages"] if p["id"] == "gpl2@1")
    assert g["shortest_path"] == ["core@1", "gpl2@1"]
    # 总览顶层 packages 的受影响制品列表
    g_ov = next(p for p in payload["packages"] if p["id"] == "gpl2@1")
    assert {a["distribution"] for a in g_ov["affected"]} == {"sdk", "cli"}
    # 例外记录带规则与制品
    exc = payload["exceptions"][0]
    assert exc["package_id"] == "gpl2@1"
    assert exc["distribution"] == "sdk"
    assert exc["rule"].startswith("MATRIX:")
    assert payload["unreachable_packages"] == ["orphan@1"]
    assert payload["manifest"]["distributions"][0]["name"] == "sdk"


def test_same_rule_exception_covers_sibling_distribution():
    # 两个制品同为 GPL-3.0 项目许可证，GPL-2.0 依赖规则相同
    manifest = {
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
    pid = client.post(
        "/api/projects",
        files={"file": ("m.json", json.dumps(manifest).encode(), "application/json")},
        data={"policy_key": "copyleft"},
    ).json()["project_id"]
    res = client.post(
        f"/api/projects/{pid}/exceptions/g@1",
        json={"note": "同一规则覆盖两个制品", "distribution": "d1"},
    )
    assert res.status_code == 200, res.text
    data = res.json()
    for d in data["distributions"]:
        g = next(p for p in d["packages"] if p["id"] == "g@1")
        assert g["verdict"] == "exception", d["name"]
    # 撤销 d1 的保存记录后，两个制品的结论都恢复 review
    res = client.delete(f"/api/projects/{pid}/exceptions/g@1?distribution=d1")
    assert res.status_code == 200
    for d in res.json()["distributions"]:
        g = next(p for p in d["packages"] if p["id"] == "g@1")
        assert g["verdict"] == "review"


def test_legacy_single_manifest_still_works():
    single = {
        "direct_dependencies": ["app"],
        "packages": [
            {"name": "app", "version": "1", "license": "MIT", "dependencies": ["g"]},
            {"name": "g", "version": "1", "license": "GPL-3.0", "dependencies": []},
        ],
    }
    res = client.post(
        "/api/projects",
        files={"file": ("s.json", json.dumps(single).encode(), "application/json")},
        data={"policy_key": "permissive"},
    )
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["mode"] == "single"
    assert data["summary"]["deny"] == 1
    assert "distributions" not in data

    # 旧的例外 API（不带 distribution）行为不变
    pid = data["project_id"]
    res = client.post(f"/api/projects/{pid}/exceptions/g@1", json={"note": "ok"})
    assert res.status_code == 200
    assert res.json()["summary"]["conflicts"] == 0
    res = client.delete(f"/api/projects/{pid}/exceptions/g@1")
    assert res.status_code == 200
    assert res.json()["summary"]["conflicts"] == 1
