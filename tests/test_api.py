"""FastAPI 端到端测试（使用内存 SQLite）。"""
import io
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# 必须在导入 app.main 之前指向内存库
os.environ["LICENSEGATE_DB"] = ":memory:"

from fastapi.testclient import TestClient  # noqa: E402

from app import main  # noqa: E402

client = TestClient(main.app)

MANIFEST = {
    "project": {"name": "api-demo", "version": "1.0"},
    "direct_dependencies": ["app"],
    "packages": [
        {"name": "app", "version": "1", "license": "MIT",
         "dependencies": ["gpl-lib", "apache-lib"]},
        {"name": "gpl-lib", "version": "2", "license": "GPL-3.0", "dependencies": []},
        {"name": "apache-lib", "version": "3", "license": "Apache-2.0",
         "dependencies": []},
    ],
}


def upload(manifest=MANIFEST, policy="permissive", project_license=""):
    return client.post(
        "/api/projects",
        files={"file": ("m.json", json.dumps(manifest).encode(), "application/json")},
        data={"policy_key": policy, "project_license": project_license},
    )


def test_health_and_meta():
    assert client.get("/api/health").json()["status"] == "ok"
    policies = client.get("/api/policies").json()
    assert {p["key"] for p in policies["policies"]} == {
        "permissive", "copyleft", "strict", "proprietary"
    }
    licenses = client.get("/api/licenses").json()
    assert licenses["matrix"]["MIT"]["GPL-3.0"] == "deny"
    assert licenses["matrix"]["MIT"]["MIT"] == "allow"


def test_index_served():
    res = client.get("/")
    assert res.status_code == 200
    assert "LicenseGate" in res.text


def test_upload_and_conflicts():
    res = upload()
    assert res.status_code == 200, res.text
    data = res.json()
    pid = data["project_id"]
    assert data["summary"]["deny"] == 1
    gpl = next(p for p in data["conflicts"] if p["name"] == "gpl-lib")
    assert gpl["verdict"] == "deny"
    assert gpl["shortest_path"] == ["app@1", "gpl-lib@2"]
    assert gpl["message"]
    assert gpl["rule"]
    assert pid


def test_upload_bad_json():
    res = client.post(
        "/api/projects",
        files={"file": ("m.json", b"{not json", "application/json")},
        data={"policy_key": "permissive"},
    )
    assert res.status_code == 400


def test_direct_analyze_endpoint():
    res = client.post("/api/analyze", json={"manifest": MANIFEST, "policy_key": "strict"})
    assert res.status_code == 200
    # strict 下 Apache-2.0 仍允许，GPL deny
    verdicts = {p["id"]: p["verdict"] for p in res.json()["packages"]}
    assert verdicts["gpl-lib@2"] == "deny"
    assert verdicts["apache-lib@3"] == "allow"


def test_exception_workflow_and_recompute():
    pid = upload().json()["project_id"]

    # 确认例外
    res = client.post(
        f"/api/projects/{pid}/exceptions/gpl-lib@2",
        json={"note": "仅内部分发，法务批准"},
    )
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["summary"]["conflicts"] == 0
    gpl = next(p for p in data["packages"] if p["id"] == "gpl-lib@2")
    assert gpl["verdict"] == "exception"
    assert gpl["exception"]["note"] == "仅内部分发，法务批准"
    assert gpl["exception"]["original_verdict"] == "deny"
    # 冲突列表里不再出现
    assert all(p["id"] != "gpl-lib@2" for p in data["conflicts"])

    # GET 结果持久化
    got = client.get(f"/api/projects/{pid}").json()
    assert next(p for p in got["packages"] if p["id"] == "gpl-lib@2")["verdict"] == "exception"

    # 撤销例外，冲突恢复
    res = client.delete(f"/api/projects/{pid}/exceptions/gpl-lib@2")
    assert res.status_code == 200
    assert res.json()["summary"]["conflicts"] == 1

    # 不存在的包
    res = client.post(f"/api/projects/{pid}/exceptions/nope@9", json={"note": "x"})
    assert res.status_code == 404


def test_reanalyze_with_policy_switch():
    pid = upload().json()["project_id"]
    # 切换到 copyleft + GPL-3.0 项目许可证：GPL-3.0 依赖兼容
    res = client.post(
        f"/api/projects/{pid}/reanalyze",
        json={"policy_key": "copyleft", "project_license": "GPL-3.0"},
    )
    assert res.status_code == 200
    verdicts = {p["id"]: p["verdict"] for p in res.json()["packages"]}
    assert verdicts["gpl-lib@2"] == "allow"


def test_policy_license_mismatch_rejected():
    # permissive 策略只允许 MIT/Apache 作为项目许可证
    res = upload(project_license="GPL-3.0")
    assert res.status_code == 400


def test_export_payload():
    pid = upload().json()["project_id"]
    client.post(f"/api/projects/{pid}/exceptions/gpl-lib@2", json={"note": "ok"})
    res = client.get(f"/api/projects/{pid}/export")
    assert res.status_code == 200
    assert "attachment" in res.headers["content-disposition"]
    payload = res.json()
    assert payload["report_format"] == "licensegate-report/v1"
    assert payload["project"]["license"] == "MIT"
    assert len(payload["conflicts"]) == 0  # 唯一冲突已例外
    assert payload["exceptions"][0]["package_id"] == "gpl-lib@2"
    conflict_ex = next(p for p in payload["packages"] if p["id"] == "gpl-lib@2")
    assert conflict_ex["verdict"] == "exception"
    assert conflict_ex["shortest_path"] == ["app@1", "gpl-lib@2"]
    assert payload["manifest"]["packages"][0]["name"] == "app"


def test_project_crud():
    pid = upload().json()["project_id"]
    assert client.get("/api/projects").status_code == 200
    assert client.get(f"/api/projects/{pid}").status_code == 200
    assert client.get("/api/projects/99999").status_code == 404
    assert client.delete(f"/api/projects/{pid}").status_code == 200
    assert client.get(f"/api/projects/{pid}").status_code == 404
