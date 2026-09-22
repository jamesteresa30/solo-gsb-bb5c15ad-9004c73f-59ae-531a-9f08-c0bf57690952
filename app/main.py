"""FastAPI 入口：上传清单、查看分析结果、确认例外、导出 JSON。"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import __version__, analyzer, compare, licenses, policies
from .db import Database, now_iso

DB_PATH = os.environ.get("LICENSEGATE_DB", "/data/licensegate.db")
db = Database(DB_PATH)

app = FastAPI(
    title="LicenseGate",
    description="开源依赖许可审查：解析传递依赖图，按策略与兼容矩阵标出许可证冲突，"
    "给出最短依赖路径与触发规则，支持例外确认与 JSON 导出。",
    version=__version__,
)


# ---------------------------------------------------------------------------
# 请求模型
# ---------------------------------------------------------------------------


class AnalyzeRequest(BaseModel):
    manifest: dict = Field(..., description="依赖清单 JSON")
    policy_key: str = Field(default=policies.DEFAULT_POLICY)
    project_license: Optional[str] = Field(
        default=None, description="项目许可证，覆盖策略默认值/清单内 project_license"
    )


class ReanalyzeRequest(BaseModel):
    policy_key: Optional[str] = None
    project_license: Optional[str] = None


class ExceptionRequest(BaseModel):
    note: str = Field(default="", max_length=2000, description="例外理由 / 审批备注")
    distribution: str = Field(default="", description="多制品模式：确认例外所在的制品名称")


class CompareRequest(BaseModel):
    baseline_id: int = Field(..., description="基线（旧版本）项目 ID")
    current_id: int = Field(..., description="当前（新版本）项目 ID")


# ---------------------------------------------------------------------------
# 核心辅助
# ---------------------------------------------------------------------------


def _resolve_policy(key: Optional[str]) -> policies.Policy:
    if key is None or key == "":
        return policies.get_policy(policies.DEFAULT_POLICY)
    if key not in policies.POLICIES:
        raise HTTPException(status_code=400, detail=f"未知策略: {key}")
    return policies.POLICIES[key]


def _analyze_project(project_id: int, policy: policies.Policy,
                     project_license: Optional[str]) -> dict:
    project = db.get_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="项目不存在")
    exceptions = db.list_exceptions(project_id)
    # 多制品清单按各制品 project_license 判定，忽略统一覆盖（端点层会显式报错）
    if project["manifest"].get("distributions"):
        project_license = None
    try:
        result = analyzer.analyze(
            project["manifest"], policy, project_license, exceptions
        )
    except analyzer.ManifestError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    result["project_id"] = project_id
    result["stored_license"] = project["project_license"]
    return result


def _analyze_saved(project_id: int) -> tuple[dict, dict]:
    """按项目保存时的策略重算结果，同时返回项目行（供对比等功能复用）。"""
    project = db.get_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail=f"项目 {project_id} 不存在")
    policy = _resolve_policy(project["policy_key"])
    result = _analyze_project(project_id, policy, None)
    return project, result


def _parse_manifest_bytes(raw: bytes, filename: str) -> dict:
    if not raw.strip():
        raise HTTPException(status_code=400, detail="上传文件为空")
    try:
        data = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(
            status_code=400, detail=f"文件 {filename} 不是合法 JSON：{exc}"
        ) from exc
    if not isinstance(data, dict):
        raise HTTPException(status_code=400, detail="清单根节点必须是 JSON 对象")
    return data


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok", "version": __version__}


@app.get("/api/policies")
def get_policies() -> dict:
    return {"policies": policies.list_policies(), "default": policies.DEFAULT_POLICY}


@app.get("/api/licenses")
def get_licenses() -> dict:
    """返回许可证家族、项目许可证选项与完整兼容矩阵，便于前端展示规则来源。"""
    matrix: dict[str, dict[str, str]] = {}
    for proj, row in licenses.MATRIX.items():
        matrix[proj] = {dep: verdict for dep, (verdict, _note) in row.items()}
    return {
        "known_licenses": sorted(licenses.KNOWN_LICENSES),
        "families": licenses.LICENSE_FAMILY,
        "project_license_options": licenses.PROJECT_LICENSE_OPTIONS,
        "matrix": matrix,
    }


@app.post("/api/analyze")
def analyze_direct(req: AnalyzeRequest) -> dict:
    """不落库的即时分析（前端上传后预览用）。"""
    policy = _resolve_policy(req.policy_key)
    override = req.project_license or None
    try:
        return analyzer.analyze(req.manifest, policy, override, {})
    except analyzer.ManifestError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/projects")
async def create_project(
    file: UploadFile = File(..., description="依赖清单 JSON 文件"),
    policy_key: str = Form(default=policies.DEFAULT_POLICY),
    project_license: str = Form(default=""),
) -> dict:
    policy = _resolve_policy(policy_key)
    raw = await file.read()
    manifest = _parse_manifest_bytes(raw, file.filename or "manifest.json")

    # 多制品清单按各制品自己的 project_license 判定，不接受统一覆盖
    override = project_license.strip() or None
    if manifest.get("distributions") and override:
        raise HTTPException(
            status_code=400,
            detail="多制品清单（含 distributions）不支持统一覆盖项目许可证，"
                   "请在每个制品的 project_license 中分别指定",
        )
    try:
        preview = analyzer.analyze(manifest, policy, override, {})
    except analyzer.ManifestError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    chosen_license = preview["project_license"]
    project_id = db.create_project(
        name=preview["project"]["name"],
        project_version=preview["project"].get("version", ""),
        project_license=chosen_license,
        policy_key=policy.key,
        manifest=manifest,
    )
    return _analyze_project(project_id, policy, chosen_license)


@app.get("/api/projects")
def list_projects() -> dict:
    return {"projects": db.list_projects()}


@app.get("/api/projects/{project_id}")
def get_project(project_id: int, policy_key: Optional[str] = None,
                project_license: Optional[str] = None) -> dict:
    project = db.get_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="项目不存在")
    policy = _resolve_policy(policy_key or project["policy_key"])
    return _analyze_project(project_id, policy, project_license or None)


@app.post("/api/projects/{project_id}/reanalyze")
def reanalyze(project_id: int, req: ReanalyzeRequest) -> dict:
    project = db.get_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="项目不存在")
    if project["manifest"].get("distributions") and req.project_license:
        raise HTTPException(
            status_code=400,
            detail="多制品清单（含 distributions）不支持统一覆盖项目许可证",
        )
    policy = _resolve_policy(req.policy_key or project["policy_key"])
    license_choice = req.project_license or None
    return _analyze_project(project_id, policy, license_choice)


def _find_package_occurrence(result: dict, package_id: str,
                             distribution: Optional[str] = None) -> Optional[dict]:
    """在分析结果中定位某个包的结论记录；多制品模式定位到具体制品。"""
    if result.get("mode") == "multi":
        dists = result.get("distributions", [])
        if distribution:
            target_dists = [d for d in dists if d["name"] == distribution]
            if not target_dists:
                return None
        else:
            target_dists = dists
        for dist in target_dists:
            for pkg in dist.get("packages", []):
                if pkg["id"] == package_id:
                    return {**pkg, "_distribution": dist["name"]}
        return None
    for pkg in result.get("packages", []):
        if pkg["id"] == package_id:
            return pkg
    return None


@app.post("/api/projects/{project_id}/exceptions/{package_id:path}")
def add_exception(project_id: int, package_id: str, req: ExceptionRequest) -> dict:
    project = db.get_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="项目不存在")
    pkg_keys = {
        f"{p.get('name','')}@{p.get('version') or '0.0.0'}"
        for p in project["manifest"].get("packages", [])
        if isinstance(p, dict)
    }
    if package_id not in pkg_keys:
        raise HTTPException(status_code=404, detail=f"包 {package_id} 不在清单中")

    policy = _resolve_policy(project["policy_key"])
    current = _analyze_project(project_id, policy, None)
    dist_name = req.distribution or None
    if current.get("mode") == "multi" and not dist_name:
        raise HTTPException(
            status_code=400,
            detail="多制品清单确认例外必须指定 distribution（制品名称）",
        )
    occurrence = _find_package_occurrence(current, package_id, dist_name)
    if occurrence is None:
        if current.get("mode") == "multi":
            raise HTTPException(
                status_code=404,
                detail=f"包 {package_id} 在制品 {dist_name} 中不可达或不存在",
            )
        raise HTTPException(status_code=404, detail=f"包 {package_id} 不可达或不存在")
    if occurrence["base_verdict"] not in ("deny", "review"):
        raise HTTPException(
            status_code=400,
            detail=f"包 {package_id} 结论为 {occurrence['base_verdict']}，无需确认例外",
        )

    # 保存所选制品下的触发规则：仅覆盖同 package_id 且规则相同的制品结论
    db.add_exception(
        project_id,
        package_id,
        req.note.strip(),
        rule=occurrence["rule"],
        distribution=occurrence.get("_distribution", ""),
    )
    return _analyze_project(project_id, policy, None)


@app.delete("/api/projects/{project_id}/exceptions/{package_id:path}")
def revoke_exception(project_id: int, package_id: str,
                     distribution: Optional[str] = None,
                     rule: Optional[str] = None) -> dict:
    project = db.get_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="项目不存在")
    policy = _resolve_policy(project["policy_key"])
    current = _analyze_project(project_id, policy, None)

    if current.get("mode") == "multi":
        if not distribution:
            raise HTTPException(
                status_code=400, detail="多制品清单撤销例外需指定 distribution"
            )
        if not _find_package_occurrence(current, package_id, distribution):
            raise HTTPException(status_code=404, detail=f"包 {package_id} 在制品 {distribution} 中不可达")
        # 找到该制品下保存的规则例外（可能因切换策略而未在当前结果中生效）
        stored = [
            e for e in db.list_exceptions(project_id)
            if e["package_id"] == package_id and e["distribution"] == distribution
        ]
        if rule is not None:
            stored = [e for e in stored if e["rule"] == rule]
        if not stored:
            raise HTTPException(status_code=404, detail="该包在此制品下没有已确认的例外")
        removed = db.remove_exception(project_id, package_id, stored[0]["rule"])
    else:
        removed = db.remove_exception(project_id, package_id)
    if not removed:
        raise HTTPException(status_code=404, detail="该包没有已确认的例外")
    return _analyze_project(project_id, policy, None)


@app.delete("/api/projects/{project_id}")
def delete_project(project_id: int) -> dict:
    if not db.delete_project(project_id):
        raise HTTPException(status_code=404, detail="项目不存在")
    return {"deleted": project_id}


@app.get("/api/projects/{project_id}/export")
def export_project(project_id: int) -> JSONResponse:
    project = db.get_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="项目不存在")
    policy = _resolve_policy(project["policy_key"])
    result = _analyze_project(project_id, policy, None)
    multi = result.get("mode") == "multi"

    def package_row(p: dict) -> dict:
        return {
            "id": p["id"],
            "name": p["name"],
            "version": p["version"],
            "license": p["license_raw"],
            "license_canonical": p["license"],
            "family": p["family"],
            "direct": p.get("direct", False),
            "depth": p.get("depth"),
            "reachable": p.get("reachable", True),
            "verdict": p["verdict"],
            "base_verdict": p["base_verdict"],
            "rule": p.get("rule", ""),
            "rule_kind": p.get("rule_kind", ""),
            "message": p.get("message", ""),
            "shortest_path": p.get("shortest_path", []),
            "exception": p.get("exception"),
        }

    def conflict_row(c: dict) -> dict:
        return {
            "package": c["id"],
            "license": c["license_raw"],
            "severity": c["severity"],
            "rule": c["rule"],
            "message": c["message"],
            "shortest_path": c.get("shortest_path", []),
        }

    exceptions_rows = [
        {
            "package_id": info["package_id"],
            "note": info["note"],
            "rule": info.get("rule", ""),
            "distribution": info.get("distribution", ""),
            "approved_at": info["approved_at"],
        }
        for info in db.list_exceptions(project_id)
    ]

    export_payload = {
        "report_format": "licensegate-report/v1",
        "exported_at": now_iso(),
        "mode": "multi" if multi else "single",
        "project": {
            "id": project["id"],
            "name": project["name"],
            "version": project["project_version"],
            "license": project["project_license"],
        },
        "policy": {
            "key": policy.key,
            "name": policy.name,
        },
        "summary": result["overview"]["summary"] if multi else result["summary"],
        "packages": (
            [
                {
                    **package_row(p),
                    "affected": p.get("affected", []),
                }
                for p in result["overview"]["packages"]
            ]
            if multi
            else [package_row(p) for p in result["packages"]]
        ),
        "conflicts": (
            [
                {
                    **conflict_row(c),
                    "affected_distributions": [
                        {
                            "distribution": a["distribution"],
                            "verdict": a["verdict"],
                            "rule": a["rule"],
                            "shortest_path": a["shortest_path"],
                            "depth": a["depth"],
                        }
                        for a in c["affected"]
                        if a["verdict"] in ("deny", "review")
                    ],
                }
                for c in result["overview"]["conflicts"]
            ]
            if multi
            else [conflict_row(c) for c in result["conflicts"]]
        ),
        "exceptions": exceptions_rows,
        "cycles": result["cycles"],
        "unresolved_refs": result["unresolved_refs"],
        "manifest": project["manifest"],
    }

    if multi:
        export_payload["distributions"] = [
            {
                "name": dist["name"],
                "project_license": dist["project_license"],
                "roots": dist["roots"],
                "unresolved_roots": dist["unresolved_roots"],
                "summary": dist["summary"],
                "packages": [package_row(p) for p in dist["packages"]],
                "conflicts": [conflict_row(c) for c in dist["conflicts"]],
            }
            for dist in result["distributions"]
        ]
        export_payload["unreachable_packages"] = result.get("unreachable_packages", [])

    filename = f"license-report-{project_id}.json"
    return JSONResponse(
        content=export_payload,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Access-Control-Expose-Headers": "Content-Disposition",
        },
    )


# ---------------------------------------------------------------------------
# 审查版本对比
# ---------------------------------------------------------------------------


@app.post("/api/compare")
def compare_projects(req: CompareRequest) -> dict:
    """对比两个已保存项目（基线 vs 当前）的审查结果。

    按 ``name@version`` 对齐依赖，报告新增 / 移除、许可证或结论变化；
    多制品清单按同名制品分别对比，新增冲突给出当前制品、触发规则与最短路径。
    """
    if req.baseline_id == req.current_id:
        raise HTTPException(status_code=400, detail="基线项目与当前项目不能相同")
    base_project, base_result = _analyze_saved(req.baseline_id)
    cur_project, cur_result = _analyze_saved(req.current_id)
    try:
        payload = compare.compare_results(
            baseline=base_result,
            current=cur_result,
            baseline_id=req.baseline_id,
            current_id=req.current_id,
            baseline_project=base_project,
            current_project=cur_project,
        )
    except compare.CompareError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    payload["generated_at"] = now_iso()
    return payload


# ---------------------------------------------------------------------------
# 前端静态页（必须放在 API 路由之后挂载）
# ---------------------------------------------------------------------------

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"


@app.get("/")
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
