"""审查版本对比：对齐两个已保存项目的分析结果。

按 ``name@version`` 对齐基线（baseline）与当前（current）两份审查结果，
报告：

* **新增 / 移除**的依赖；
* **许可证变化**（同一 ``name@version`` 的声明许可证改变）；
* **结论或触发规则变化**（按制品分别统计，多制品清单逐制品对比）；
* **新增冲突**：当前新出现的 deny/review，给出当前制品、触发规则、当前最短路径；
* **已消除冲突**。

单制品结果（``mode == "single"``）只有一个隐式作用域（制品名 ``None``）；
多制品结果按同名制品对齐，制品本身也会作为新增 / 移除报告。
两个项目模式不同（一单制品、一多制品）时拒绝对比。
"""
from __future__ import annotations

from typing import Dict, List, Optional

#: 结论严重度（deny > review > exception > allow > unreachable）
_VERDICT_ORDER = {"deny": 0, "review": 1, "exception": 2, "allow": 3}
PROBLEM_VERDICTS = ("deny", "review")


class CompareError(ValueError):
    """两份结果无法对比（模式不一致等）。"""


# ---------------------------------------------------------------------------
# 数据投影
# ---------------------------------------------------------------------------


def _occurrence(pkg: dict, scope: Optional[str]) -> dict:
    """从一条包结论中抽取对比所需字段。"""
    return {
        "id": pkg["id"],
        "name": pkg["name"],
        "version": pkg["version"],
        "license_raw": pkg.get("license_raw", ""),
        "license": pkg.get("license", ""),
        "verdict": pkg["verdict"],
        "base_verdict": pkg.get("base_verdict"),
        "rule": pkg.get("rule", ""),
        "message": pkg.get("message", ""),
        "severity": pkg.get("severity", ""),
        "depth": pkg.get("depth"),
        "direct": pkg.get("direct", False),
        "shortest_path": pkg.get("shortest_path", []),
        "exception": pkg.get("exception"),
        "scope": scope,
    }


def _scopes(result: dict) -> List[tuple]:
    """返回 [(scope_name, packages), ...]；单制品为一个 None 作用域。"""
    if result.get("mode") == "multi":
        return [(d["name"], d.get("packages", [])) for d in result["distributions"]]
    return [(None, result.get("packages", []))]


def _project_meta(result: dict, project_id, project_row: Optional[dict]) -> dict:
    return {
        "project_id": project_id,
        "name": result["project"]["name"],
        "version": result["project"].get("version", ""),
        "mode": result.get("mode", "single"),
        "policy_key": result.get("policy_key", ""),
        "policy_name": result.get("policy", {}).get("name", ""),
        "project_license": result.get("project_license", ""),
        "created_at": (project_row or {}).get("created_at", ""),
    }


# ---------------------------------------------------------------------------
# 对比
# ---------------------------------------------------------------------------


def compare_results(
    baseline: dict,
    current: dict,
    baseline_id=None,
    current_id=None,
    baseline_project: Optional[dict] = None,
    current_project: Optional[dict] = None,
) -> dict:
    """对比两份 ``analyzer.analyze`` 结果，返回可序列化的对比报告。"""
    if baseline.get("mode", "single") != current.get("mode", "single"):
        raise CompareError(
            "两个项目的审查模式不同（一个为单制品、另一个为多制品），无法直接对比；"
            "请选择结构相同的两个版本"
        )
    multi = current.get("mode") == "multi"

    # pkg_id -> {scope -> occurrence}
    base_map: Dict[str, Dict[Optional[str], dict]] = {}
    for scope, packages in _scopes(baseline):
        for pkg in packages:
            base_map.setdefault(pkg["id"], {})[scope] = _occurrence(pkg, scope)
    cur_map: Dict[str, Dict[Optional[str], dict]] = {}
    for scope, packages in _scopes(current):
        for pkg in packages:
            cur_map.setdefault(pkg["id"], {})[scope] = _occurrence(pkg, scope)

    # ---- 图级别（不区分制品）：新增 / 移除 / 许可证变化 ----
    all_ids = list(dict.fromkeys(list(cur_map) + list(base_map)))
    added_rows: List[dict] = []
    removed_rows: List[dict] = []
    license_changes: List[dict] = []

    for pkg_id in all_ids:
        in_base = pkg_id in base_map
        in_cur = pkg_id in cur_map
        if in_cur and not in_base:
            added_rows.append(_graph_added_row(pkg_id, cur_map[pkg_id]))
        elif in_base and not in_cur:
            removed_rows.append(_graph_removed_row(pkg_id, base_map[pkg_id]))
        else:
            b_lic = _graph_license(base_map[pkg_id])
            c_lic = _graph_license(cur_map[pkg_id])
            if (b_lic or "").strip() != (c_lic or "").strip():
                name, _, version = pkg_id.rpartition("@")
                license_changes.append({
                    "id": pkg_id,
                    "name": name,
                    "version": version,
                    "baseline_license": b_lic,
                    "current_license": c_lic,
                })

    added_rows.sort(key=lambda r: (_worst_order(r["occurrences"]), r["id"]))
    removed_rows.sort(key=lambda r: r["id"])
    license_changes.sort(key=lambda r: r["id"])

    # ---- 作用域（制品）级别：结论 / 规则变化、新增冲突、已消除冲突 ----
    verdict_changed: List[dict] = []
    new_conflicts: List[dict] = []
    resolved_conflicts: List[dict] = []
    dist_sections: List[dict] = []

    base_scopes = [s for s, _ in _scopes(baseline)]
    cur_scopes = [s for s, _ in _scopes(current)]
    # (kind, scope)：kind ∈ common / added / removed
    scope_pairs: List[tuple] = []
    if multi:
        for scope in cur_scopes:
            scope_pairs.append(("common" if scope in base_scopes else "added", scope))
        for scope in base_scopes:
            if scope not in cur_scopes:
                scope_pairs.append(("removed", scope))
    else:
        scope_pairs.append(("common", None))

    for kind, scope in scope_pairs:
        if kind == "removed":
            section = _removed_distribution_section(
                baseline, scope, base_map, resolved_conflicts
            )
            dist_sections.append(section)
            continue
        section = _compare_scope(
            scope=scope,
            newly_added=(kind == "added"),
            baseline_result=baseline,
            current_result=current,
            base_map=base_map,
            cur_map=cur_map,
            multi=multi,
            verdict_changed=verdict_changed,
            new_conflicts=new_conflicts,
            resolved_conflicts=resolved_conflicts,
        )
        dist_sections.append(section)

    distributions_added = [s for s in cur_scopes if s not in base_scopes] if multi else []
    distributions_removed = [s for s in base_scopes if s not in cur_scopes] if multi else []

    # ---- 汇总 ----
    graph_summary = {
        "added": len(added_rows),
        "removed": len(removed_rows),
        "license_changed": len(license_changes),
        "verdict_changed": len(verdict_changed),
        "new_conflicts": len(new_conflicts),
        "resolved_conflicts": len(resolved_conflicts),
    }
    if multi:
        graph_summary["distributions_added"] = len(distributions_added)
        graph_summary["distributions_removed"] = len(distributions_removed)

    new_conflicts.sort(
        key=lambda c: (_VERDICT_ORDER.get(c["current_verdict"], 9), c["id"], c["distribution"] or "")
    )
    resolved_conflicts.sort(
        key=lambda c: (_VERDICT_ORDER.get(c["baseline_verdict"], 9), c["id"], c["distribution"] or "")
    )
    verdict_changed.sort(
        key=lambda r: (_VERDICT_ORDER.get(r["current_verdict"], 9), r["id"], r["distribution"] or "")
    )

    payload = {
        "report_format": "licensegate-compare/v1",
        "mode": "multi" if multi else "single",
        "baseline": _project_meta(baseline, baseline_id, baseline_project),
        "current": _project_meta(current, current_id, current_project),
        "summary": graph_summary,
        "added": added_rows,
        "removed": removed_rows,
        "license_changes": license_changes,
        "verdict_changed": verdict_changed,
        "new_conflicts": new_conflicts,
        "resolved_conflicts": resolved_conflicts,
    }
    if multi:
        payload["distributions_added"] = distributions_added
        payload["distributions_removed"] = distributions_removed
        payload["distributions"] = dist_sections
    return payload


def _worst_order(occurrences: List[dict]) -> int:
    return min((_VERDICT_ORDER.get(o["verdict"], 9) for o in occurrences), default=9)


def _graph_license(per_scope: Dict[Optional[str], dict]) -> str:
    for occ in per_scope.values():
        return occ["license_raw"]
    return ""


def _graph_added_row(pkg_id: str, per_scope: Dict[Optional[str], dict]) -> dict:
    any_occ = next(iter(per_scope.values()))
    worst_scope = min(
        per_scope.values(), key=lambda o: _VERDICT_ORDER.get(o["verdict"], 9)
    )
    return {
        "id": pkg_id,
        "name": any_occ["name"],
        "version": any_occ["version"],
        "license_raw": any_occ["license_raw"],
        "license": any_occ["license"],
        "occurrences": [
            {
                "distribution": o["scope"],
                "verdict": o["verdict"],
                "rule": o["rule"],
                "depth": o["depth"],
                "direct": o["direct"],
                "shortest_path": o["shortest_path"],
            }
            for o in sorted(per_scope.values(), key=lambda o: _VERDICT_ORDER.get(o["verdict"], 9))
        ],
        "current_verdict": worst_scope["verdict"],
        "current_rule": worst_scope["rule"],
        "current_distribution": worst_scope["scope"],
        "current_shortest_path": worst_scope["shortest_path"],
        "current_depth": worst_scope["depth"],
    }


def _graph_removed_row(pkg_id: str, per_scope: Dict[Optional[str], dict]) -> dict:
    any_occ = next(iter(per_scope.values()))
    return {
        "id": pkg_id,
        "name": any_occ["name"],
        "version": any_occ["version"],
        "license_raw": any_occ["license_raw"],
        "license": any_occ["license"],
        "occurrences": [
            {
                "distribution": o["scope"],
                "verdict": o["verdict"],
                "rule": o["rule"],
                "depth": o["depth"],
            }
            for o in per_scope.values()
        ],
    }


# ---------------------------------------------------------------------------
# 单作用域（制品）对比
# ---------------------------------------------------------------------------


def _compare_scope(
    *,
    scope: Optional[str],
    newly_added: bool,
    baseline_result: dict,
    current_result: dict,
    base_map: Dict[str, Dict[Optional[str], dict]],
    cur_map: Dict[str, Dict[Optional[str], dict]],
    multi: bool,
    verdict_changed: List[dict],
    new_conflicts: List[dict],
    resolved_conflicts: List[dict],
) -> dict:
    if multi:
        b_dists = {d["name"]: d for d in baseline_result["distributions"]}
        c_dist = next(d for d in current_result["distributions"] if d["name"] == scope)
        b_dist = b_dists.get(scope)
        b_license = b_dist["project_license"] if b_dist else None
        c_license = c_dist["project_license"]
    else:
        b_license = baseline_result.get("project_license")
        c_license = current_result.get("project_license")

    section_added: List[dict] = []
    section_removed: List[dict] = []
    section_common: List[str] = []
    section_verdict_changed: List[dict] = []
    section_new_conflicts: List[dict] = []
    section_resolved_conflicts: List[dict] = []

    all_ids = list(dict.fromkeys(
        [pid for pid, sc in cur_map.items() if scope in sc]
        + [pid for pid, sc in base_map.items() if scope in sc]
    ))

    for pkg_id in all_ids:
        b = base_map.get(pkg_id, {}).get(scope)
        c = cur_map.get(pkg_id, {}).get(scope)
        if c is not None and b is None:
            if not multi:
                reason = "added"
            else:
                reason = "added" if newly_added else "newly_reachable"
            row = _scope_package_row(c)
            row["reason"] = reason
            section_added.append(row)
            if c["verdict"] in PROBLEM_VERDICTS:
                item = _new_conflict_item(c, reason)
                section_new_conflicts.append(item)
                new_conflicts.append(item)
            continue
        if b is not None and c is None:
            row = _scope_package_row(b, prefix="baseline_")
            row["reason"] = "removed" if not multi else "no_longer_reachable"
            section_removed.append(row)
            if b["verdict"] in PROBLEM_VERDICTS:
                item = _resolved_conflict_item(b, row["reason"])
                section_resolved_conflicts.append(item)
                resolved_conflicts.append(item)
            continue

        # 两侧均在该作用域可达
        section_common.append(pkg_id)
        license_changed = (b["license_raw"] or "").strip() != (c["license_raw"] or "").strip()
        verdict_changed_flag = b["verdict"] != c["verdict"]
        rule_changed = b["rule"] != c["rule"]
        if verdict_changed_flag or rule_changed:
            row = {
                "id": pkg_id,
                "name": c["name"],
                "version": c["version"],
                "distribution": scope,
                "baseline_license_raw": b["license_raw"],
                "current_license_raw": c["license_raw"],
                "license_changed": license_changed,
                "baseline_verdict": b["verdict"],
                "current_verdict": c["verdict"],
                "verdict_changed": verdict_changed_flag,
                "baseline_rule": b["rule"],
                "current_rule": c["rule"],
                "rule_changed": rule_changed,
                "baseline_shortest_path": b["shortest_path"],
                "current_shortest_path": c["shortest_path"],
                "baseline_depth": b["depth"],
                "current_depth": c["depth"],
                "current_message": c["message"],
                "current_exception": c["exception"],
            }
            section_verdict_changed.append(row)
            verdict_changed.append(row)

        b_problem = b["verdict"] in PROBLEM_VERDICTS
        c_problem = c["verdict"] in PROBLEM_VERDICTS
        if c_problem and not b_problem:
            item = _new_conflict_item(c, "added" if newly_added else "changed")
            section_new_conflicts.append(item)
            new_conflicts.append(item)
        elif b_problem and not c_problem:
            item = _resolved_conflict_item(b, "changed")
            section_resolved_conflicts.append(item)
            resolved_conflicts.append(item)
        elif b_problem and c_problem and b["rule"] != c["rule"]:
            # 仍为冲突但触发规则变化：在新增冲突中给出当前规则与路径
            item = _new_conflict_item(c, "changed", previous_rule=b["rule"])
            section_new_conflicts.append(item)
            new_conflicts.append(item)

    _sort_scope_rows(section_added)
    _sort_scope_rows(section_removed)
    section_verdict_changed.sort(
        key=lambda r: (_VERDICT_ORDER.get(r["current_verdict"], 9), r["id"])
    )
    section_new_conflicts.sort(key=lambda c: (_VERDICT_ORDER.get(c["current_verdict"], 9), c["id"]))
    section_resolved_conflicts.sort(key=lambda c: (_VERDICT_ORDER.get(c["baseline_verdict"], 9), c["id"]))

    return {
        "name": scope,
        "status": "added" if newly_added else "present",
        "baseline_project_license": b_license,
        "current_project_license": c_license,
        "project_license_changed": b_license != c_license,
        "summary": {
            "added": len(section_added),
            "removed": len(section_removed),
            "verdict_changed": len(section_verdict_changed),
            "new_conflicts": len(section_new_conflicts),
            "resolved_conflicts": len(section_resolved_conflicts),
        },
        "common": section_common,
        "added": section_added,
        "removed": section_removed,
        "verdict_changed": section_verdict_changed,
        "new_conflicts": section_new_conflicts,
        "resolved_conflicts": section_resolved_conflicts,
    }


def _removed_distribution_section(
    baseline_result: dict,
    scope: str,
    base_map: Dict[str, Dict[Optional[str], dict]],
    resolved_conflicts: List[dict],
) -> dict:
    b_dist = next(d for d in baseline_result["distributions"] if d["name"] == scope)
    section_removed: List[dict] = []
    section_resolved: List[dict] = []
    for pkg_id, per_scope in base_map.items():
        b = per_scope.get(scope)
        if b is None:
            continue
        row = _scope_package_row(b, prefix="baseline_")
        row["reason"] = "distribution_removed"
        section_removed.append(row)
        if b["verdict"] in PROBLEM_VERDICTS:
            item = _resolved_conflict_item(b, "distribution_removed")
            section_resolved.append(item)
            resolved_conflicts.append(item)
    section_removed.sort(key=lambda r: r["id"])
    section_resolved.sort(key=lambda c: (_VERDICT_ORDER.get(c["baseline_verdict"], 9), c["id"]))
    return {
        "name": scope,
        "status": "removed",
        "baseline_project_license": b_dist["project_license"],
        "current_project_license": None,
        "project_license_changed": False,
        "summary": {
            "added": 0,
            "removed": len(section_removed),
            "verdict_changed": 0,
            "new_conflicts": 0,
            "resolved_conflicts": len(section_resolved),
        },
        "common": [],
        "added": [],
        "removed": section_removed,
        "verdict_changed": [],
        "new_conflicts": [],
        "resolved_conflicts": section_resolved,
    }


def _sort_scope_rows(rows: List[dict]) -> None:
    rows.sort(key=lambda r: (_VERDICT_ORDER.get(
        r.get("current_verdict", r.get("baseline_verdict", "")), 9
    ), r["id"]))


def _scope_package_row(occ: dict, prefix: str = "current_") -> dict:
    """新增（prefix=current_）/ 移除（prefix=baseline_）包在某作用域内的行。"""
    return {
        "id": occ["id"],
        "name": occ["name"],
        "version": occ["version"],
        "license_raw": occ["license_raw"],
        "license": occ["license"],
        f"{prefix}verdict": occ["verdict"],
        f"{prefix}rule": occ["rule"],
        f"{prefix}shortest_path": occ["shortest_path"],
        f"{prefix}depth": occ["depth"],
        "direct": occ["direct"],
    }


def _new_conflict_item(occ: dict, reason: str, previous_rule: Optional[str] = None) -> dict:
    return {
        "id": occ["id"],
        "name": occ["name"],
        "version": occ["version"],
        "distribution": occ["scope"],
        "license_raw": occ["license_raw"],
        "license": occ["license"],
        "reason": reason,
        "current_verdict": occ["verdict"],
        "current_rule": occ["rule"],
        "current_message": occ["message"],
        "current_severity": occ["severity"],
        "current_shortest_path": occ["shortest_path"],
        "current_depth": occ["depth"],
        "current_direct": occ["direct"],
        "previous_rule": previous_rule,
    }


def _resolved_conflict_item(occ: dict, reason: str) -> dict:
    return {
        "id": occ["id"],
        "name": occ["name"],
        "version": occ["version"],
        "distribution": occ["scope"],
        "license_raw": occ["license_raw"],
        "license": occ["license"],
        "reason": reason,
        "baseline_verdict": occ["verdict"],
        "baseline_rule": occ["rule"],
        "baseline_message": occ["message"],
        "baseline_shortest_path": occ["shortest_path"],
        "baseline_depth": occ["depth"],
    }
