"""依赖裁剪模拟（只读试算）。

在**不改动已保存清单**的前提下，临时移除用户选中的一条或多条
"父包 → 子包"依赖边，然后重新执行 BFS 可达性遍历与许可判定，
对比试算前后每个制品（多制品清单按各自根分别计算）的：

* **被消除的冲突**：原本 deny/review，裁剪后从该制品根不可达；
* **仍存在的冲突**：裁剪后仍可达（含改走其他路径的情况），给出变化前后最短路径；
* **不再纳入审查的包**：失去全部到达路径的包（其中非冲突包单列）；
* **路径变化**：仍可达、结论不变，但最短路径改变的包。

注意：移除边只会缩短可达集合，许可证 / 项目许可证 / 策略均不变，
因此对仍可达的包，许可结论与触发规则不会改变；若同一包仍可经其他
路径到达，它只会出现在"仍存在的冲突"中，绝不会被误报为已消除。
"""
from __future__ import annotations

from dataclasses import replace
from typing import Dict, List, Optional, Set, Tuple

from . import analyzer
from . import policies as pol

PROBLEM_VERDICTS = ("deny", "review")

#: 结论严重度（deny > review > exception > allow）
_VERDICT_ORDER = {"deny": 0, "review": 1, "exception": 2, "allow": 3}


class TrialError(ValueError):
    """试算请求不合法（边不存在 / 未选择边等）。"""


# ---------------------------------------------------------------------------
# 图裁剪
# ---------------------------------------------------------------------------


def validate_edges(graph: analyzer.Graph, edges: List[dict]) -> List[Tuple[str, str]]:
    """校验所选边确实存在于解析后的依赖图，返回去重后的 (from, to) 列表。"""
    valid: List[Tuple[str, str]] = []
    seen: Set[Tuple[str, str]] = set()
    invalid: List[dict] = []
    for edge in edges:
        src = (edge.get("from") or "").strip()
        dst = (edge.get("to") or "").strip()
        pair = (src, dst)
        if pair in seen:
            continue
        seen.add(pair)
        if not src or not dst or dst not in graph.edges.get(src, []):
            invalid.append({"from": src, "to": dst})
            continue
        valid.append(pair)
    if invalid:
        rendered = "、".join(f"{s} → {d}" for s, d in ((e["from"], e["to"]) for e in invalid))
        raise TrialError(f"以下依赖边在清单依赖图中不存在，请重新选择：{rendered}")
    if not valid:
        raise TrialError("请至少选择一条要临时移除的依赖边")
    return valid


def _trim_graph(graph: analyzer.Graph, removed: List[Tuple[str, str]]) -> analyzer.Graph:
    """返回一份移除指定边后的新图（不修改原图与清单）。"""
    edges = {key: list(targets) for key, targets in graph.edges.items()}
    for src, dst in removed:
        edges[src].remove(dst)
    return replace(graph, edges=edges)


# ---------------------------------------------------------------------------
# 按作用域（单制品隐式作用域 / 多制品的每个制品）重算
# ---------------------------------------------------------------------------


def _scope_entries(
    graph: analyzer.Graph,
    policy: pol.Policy,
    roots: List[str],
    project_license: str,
    exc_rows: List[dict],
    multi: bool,
) -> Dict[str, dict]:
    """在给定图上从固定根集合重算每个包的结论条目（不可达包条目的 reachable=False）。"""
    paths = analyzer.shortest_paths(graph, roots)
    root_set = set(roots)
    entries: Dict[str, dict] = {}
    for key, pkg in graph.packages.items():
        path = paths[key]
        probe = pol.judge(project_license, pkg.license_raw, policy)
        exc = analyzer._match_exception(exc_rows, key, probe["rule"], multi=multi)
        entries[key] = analyzer._build_package_entry(
            pkg, graph, project_license, policy, path, root_set, exc
        )
    return entries


def _remaining_row(pkg_id: str, before: dict, after: dict) -> dict:
    return {
        "id": pkg_id,
        "name": after["name"],
        "version": after["version"],
        "license_raw": after["license_raw"],
        "license": after["license"],
        "verdict": after["verdict"],
        "base_verdict": after["base_verdict"],
        "rule": after["rule"],
        "rule_kind": after["rule_kind"],
        "message": after["message"],
        "severity": after["severity"],
        "exception": after["exception"],
        "baseline_shortest_path": before["shortest_path"],
        "trimmed_shortest_path": after["shortest_path"],
        "baseline_depth": before["depth"],
        "trimmed_depth": after["depth"],
        "path_changed": before["shortest_path"] != after["shortest_path"],
    }


def _dropped_row(before: dict) -> dict:
    return {
        "id": before["id"],
        "name": before["name"],
        "version": before["version"],
        "license_raw": before["license_raw"],
        "license": before["license"],
        "baseline_verdict": before["verdict"],
        "baseline_base_verdict": before["base_verdict"],
        "baseline_rule": before["rule"],
        "baseline_rule_kind": before["rule_kind"],
        "baseline_message": before["message"],
        "baseline_shortest_path": before["shortest_path"],
        "baseline_depth": before["depth"],
        "was_conflict": before["verdict"] in PROBLEM_VERDICTS,
    }


def _diff_scope(
    name: Optional[str],
    project_license: str,
    roots: List[str],
    before_map: Dict[str, dict],
    after_entries: Dict[str, dict],
) -> dict:
    before_reachable = {k for k, e in before_map.items() if e.get("reachable", True)}
    after_reachable = {k for k, e in after_entries.items() if e["reachable"]}

    dropped_ids = before_reachable - after_reachable
    still_ids = before_reachable & after_reachable

    dropped = [_dropped_row(before_map[k]) for k in dropped_ids]
    dropped.sort(key=lambda r: (r["baseline_depth"] if r["baseline_depth"] is not None else 999, r["id"]))
    resolved = [dict(r) for r in dropped if r["was_conflict"]]

    remaining = [
        _remaining_row(k, before_map[k], after_entries[k])
        for k in still_ids
        if after_entries[k]["verdict"] in PROBLEM_VERDICTS
    ]
    remaining.sort(key=lambda r: (
        _VERDICT_ORDER.get(r["verdict"], 9),
        r["trimmed_depth"] if r["trimmed_depth"] is not None else 999,
        r["id"],
    ))

    # 仍可达、结论不变但最短路径变化；deny/review 已在"仍存在的冲突"中给出前后路径
    path_changed = []
    for k in still_ids:
        b, a = before_map[k], after_entries[k]
        if b["verdict"] != a["verdict"]:
            continue
        if a["verdict"] in PROBLEM_VERDICTS:
            continue
        if b["shortest_path"] != a["shortest_path"]:
            path_changed.append({
                "id": k,
                "name": a["name"],
                "version": a["version"],
                "license_raw": a["license_raw"],
                "verdict": a["verdict"],
                "rule": a["rule"],
                "baseline_shortest_path": b["shortest_path"],
                "trimmed_shortest_path": a["shortest_path"],
                "baseline_depth": b["depth"],
                "trimmed_depth": a["depth"],
            })
    path_changed.sort(key=lambda r: (
        r["trimmed_depth"] if r["trimmed_depth"] is not None else 999, r["id"]
    ))

    baseline_conflicts = sum(1 for k in before_reachable if before_map[k]["verdict"] in PROBLEM_VERDICTS)
    summary = {
        "baseline_reachable": len(before_reachable),
        "trimmed_reachable": len(after_reachable),
        "baseline_conflicts": baseline_conflicts,
        "remaining_conflicts": len(remaining),
        "resolved_conflicts": len(resolved),
        "dropped_packages": len(dropped),
        "path_changed": len(path_changed),
    }

    return {
        "name": name,
        "project_license": project_license,
        "roots": list(roots),
        "summary": summary,
        "remaining_conflicts": remaining,
        "resolved_conflicts": resolved,
        "dropped_packages": dropped,
        "path_changed": path_changed,
    }


# ---------------------------------------------------------------------------
# 试算入口
# ---------------------------------------------------------------------------


def simulate(
    manifest: dict,
    policy: pol.Policy,
    baseline: dict,
    exceptions,
    edges: List[dict],
) -> dict:
    """基于原清单临时移除所选边并重算，返回 ``licensegate-trial/v1`` 报告。

    ``baseline`` 为项目按保存策略 / 例外计算出的 ``analyzer.analyze`` 结果，
    用作"试算前"快照；本函数不写回任何数据。
    """
    graph = analyzer.build_graph(manifest, policy)
    removed = validate_edges(graph, edges)
    trimmed = _trim_graph(graph, removed)
    cycles = analyzer.detect_cycles(trimmed)
    exc_rows = analyzer._normalize_exceptions(exceptions)

    scopes: List[dict] = []
    if graph.multi:
        base_dists = {
            d["name"]: {p["id"]: p for p in d.get("packages", [])}
            for d in baseline.get("distributions", [])
        }
        after_reachable_by_dist: Dict[str, Set[str]] = {}
        for dist in graph.distributions:
            # 根集合固定为原清单制品根：裁剪不改变"什么是直接依赖"
            after_entries = _scope_entries(
                trimmed, policy, dist.roots, dist.project_license, exc_rows, multi=True
            )
            after_reachable_by_dist[dist.name] = {
                k for k, e in after_entries.items() if e["reachable"]
            }
            scopes.append(
                _diff_scope(
                    dist.name,
                    dist.project_license,
                    dist.roots,
                    base_dists.get(dist.name, {}),
                    after_entries,
                )
            )
        unreachable_after = [
            key for key in graph.packages
            if not any(key in reach for reach in after_reachable_by_dist.values())
        ]
    else:
        before_map = {p["id"]: p for p in baseline.get("packages", [])}
        after_entries = _scope_entries(
            trimmed, policy, graph.roots, graph.project_license, exc_rows, multi=False
        )
        scopes.append(
            _diff_scope(None, graph.project_license, graph.roots, before_map, after_entries)
        )
        unreachable_after = None

    totals = {
        "baseline_conflicts": sum(s["summary"]["baseline_conflicts"] for s in scopes),
        "remaining_conflicts": sum(s["summary"]["remaining_conflicts"] for s in scopes),
        "resolved_conflicts": sum(s["summary"]["resolved_conflicts"] for s in scopes),
        "dropped_packages": sum(s["summary"]["dropped_packages"] for s in scopes),
        "path_changed": sum(s["summary"]["path_changed"] for s in scopes),
    }

    payload = {
        "report_format": "licensegate-trial/v1",
        "mode": "multi" if graph.multi else "single",
        "project": baseline.get("project", graph.project),
        "project_license": baseline.get("project_license", graph.project_license),
        "policy": baseline.get("policy", policy.to_dict()),
        "removed_edges": [{"from": s, "to": d} for s, d in removed],
        "summary": totals,
        "scopes": scopes,
        "cycles": cycles,
        "unresolved_refs": list(graph.unresolved_refs),
        "read_only": True,
    }
    if graph.multi:
        payload["unreachable_packages"] = unreachable_after
    return payload
