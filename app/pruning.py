"""依赖裁剪试算（只读 what-if 模拟）。

在**已保存项目**的原清单上临时移除用户选定的一条或多条
"父包 → 子包" 依赖边（``name@version → name@version``），随后：

* 重新执行完整的可达性遍历（多制品清单按各制品自己的根分别计算）；
* 重新给出每个可达包的许可结论（沿用项目保存时的策略与已确认例外）；
* 与试算前结果逐制品对比，报告：

  - **被消除的冲突**：试算前在该制品下为 deny/review，试算后因失去全部
    路径而在该制品不可达（若同一包仍可经其他路径到达则只计入"路径变化"，
    不会误报为已消除）；
  - **仍存在的冲突**：裁剪后仍可达且仍为 deny/review 的包，附裁剪前后路径；
  - **不再纳入审查的包**：在该制品下从可达变为不可达的全部包；
  - **路径变化**：仍可达但最短路径发生变化的包。

整个过程**不写回**清单、策略、例外或数据库：被裁剪的清单只在本次请求内
存在于内存中。
"""
from __future__ import annotations

import copy
from typing import Dict, List, Optional, Set, Tuple

from . import analyzer
from . import policies as pol


class PruningError(ValueError):
    """试算请求不合法（边不存在 / 包不存在等）。"""


#: 仍视为"未处理冲突"的结论（例外确认后不计入冲突）
PROBLEM_VERDICTS = ("deny", "review")


# ---------------------------------------------------------------------------
# 裁剪
# ---------------------------------------------------------------------------


def _validate_edge(edge: dict, graph: analyzer.Graph, seen: Set[Tuple[str, str]]) -> Tuple[str, str]:
    src = str(edge.get("from", "")).strip()
    dst = str(edge.get("to", "")).strip()
    if not src or not dst:
        raise PruningError(
            f"依赖边必须同时提供 from 与 to（name@version），收到：{edge!r}"
        )
    if src not in graph.packages:
        raise PruningError(f"依赖边的父包 {src} 不在清单中")
    if dst not in graph.packages:
        raise PruningError(f"依赖边 {src} → {dst} 的子包 {dst} 不在清单中")
    if dst not in graph.edges.get(src, []):
        raise PruningError(f"依赖边 {src} → {dst} 不存在（原清单中 {src} 不依赖 {dst}）")
    if (src, dst) in seen:
        raise PruningError(f"依赖边 {src} → {dst} 在裁剪方案中重复出现")
    seen.add((src, dst))
    return src, dst


def build_pruned_manifest(
    manifest: dict,
    edges: List[Tuple[str, str]],
    frozen_roots: Optional[List[str]] = None,
) -> dict:
    """返回一份裁剪后的清单深拷贝（不修改原清单）。

    从各包声明的 ``dependencies`` 中移除所有会解析到目标子包的引用
    （合并包的多处声明都会被清理）。``frozen_roots`` 非空时，为单制品
    清单注入显式 ``direct_dependencies``，使裁剪后根集合保持不变。
    """
    pruned = copy.deepcopy(manifest)
    resolve = analyzer.build_reference_resolver(pruned.get("packages", []))
    edge_set = set(edges)

    for item in pruned.get("packages", []):
        if not isinstance(item, dict):
            continue
        name = str(item.get("name", "")).strip()
        version = str(item.get("version") or "").strip() or "0.0.0"
        src = f"{name}@{version}"
        kept: List[str] = []
        for ref in item.get("dependencies", []) or []:
            target = resolve(str(ref).strip())
            # target 为 None 时是悬空引用：不在边集合中，原样保留
            if (src, target) not in edge_set:
                kept.append(ref if isinstance(ref, str) else str(ref))
        item["dependencies"] = kept

    if frozen_roots:
        pruned["direct_dependencies"] = list(frozen_roots)
        pruned.pop("root_dependencies", None)
    return pruned


# ---------------------------------------------------------------------------
# 结果投影
# ---------------------------------------------------------------------------


def _entry_map(scope_result: Optional[dict]) -> Dict[str, dict]:
    if scope_result is None:
        return {}
    return {p["id"]: p for p in scope_result.get("packages", [])}


def _path_row(before: Optional[dict], after: Optional[dict]) -> dict:
    return {
        "before_shortest_path": (before or {}).get("shortest_path", []),
        "before_depth": (before or {}).get("depth"),
        "after_shortest_path": (after or {}).get("shortest_path", []),
        "after_depth": (after or {}).get("depth"),
    }


# ---------------------------------------------------------------------------
# 单作用域（制品）差异
# ---------------------------------------------------------------------------


def _diff_scope(
    name: Optional[str],
    base_scope: Optional[dict],
    sim_scope: Optional[dict],
) -> dict:
    """对比同一制品裁剪前后的包结论（None 作用域表示单制品模式）。"""
    base = _entry_map(base_scope)
    sim = _entry_map(sim_scope)
    project_license = (base_scope or sim_scope or {}).get("project_license")

    eliminated: List[dict] = []
    remaining: List[dict] = []
    dropped: List[dict] = []
    changed_paths: List[dict] = []

    for pkg_id in base:
        b = base[pkg_id]
        c = sim.get(pkg_id)
        # 单制品结果会保留对任何根都不可达的包（孤立环 / 未引用）；
        # 它们试算前就不在审查范围内，不参与任何差异统计。
        if not b.get("reachable", True):
            continue
        b_problem = b["verdict"] in PROBLEM_VERDICTS

        if c is None or not c.get("reachable", False):
            # 失去全部路径，不再纳入该制品审查
            drop_row = {
                "id": pkg_id,
                "name": b["name"],
                "version": b["version"],
                "distribution": name,
                "license_raw": b.get("license_raw", ""),
                "verdict": b["verdict"],
                "base_verdict": b.get("base_verdict"),
                "rule": b.get("rule", ""),
                **_path_row(b, None),
            }
            dropped.append(drop_row)
            if b_problem:
                eliminated.append({
                    "id": pkg_id,
                    "name": b["name"],
                    "version": b["version"],
                    "distribution": name,
                    "license_raw": b.get("license_raw", ""),
                    "verdict": b["verdict"],
                    "rule": b.get("rule", ""),
                    "message": b.get("message", ""),
                    **_path_row(b, None),
                })
            continue

        if b_problem and c["verdict"] in PROBLEM_VERDICTS:
            remaining.append({
                "id": pkg_id,
                "name": b["name"],
                "version": b["version"],
                "distribution": name,
                "license_raw": b.get("license_raw", ""),
                "verdict": c["verdict"],
                "rule": c.get("rule", ""),
                "message": c.get("message", ""),
                **_path_row(b, c),
            })

        if b.get("shortest_path", []) != c.get("shortest_path", []):
            # 仍可经其他（可能更短/更长）路径到达：仅报告路径变化，绝不报消除
            changed_paths.append({
                "id": pkg_id,
                "name": b["name"],
                "version": b["version"],
                "distribution": name,
                "verdict": c["verdict"],
                "rule": c.get("rule", ""),
                **_path_row(b, c),
            })

    # 裁剪只移除边，不会新增可达包；sim 中出现新可达包属于不应发生的情况，
    # 保险起见忽略（无法形成新增审查项）。
    for rows in (eliminated, remaining, dropped, changed_paths):
        rows.sort(key=lambda r: (r["id"], r["distribution"] or ""))

    # 统计以"该制品可达"为准（单制品结果的 summary 会把孤立环/不可达包也计入，
    # 试算语义下不可达即不纳入审查）。
    def reachable_counts(scope_result: Optional[dict]) -> Tuple[int, int]:
        if scope_result is None:
            return 0, 0
        reachable = [
            p for p in scope_result.get("packages", []) if p.get("reachable", True)
        ]
        conflicts = sum(1 for p in reachable if p["verdict"] in PROBLEM_VERDICTS)
        return len(reachable), conflicts

    total_before, conflicts_before = reachable_counts(base_scope)
    total_after, conflicts_after = reachable_counts(sim_scope)
    return {
        "name": name,
        "project_license": project_license,
        "summary": {
            "eliminated_conflicts": len(eliminated),
            "remaining_conflicts": len(remaining),
            "dropped_packages": len(dropped),
            "changed_paths": len(changed_paths),
            "conflicts_before": conflicts_before,
            "conflicts_after": conflicts_after,
            "total_before": total_before,
            "total_after": total_after,
        },
        "eliminated_conflicts": eliminated,
        "remaining_conflicts": remaining,
        "dropped_packages": dropped,
        "changed_paths": changed_paths,
    }


# ---------------------------------------------------------------------------
# 多制品总览差异（跨制品最严重结论）
# ---------------------------------------------------------------------------


def _overview_map(result: dict) -> Dict[str, dict]:
    overview = result.get("overview")
    if not overview:
        return {}
    return {p["id"]: p for p in overview.get("packages", [])}


def _diff_overview(base_result: dict, sim_result: dict) -> dict:
    base = _overview_map(base_result)
    sim = _overview_map(sim_result)
    changes: List[dict] = []

    for pkg_id, b in base.items():
        c = sim.get(pkg_id)
        b_names = {a["distribution"] for a in b.get("affected", [])}
        c_names = {a["distribution"] for a in (c or {}).get("affected", [])}
        b_verdict = b["verdict"]
        c_verdict = c["verdict"] if c else "unreachable"
        if b_verdict == c_verdict and b_names == c_names:
            continue

        def pick_affected(ov_row: Optional[dict], verdict: str) -> Optional[dict]:
            if not ov_row:
                return None
            for a in ov_row.get("affected", []):
                if a["verdict"] == verdict:
                    return a
            return None

        b_aff = pick_affected(b, b_verdict)
        c_aff = pick_affected(c, c_verdict) if c_verdict in PROBLEM_VERDICTS + ("exception", "allow") else None
        change = "verdict_changed" if b_verdict != c_verdict else "reachability_changed"
        if c_verdict == "unreachable":
            change = "dropped"
        elif b_verdict in PROBLEM_VERDICTS and c_verdict not in PROBLEM_VERDICTS:
            change = "conflict_cleared"

        changes.append({
            "id": pkg_id,
            "name": b["name"],
            "version": b["version"],
            "license_raw": b.get("license_raw", ""),
            "before_verdict": b_verdict,
            "after_verdict": c_verdict,
            "change": change,
            "reachable_distributions_before": sorted(b_names),
            "reachable_distributions_after": sorted(c_names),
            "before_shortest_path": (b_aff or {}).get("shortest_path", []),
            "after_shortest_path": (c_aff or {}).get("shortest_path", []),
        })

    changes.sort(key=lambda r: (r["id"],))
    return {
        "summary": {
            "changed_packages": len(changes),
            "conflicts_before": base_result.get("overview", {}).get("summary", {}).get("conflicts", 0),
            "conflicts_after": sim_result.get("overview", {}).get("summary", {}).get("conflicts", 0),
            "unreachable_before": base_result.get("overview", {}).get("summary", {}).get("unreachable", 0),
            "unreachable_after": sim_result.get("overview", {}).get("summary", {}).get("unreachable", 0),
        },
        "changes": changes,
    }


# ---------------------------------------------------------------------------
# 试算入口
# ---------------------------------------------------------------------------


def simulate_pruning(
    manifest: dict,
    policy: pol.Policy,
    edges: List[dict],
    exceptions=None,
) -> dict:
    """校验裁剪边并执行只读试算，返回可序列化的试算报告。

    ``edges`` 为 ``[{"from": "a@1", "to": "b@2"}, ...]``；边必须是原清单
    解析后真实存在的边，否则抛出 :class:`PruningError`。
    """
    # 1. 原图（用于校验边真实存在、拿到稳定的根集合）
    base_graph = analyzer.build_graph(manifest, policy)
    seen: Set[Tuple[str, str]] = set()
    edge_pairs = [_validate_edge(e, base_graph, seen) for e in edges]
    removed_edges = [{"from": s, "to": d} for s, d in edge_pairs]

    # 2. 单制品且根为"入度为 0"隐式推导时，冻结根集合，避免删除唯一入边后根漂移
    frozen_roots: Optional[List[str]] = None
    has_explicit_roots = bool(
        manifest.get("direct_dependencies") or manifest.get("root_dependencies")
    )
    if not base_graph.multi and not has_explicit_roots:
        frozen_roots = list(base_graph.roots)

    # 3. 原清单结果（沿用调用方给出的已确认例外）
    baseline = analyzer.analyze(manifest, policy, None, exceptions)

    # 4. 裁剪后的临时清单与试算结果（不落库、不修改入参）
    pruned_manifest = build_pruned_manifest(manifest, edge_pairs, frozen_roots)
    simulated = analyzer.analyze(pruned_manifest, policy, None, exceptions)

    multi = base_graph.multi

    # 5. 逐作用域（制品）差异
    scopes: List[dict] = []
    if multi:
        base_dists = {d["name"]: d for d in baseline["distributions"]}
        sim_dists = {d["name"]: d for d in simulated["distributions"]}
        for name in base_dists:
            scopes.append(_diff_scope(name, base_dists[name], sim_dists.get(name)))
    else:
        scopes.append(_diff_scope(None, baseline, simulated))

    # 6. 因失去全部路径而不再纳入审查（图级别；多制品=对所有制品都不可达）
    if multi:
        newly_unreachable = sorted(
            set(simulated.get("unreachable_packages", []))
            - set(baseline.get("unreachable_packages", []))
        )
        overview = _diff_overview(baseline, simulated)
    else:
        newly_unreachable = sorted(
            p["id"] for p in simulated["packages"]
            if not p.get("reachable", True)
            and next(
                (b for b in baseline["packages"] if b["id"] == p["id"]), {}
            ).get("reachable", True)
        )
        overview = None

    eliminated_total = sum(s["summary"]["eliminated_conflicts"] for s in scopes)
    remaining_total = sum(s["summary"]["remaining_conflicts"] for s in scopes)
    dropped_total = sum(s["summary"]["dropped_packages"] for s in scopes)
    changed_total = sum(s["summary"]["changed_paths"] for s in scopes)
    conflicts_before_total = sum(s["summary"]["conflicts_before"] for s in scopes)
    conflicts_after_total = sum(s["summary"]["conflicts_after"] for s in scopes)

    return {
        "report_format": "licensegate-pruning/v1",
        "mode": "multi" if multi else "single",
        "project": {
            "name": base_graph.project.get("name", "未命名项目"),
            "version": base_graph.project.get("version", ""),
        },
        "project_license": base_graph.project_license,
        "policy_key": policy.key,
        "policy": policy.to_dict(),
        "read_only": True,
        "removed_edges": removed_edges,
        "summary": {
            "edges_removed": len(removed_edges),
            "scopes": len(scopes),
            "eliminated_conflicts": eliminated_total,
            "remaining_conflicts": remaining_total,
            "dropped_packages": dropped_total,
            "changed_paths": changed_total,
            "conflicts_before": conflicts_before_total,
            "conflicts_after": conflicts_after_total,
            "newly_unreachable": len(newly_unreachable),
        },
        "newly_unreachable_packages": newly_unreachable,
        "scopes": scopes,
        "overview": overview,
        "baseline": baseline,
        "simulated": simulated,
    }
