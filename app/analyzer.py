"""清单解析、依赖图构建、最短路径与冲突分析。

支持的清单格式（单制品）::

    {
      "project": {"name": "my-app", "version": "1.0.0"},
      "project_license": "MIT",                 // 可选，覆盖策略默认值
      "direct_dependencies": ["web框架"],        // 可选：显式直接依赖（name 或 name@version）
      "packages": [
        {
          "name": "web框架",
          "version": "2.0.0",
          "license": "MIT",
          "dependencies": ["工具@1.0", "解析器"]
        }
      ]
    }

多制品审查（可选 ``distributions`` 数组）::

    {
      "project": {"name": "monorepo", "version": "1.0.0"},
      "packages": [ ... 共享的完整依赖图 ... ],
      "distributions": [
        {"name": "sdk-js",   "project_license": "MIT",     "direct_dependencies": ["js-core"]},
        {"name": "cli-gpl",  "project_license": "GPL-3.0", "direct_dependencies": ["cli-main"]}
      ]
    }

说明：

* 依赖引用写作 ``name`` 或 ``name@version``；带版本时优先精确匹配，
  否则按名字匹配同名包；引用不存在的包会记入 ``unresolved_refs``，不中断分析。
* 单制品模式下，未声明 ``direct_dependencies`` 时，入度为 0 的包视为根（直接依赖）。
* 多制品模式下，每个制品声明各自的 ``project_license`` 与 ``direct_dependencies``；
  后端在**同一依赖图**上分别从各制品根执行最短路径遍历（BFS），按该制品的项目许可证
  与所选策略判定，只统计该制品可达的包；悬空的制品根会记入该制品的
  ``unresolved_roots``（同时进入全局 ``unresolved_refs``）。
* BFS 计算每个包到根的最短依赖路径；循环依赖不会导致死循环，
  不可达包会被标记（常见于孤立环）。多制品总览中对任何制品都不可达的包列入
  ``unreachable_packages``。
* 一个包多条许可证时可用 SPDX 表达式（``A OR B``、``(A AND B)``）描述。
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from . import licenses as lic
from . import policies as pol


class ManifestError(ValueError):
    """清单结构不合法。"""


@dataclass
class Pkg:
    name: str
    version: str
    license_raw: str
    deps: List[str] = field(default_factory=list)  # 原始引用字符串

    @property
    def key(self) -> str:
        return f"{self.name}@{self.version}"


@dataclass
class Distribution:
    """多制品清单中的一个制品（遍历根 + 该制品的项目许可证）。"""
    name: str
    project_license_raw: Optional[str]
    direct_deps: List[str]
    # build_graph 解析后填充：
    project_license: str = ""
    roots: List[str] = field(default_factory=list)
    unresolved_roots: List[str] = field(default_factory=list)


@dataclass
class Graph:
    project: dict
    project_license: str
    packages: Dict[str, Pkg]  # key -> Pkg（保留插入顺序）
    edges: Dict[str, List[str]]  # from key -> [to key]
    roots: List[str]
    unresolved_refs: List[str]
    #: 多制品模式下为各制品的根/许可证信息；单制品模式为 None
    distributions: Optional[List[Distribution]] = None

    @property
    def multi(self) -> bool:
        return bool(self.distributions)


# ---------------------------------------------------------------------------
# 解析
# ---------------------------------------------------------------------------


def _coerce_str(value, field_name: str) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, (int, float)):
        return str(value)
    raise ManifestError(f"字段 {field_name} 必须是字符串，实际为 {type(value).__name__}")


def parse_manifest(
    data: dict,
) -> Tuple[List[Pkg], dict, Optional[str], Optional[List[str]], Optional[List[Distribution]]]:
    if not isinstance(data, dict):
        raise ManifestError("清单必须是 JSON 对象")
    raw_packages = data.get("packages")
    if not isinstance(raw_packages, list) or not raw_packages:
        raise ManifestError("清单缺少非空的 packages 数组")

    project = data.get("project") or {}
    if not isinstance(project, dict):
        raise ManifestError("project 字段必须是对象")

    project_license_raw = data.get("project_license")
    project_license = (
        lic.canonicalize(project_license_raw)
        if isinstance(project_license_raw, str) and project_license_raw.strip()
        else None
    )
    if project_license == "NOASSERTION":
        raise ManifestError(
            f"项目许可证 {project_license_raw!r} 无法识别为已知 SPDX 标识"
        )

    direct_raw = data.get("direct_dependencies") or data.get("root_dependencies")
    if direct_raw is not None and not isinstance(direct_raw, list):
        raise ManifestError("direct_dependencies 必须是字符串数组")
    direct_deps = (
        [_coerce_str(r, "direct_dependencies[]") for r in direct_raw]
        if direct_raw is not None
        else None
    )

    distributions = _parse_distributions(data.get("distributions"))

    packages: Dict[str, Pkg] = {}
    for idx, item in enumerate(raw_packages):
        if not isinstance(item, dict):
            raise ManifestError(f"packages[{idx}] 必须是对象")
        name = _coerce_str(item.get("name"), f"packages[{idx}].name")
        if not name:
            raise ManifestError(f"packages[{idx}] 缺少 name")
        version = _coerce_str(item.get("version"), f"packages[{idx}].version") or "0.0.0"
        license_raw = _coerce_str(item.get("license"), f"packages[{idx}].license")
        raw_deps = item.get("dependencies") or []
        if not isinstance(raw_deps, list):
            raise ManifestError(f"packages[{idx}].dependencies 必须是数组")
        deps = [_coerce_str(d, f"packages[{idx}].dependencies[]") for d in raw_deps if _coerce_str(d, "")]

        key = f"{name}@{version}"
        if key in packages:
            # 重复包：合并依赖边
            for d in deps:
                if d not in packages[key].deps:
                    packages[key].deps.append(d)
            if not packages[key].license_raw and license_raw:
                packages[key].license_raw = license_raw
        else:
            packages[key] = Pkg(name=name, version=version, license_raw=license_raw, deps=deps)

    return list(packages.values()), project, project_license, direct_deps, distributions


def _parse_distributions(raw) -> Optional[List[Distribution]]:
    """解析可选的 distributions 数组；未提供时返回 None。"""
    if raw is None:
        return None
    if not isinstance(raw, list) or not raw:
        raise ManifestError("distributions 必须是非空数组")

    dists: List[Distribution] = []
    seen_names: Set[str] = set()
    for idx, item in enumerate(raw):
        if not isinstance(item, dict):
            raise ManifestError(f"distributions[{idx}] 必须是对象")
        name = _coerce_str(item.get("name"), f"distributions[{idx}].name")
        if not name:
            raise ManifestError(f"distributions[{idx}] 缺少唯一 name")
        if name in seen_names:
            raise ManifestError(f"distributions 中制品名称 {name!r} 重复，名称必须唯一")
        seen_names.add(name)

        lic_raw = item.get("project_license")
        if lic_raw is not None and not isinstance(lic_raw, str):
            raise ManifestError(f"distributions[{idx}].project_license 必须是字符串")
        lic_value = lic_raw.strip() if isinstance(lic_raw, str) and lic_raw.strip() else None
        if lic_value is not None and lic.canonicalize(lic_value) == "NOASSERTION":
            raise ManifestError(
                f"制品 {name!r} 的项目许可证 {lic_value!r} 无法识别为已知 SPDX 标识"
            )

        raw_roots = item.get("direct_dependencies")
        if not isinstance(raw_roots, list) or not raw_roots:
            raise ManifestError(
                f"制品 {name!r} 的 direct_dependencies 必须是非空字符串数组"
            )
        roots = [
            _coerce_str(r, f"distributions[{idx}].direct_dependencies[]")
            for r in raw_roots
        ]
        roots = [r for r in roots if r]
        if not roots:
            raise ManifestError(
                f"制品 {name!r} 的 direct_dependencies 必须是非空字符串数组"
            )

        dists.append(
            Distribution(
                name=name,
                project_license_raw=lic_value,
                direct_deps=roots,
            )
        )
    return dists


def _split_ref(ref: str) -> Tuple[str, str]:
    ref = ref.strip()
    if "@" in ref:
        name, version = ref.rsplit("@", 1)
        return name, version
    return ref, ""


def _validate_project_license(chosen_license: str, policy: pol.Policy, where: str) -> None:
    if chosen_license not in lic.KNOWN_LICENSES:
        raise ManifestError(f"{where}许可证 {chosen_license!r} 不在内置矩阵中")
    if chosen_license not in policy.allowed_project_licenses:
        allowed = ", ".join(policy.allowed_project_licenses)
        raise ManifestError(
            f"{where}许可证 {chosen_license} 与策略「{policy.name}」不匹配，"
            f"该策略允许的项目许可证：{allowed}"
        )


def build_graph(data: dict, policy: pol.Policy, license_override: Optional[str] = None) -> Graph:
    pkgs, project, project_license, direct_deps, distributions = parse_manifest(data)
    index: Dict[str, Pkg] = {p.key: p for p in pkgs}
    by_name: Dict[str, List[str]] = {}
    for p in pkgs:
        by_name.setdefault(p.name, []).append(p.key)

    edges: Dict[str, List[str]] = {p.key: [] for p in pkgs}
    unresolved: List[str] = []

    def resolve(ref: str) -> Optional[str]:
        name, version = _split_ref(ref)
        if version:
            exact = f"{name}@{version}"
            if exact in index:
                return exact
        candidates = by_name.get(name, [])
        if len(candidates) == 1:
            return candidates[0]
        if len(candidates) > 1:
            # 多版本且引用未指定/未命中：无法确定，作为未解析引用
            return None
        return None

    def add_unresolved(ref: str) -> None:
        if ref not in unresolved:
            unresolved.append(ref)

    for p in pkgs:
        for ref in p.deps:
            target = resolve(ref)
            if target is None:
                add_unresolved(ref)
                continue
            if target not in edges[p.key]:
                edges[p.key].append(target)

    if distributions is not None:
        # 多制品模式不支持统一覆盖项目许可证：各制品使用各自的许可证
        if license_override:
            raise ManifestError(
                "多制品清单（含 distributions）按各制品的 project_license 分别判定，"
                "不支持统一覆盖项目许可证"
            )
        all_roots: List[str] = []
        for dist in distributions:
            chosen = (
                lic.canonicalize(dist.project_license_raw)
                if dist.project_license_raw
                else project_license or policy.default_project_license
            )
            _validate_project_license(chosen, policy, f"制品 {dist.name!r} 的项目")
            dist.project_license = chosen
            for ref in dist.direct_deps:
                target = resolve(ref)
                if target is None:
                    dist.unresolved_roots.append(ref)
                    add_unresolved(ref)
                    continue
                if target not in dist.roots:
                    dist.roots.append(target)
                if target not in all_roots:
                    all_roots.append(target)

        # 顶层 project_license 仅作展示用：清单声明则透传，否则取策略默认值
        display_license = project_license or policy.default_project_license
        return Graph(
            project=project,
            project_license=display_license,
            packages=index,
            edges=edges,
            roots=all_roots,
            unresolved_refs=unresolved,
            distributions=distributions,
        )

    chosen_license = license_override or project_license or policy.default_project_license
    _validate_project_license(chosen_license, policy, "项目")

    # 根：显式声明 > 入度为 0
    roots: List[str] = []
    if direct_deps is not None:
        for ref in direct_deps:
            target = resolve(ref)
            if target is None:
                add_unresolved(ref)
                continue
            if target not in roots:
                roots.append(target)
    else:
        depended: Set[str] = set()
        for targets in edges.values():
            depended.update(targets)
        roots = [p.key for p in pkgs if p.key not in depended]

    return Graph(
        project=project,
        project_license=chosen_license,
        packages=index,
        edges=edges,
        roots=roots,
        unresolved_refs=unresolved,
    )


# ---------------------------------------------------------------------------
# 最短路径（多源 BFS，记录前驱）
# ---------------------------------------------------------------------------


def shortest_paths(
    graph: Graph, roots: Optional[List[str]] = None
) -> Dict[str, Optional[List[str]]]:
    """返回每个包从给定根（默认 graph.roots）出发的最短路径（含首尾）。不可达为 None。"""
    use_roots = graph.roots if roots is None else roots
    prev: Dict[str, Optional[str]] = {}
    dist: Dict[str, int] = {}
    queue: deque[str] = deque()
    for root in use_roots:
        if root in graph.packages and root not in dist:
            dist[root] = 0
            prev[root] = None
            queue.append(root)

    while queue:
        cur = queue.popleft()
        for nxt in graph.edges.get(cur, []):
            if nxt not in dist:
                dist[nxt] = dist[cur] + 1
                prev[nxt] = cur
                queue.append(nxt)

    paths: Dict[str, Optional[List[str]]] = {}
    for key in graph.packages:
        if key not in dist:
            paths[key] = None
            continue
        path: List[str] = []
        node: Optional[str] = key
        while node is not None:
            path.append(node)
            node = prev[node]
        path.reverse()
        paths[key] = path
    return paths


def detect_cycles(graph: Graph) -> List[List[str]]:
    """用 Tarjan 强连通分量找环（返回大小 >1 以及自环的分量）。"""
    index_counter = [0]
    stack: List[str] = []
    on_stack: Set[str] = set()
    indices: Dict[str, int] = {}
    lowlink: Dict[str, int] = {}
    cycles: List[List[str]] = []

    def strongconnect(v: str) -> None:
        indices[v] = index_counter[0]
        lowlink[v] = index_counter[0]
        index_counter[0] += 1
        stack.append(v)
        on_stack.add(v)
        for w in graph.edges.get(v, []):
            if w not in indices:
                strongconnect(w)
                lowlink[v] = min(lowlink[v], lowlink[w])
            elif w in on_stack:
                lowlink[v] = min(lowlink[v], indices[w])
        if lowlink[v] == indices[v]:
            comp: List[str] = []
            while True:
                w = stack.pop()
                on_stack.discard(w)
                comp.append(w)
                if w == v:
                    break
            if len(comp) > 1 or (len(comp) == 1 and comp[0] in graph.edges.get(comp[0], [])):
                cycles.append(list(reversed(comp)))

    for key in graph.packages:
        if key not in indices:
            strongconnect(key)
    return cycles


# ---------------------------------------------------------------------------
# 冲突分析
# ---------------------------------------------------------------------------

#: 结论严重度排序（用于总览按最严重结论聚合）：deny > review > exception > allow
_VERDICT_ORDER = {"deny": 0, "review": 1, "exception": 2, "allow": 3}


def _is_compound(raw: str) -> bool:
    upper = (raw or "").upper()
    return " OR " in upper or " AND " in upper or "(" in upper or ")" in upper


def _empty_summary() -> dict:
    return {"total": 0, "allow": 0, "deny": 0, "review": 0, "exceptions": 0, "conflicts": 0}


def _normalize_exceptions(exceptions) -> List[dict]:
    """归一化例外数据。

    支持两种形态：

    * 旧版字典 ``{package_key: {"note", "approved_at"}}``；
    * 新版记录列表 ``[{"package_id", "note", "approved_at", "rule", "distribution"}]``。
    """
    if not exceptions:
        return []
    rows: List[dict] = []
    if isinstance(exceptions, dict):
        for pid, info in exceptions.items():
            rows.append(
                {
                    "package_id": pid,
                    "note": (info or {}).get("note", ""),
                    "approved_at": (info or {}).get("approved_at", ""),
                    "rule": (info or {}).get("rule", ""),
                    "distribution": (info or {}).get("distribution", ""),
                }
            )
        return rows
    for info in exceptions:
        rows.append(
            {
                "package_id": info.get("package_id", ""),
                "note": info.get("note", ""),
                "approved_at": info.get("approved_at", ""),
                "rule": info.get("rule", "") or "",
                "distribution": info.get("distribution", "") or "",
            }
        )
    return rows


def _match_exception(
    exc_rows: List[dict], key: str, rule: str, multi: bool
) -> Optional[dict]:
    """返回适用于该包结论的例外记录。

    多制品模式要求 ``package_id`` 与触发规则 ``rule`` 同时相等才覆盖；
    单制品模式仅按 package_id 匹配（旧清单行为不变）。
    """
    for row in exc_rows:
        if row["package_id"] != key:
            continue
        if multi and row.get("rule", "") != rule:
            continue
        return row
    return None


def _build_package_entry(
    pkg: Pkg,
    graph: Graph,
    project_license: str,
    policy: pol.Policy,
    path: Optional[List[str]],
    root_set: Set[str],
    exc: Optional[dict],
) -> dict:
    depth = (len(path) - 1) if path else None
    is_direct = pkg.key in root_set or depth == 0

    judgement = pol.judge(project_license, pkg.license_raw, policy)

    if _is_compound(pkg.license_raw):
        canonical = judgement["trigger_license"]
        members = lic.expression_licenses(pkg.license_raw)
        family = "expression"
    else:
        canonical = lic.canonicalize(pkg.license_raw)
        members = [canonical]
        family = (
            lic.LICENSE_FAMILY.get(canonical, lic.UNKNOWN)
            if canonical != "NOASSERTION"
            else lic.UNKNOWN
        )

    effective_verdict = judgement["verdict"]
    exception_info = None
    if exc and judgement["verdict"] in (pol.DENY, pol.REVIEW):
        exception_info = {
            "approved": True,
            "note": exc.get("note", ""),
            "approved_at": exc.get("approved_at", ""),
            "original_verdict": judgement["verdict"],
            "rule": judgement["rule"],
            "distribution": exc.get("distribution", ""),
        }
        effective_verdict = "exception"

    return {
        "id": pkg.key,
        "name": pkg.name,
        "version": pkg.version,
        "license_raw": pkg.license_raw,
        "license": canonical,
        "license_members": members,
        "family": family,
        "direct": is_direct,
        "depth": depth,
        "reachable": path is not None,
        "shortest_path": path or [],
        "dependencies": list(graph.edges.get(pkg.key, [])),
        "verdict": effective_verdict,  # allow / deny / review / exception
        "base_verdict": judgement["verdict"],
        "severity": judgement["severity"],
        "rule": judgement["rule"],
        "rule_kind": judgement["rule"].split(":", 1)[0],
        "message": judgement["message"],
        "exception": exception_info,
    }


def _sort_packages(package_results: List[dict]) -> None:
    # 冲突在前（deny > review > 其他），其次按深度、名字
    order = {"deny": 0, "review": 1, "exception": 2, "allow": 3}
    package_results.sort(
        key=lambda p: (
            order.get(p["verdict"], 9),
            p["depth"] if p["depth"] is not None else 999,
            p["id"],
        )
    )


def analyze(
    data: dict,
    policy: pol.Policy,
    license_override: Optional[str] = None,
    exceptions=None,
) -> dict:
    """执行完整分析，返回可序列化的结果字典。

    ``exceptions`` 支持旧版字典或新版记录列表（含 ``rule`` / ``distribution``）。
    清单含 ``distributions`` 时返回多制品结果（``mode == "multi"``），
    否则保持单制品结果（``mode == "single"``）。
    """
    graph = build_graph(data, policy, license_override)
    cycles = detect_cycles(graph)
    exc_rows = _normalize_exceptions(exceptions)

    if graph.multi:
        return _analyze_multi(graph, policy, cycles, exc_rows)
    return _analyze_single(graph, policy, cycles, exc_rows)


def _result_envelope(graph: Graph, policy: pol.Policy, cycles: List[List[str]]) -> dict:
    return {
        "project": {
            "name": graph.project.get("name", "未命名项目"),
            "version": graph.project.get("version", ""),
        },
        "project_license": graph.project_license,
        "policy_key": policy.key,
        "policy": policy.to_dict(),
        "edges": [
            {"from": src, "to": dst}
            for src, targets in graph.edges.items()
            for dst in targets
        ],
        "cycles": cycles,
        "unresolved_refs": graph.unresolved_refs,
    }


def _analyze_single(
    graph: Graph, policy: pol.Policy, cycles: List[List[str]], exc_rows: List[dict]
) -> dict:
    paths = shortest_paths(graph)
    root_set = set(graph.roots)
    package_results: List[dict] = []
    summary = _empty_summary()

    for key, pkg in graph.packages.items():
        path = paths[key]
        # 先取规则再匹配例外（单制品模式按 package_id 匹配）
        probe = pol.judge(graph.project_license, pkg.license_raw, policy)
        exc = _match_exception(exc_rows, key, probe["rule"], multi=False)
        entry = _build_package_entry(
            pkg, graph, graph.project_license, policy, path, root_set, exc
        )
        summary["total"] += 1
        if entry["verdict"] == "exception":
            summary["exceptions"] += 1
        else:
            summary[entry["verdict"]] = summary.get(entry["verdict"], 0) + 1
        if entry["base_verdict"] in (pol.DENY, pol.REVIEW) and entry["verdict"] != "exception":
            summary["conflicts"] += 1
        package_results.append(entry)

    _sort_packages(package_results)
    conflicts = [p for p in package_results if p["verdict"] in ("deny", "review")]

    result = _result_envelope(graph, policy, cycles)
    result.update(
        {
            "mode": "single",
            "summary": summary,
            "packages": package_results,
            "conflicts": conflicts,
            "roots": graph.roots,
        }
    )
    return result


def _analyze_multi(
    graph: Graph, policy: pol.Policy, cycles: List[List[str]], exc_rows: List[dict]
) -> dict:
    """多制品分析：同一依赖图上分别从各制品根遍历、按各制品许可证判定。"""
    dist_results: List[dict] = []
    # key -> {dist_name -> package entry}，仅记录该制品可达的包
    reachable_map: Dict[str, Dict[str, dict]] = {key: {} for key in graph.packages}

    for dist in graph.distributions:
        paths = shortest_paths(graph, dist.roots)
        root_set = set(dist.roots)
        package_results: List[dict] = []
        summary = _empty_summary()

        for key, pkg in graph.packages.items():
            path = paths[key]
            if path is None:
                continue  # 多制品模式只统计该制品可达的包
            probe = pol.judge(dist.project_license, pkg.license_raw, policy)
            exc = _match_exception(exc_rows, key, probe["rule"], multi=True)
            entry = _build_package_entry(
                pkg, graph, dist.project_license, policy, path, root_set, exc
            )
            summary["total"] += 1
            if entry["verdict"] == "exception":
                summary["exceptions"] += 1
            else:
                summary[entry["verdict"]] = summary.get(entry["verdict"], 0) + 1
            if entry["base_verdict"] in (pol.DENY, pol.REVIEW) and entry["verdict"] != "exception":
                summary["conflicts"] += 1
            package_results.append(entry)
            reachable_map[key][dist.name] = entry

        _sort_packages(package_results)
        dist_results.append(
            {
                "name": dist.name,
                "project_license": dist.project_license,
                "roots": list(dist.roots),
                "unresolved_roots": list(dist.unresolved_roots),
                "summary": summary,
                "packages": package_results,
                "conflicts": [p for p in package_results if p["verdict"] in ("deny", "review")],
            }
        )

    overview = _build_overview(graph, dist_results, reachable_map)

    result = _result_envelope(graph, policy, cycles)
    result.update(
        {
            "mode": "multi",
            "roots": graph.roots,
            "distributions": dist_results,
            "overview": overview,
            "unreachable_packages": [
                key for key, per in reachable_map.items() if not per
            ],
        }
    )
    return result


def _build_overview(
    graph: Graph,
    dist_results: List[dict],
    reachable_map: Dict[str, Dict[str, dict]],
) -> dict:
    """按最严重结论跨制品聚合，并列出每个包受影响的制品。"""
    dist_names = [d["name"] for d in dist_results]
    overview_packages: List[dict] = []
    summary = _empty_summary()
    summary["unreachable"] = 0
    summary["distributions"] = len(dist_results)
    exception_applications = 0

    for key, pkg in graph.packages.items():
        per_dist = reachable_map[key]
        if not per_dist:
            # 对任何制品都不可达（孤立环 / 未被引用）
            summary["unreachable"] += 1
            if _is_compound(pkg.license_raw):
                canonical = lic.canonicalize(pkg.license_raw)
                family = "expression"
            else:
                canonical = lic.canonicalize(pkg.license_raw)
                family = (
                    lic.LICENSE_FAMILY.get(canonical, lic.UNKNOWN)
                    if canonical != "NOASSERTION"
                    else lic.UNKNOWN
                )
            overview_packages.append(
                {
                    "id": key,
                    "name": pkg.name,
                    "version": pkg.version,
                    "license_raw": pkg.license_raw,
                    "license": canonical,
                    "family": family,
                    "verdict": "unreachable",
                    "base_verdict": None,
                    "rule": "",
                    "rule_kind": "",
                    "message": "",
                    "severity": "",
                    "reachable": False,
                    "affected": [],
                }
            )
            continue

        # 最严重结论的制品作为聚合代表
        reachable_names = [n for n in dist_names if n in per_dist]
        worst_name = min(
            reachable_names,
            key=lambda n: _VERDICT_ORDER.get(per_dist[n]["verdict"], 9),
        )
        worst = per_dist[worst_name]
        affected = [
            {
                "distribution": name,
                "verdict": per_dist[name]["verdict"],
                "base_verdict": per_dist[name]["base_verdict"],
                "rule": per_dist[name]["rule"],
                "rule_kind": per_dist[name]["rule_kind"],
                "message": per_dist[name]["message"],
                "severity": per_dist[name]["severity"],
                "depth": per_dist[name]["depth"],
                "direct": per_dist[name]["direct"],
                "shortest_path": per_dist[name]["shortest_path"],
                "exception": per_dist[name]["exception"],
            }
            for name in dist_names
            if name in per_dist
        ]
        exception_applications += sum(1 for a in affected if a["exception"])

        summary["total"] += 1
        if worst["verdict"] == "exception":
            summary["exceptions"] += 1
        else:
            summary[worst["verdict"]] = summary.get(worst["verdict"], 0) + 1
        if worst["verdict"] in ("deny", "review"):
            summary["conflicts"] += 1

        overview_packages.append(
            {
                "id": key,
                "name": pkg.name,
                "version": pkg.version,
                "license_raw": pkg.license_raw,
                "license": worst["license"],
                "family": worst["family"],
                "verdict": worst["verdict"],
                "base_verdict": worst["base_verdict"],
                "rule": worst["rule"],
                "rule_kind": worst["rule_kind"],
                "message": worst["message"],
                "severity": worst["severity"],
                "reachable": True,
                "affected": affected,
            }
        )

    overview_packages.sort(
        key=lambda p: (
            _VERDICT_ORDER.get(p["verdict"], 9),
            p["id"],
        )
    )
    summary["exception_applications"] = exception_applications
    return {
        "summary": summary,
        "packages": overview_packages,
        "conflicts": [p for p in overview_packages if p["verdict"] in ("deny", "review")],
        "distribution_names": dist_names,
    }
