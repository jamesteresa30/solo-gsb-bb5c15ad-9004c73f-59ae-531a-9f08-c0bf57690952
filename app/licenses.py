"""SPDX 风格许可证标识、表达式解析与兼容性矩阵。

兼容性矩阵的语义：行是"项目许可证（派生作品的分发许可证）"，
列是"依赖许可证"。值为:

* ``allow``  —— 该依赖许可证与项目许可证兼容；
* ``deny``   —— 明确不兼容（强 copyleft 冲突等）；
* ``review``  —— 未被矩阵覆盖 / 未知组合，需要法务人工审查。

矩阵依据各许可证的常见理解整理（GPL/AGPL 的单向兼容、
MPL 的文件级弱 copyleft、LGPL 的库例外等），仅用于工程辅助，
不构成法律意见。
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# 已知许可证（规范化后的标识）
# ---------------------------------------------------------------------------

#: 判定结论
ALLOW = "allow"
DENY = "deny"
REVIEW = "review"

#: 宽松型
PERMISSIVE = "permissive"
#: 弱 copyleft（文件级 / 库级）
WEAK_COPYLEFT = "weak_copyleft"
#: 强 copyleft
STRONG_COPYLEFT = "strong_copyleft"
#: 网络强 copyleft
NETWORK_COPYLEFT = "network_copyleft"
#: 公共领域 / 近似公共领域
PUBLIC_DOMAIN = "public_domain"
#: 商业专有
PROPRIETARY = "proprietary"
#: 未知 / 自定义
UNKNOWN = "unknown"

#: SPDX 标识 -> 规范化标识
ALIASES: Dict[str, str] = {
    "mit": "MIT",
    "apache-2.0": "Apache-2.0",
    "apache2": "Apache-2.0",
    "apache2.0": "Apache-2.0",
    "apache license 2.0": "Apache-2.0",
    "bsd-2-clause": "BSD-2-Clause",
    "bsd2": "BSD-2-Clause",
    "bsd-3-clause": "BSD-3-Clause",
    "bsd3": "BSD-3-Clause",
    "new bsd": "BSD-3-Clause",
    "isc": "ISC",
    "zlib": "Zlib",
    "unlicense": "Unlicense",
    "cc0-1.0": "CC0-1.0",
    "cc0": "CC0-1.0",
    "mpl-2.0": "MPL-2.0",
    "mpl2.0": "MPL-2.0",
    "mpl": "MPL-2.0",
    "mozilla public license 2.0": "MPL-2.0",
    "lgpl-2.1": "LGPL-2.1",
    "lgpl-2.1-only": "LGPL-2.1",
    "lgpl-2.1-or-later": "LGPL-2.1",
    "lgpl2.1": "LGPL-2.1",
    "lgpl-3.0": "LGPL-3.0",
    "lgpl-3.0-only": "LGPL-3.0",
    "lgpl-3.0-or-later": "LGPL-3.0",
    "lgpl3": "LGPL-3.0",
    "lgpl": "LGPL-3.0",
    "gpl-2.0": "GPL-2.0",
    "gpl-2.0-only": "GPL-2.0",
    "gpl-2.0-or-later": "GPL-2.0",
    "gpl2": "GPL-2.0",
    "gpl-3.0": "GPL-3.0",
    "gpl-3.0-only": "GPL-3.0",
    "gpl-3.0-or-later": "GPL-3.0",
    "gpl3": "GPL-3.0",
    "gpl": "GPL-3.0",
    "agpl-3.0": "AGPL-3.0",
    "agpl-3.0-only": "AGPL-3.0",
    "agpl-3.0-or-later": "AGPL-3.0",
    "agpl3": "AGPL-3.0",
    "agpl": "AGPL-3.0",
    "commercial": "Proprietary",
    "proprietary": "Proprietary",
    "see license in file": "NOASSERTION",
    "noassertion": "NOASSERTION",
}

#: 规范化标识 -> 许可证家族
LICENSE_FAMILY: Dict[str, str] = {
    "MIT": PERMISSIVE,
    "Apache-2.0": PERMISSIVE,
    "BSD-2-Clause": PERMISSIVE,
    "BSD-3-Clause": PERMISSIVE,
    "ISC": PERMISSIVE,
    "Zlib": PERMISSIVE,
    "Unlicense": PUBLIC_DOMAIN,
    "CC0-1.0": PUBLIC_DOMAIN,
    "MPL-2.0": WEAK_COPYLEFT,
    "LGPL-2.1": WEAK_COPYLEFT,
    "LGPL-3.0": WEAK_COPYLEFT,
    "GPL-2.0": STRONG_COPYLEFT,
    "GPL-3.0": STRONG_COPYLEFT,
    "AGPL-3.0": NETWORK_COPYLEFT,
    "Proprietary": PROPRIETARY,
}

KNOWN_LICENSES: Set[str] = set(LICENSE_FAMILY)

# ---------------------------------------------------------------------------
# 兼容性矩阵（行：项目许可证，列：依赖许可证）
# ---------------------------------------------------------------------------

P = "permissive"  # MIT / BSD-2 / BSD-3 / ISC / Zlib
AL = "Apache-2.0"
MPL = "MPL-2.0"
L21 = "LGPL-2.1"
L3 = "LGPL-3.0"
G2 = "GPL-2.0"
G3 = "GPL-3.0"
AG3 = "AGPL-3.0"
PD = "public-domain"  # Unlicense / CC0
PROP = "Proprietary"

_DEPGROUPS: List[Tuple[str, Tuple[str, ...]]] = [
    (PD, ("Unlicense", "CC0-1.0")),
    (P, ("MIT", "BSD-2-Clause", "BSD-3-Clause", "ISC", "Zlib")),
    (AL, (AL,)),
    (MPL, (MPL,)),
    (L21, (L21,)),
    (L3, (L3,)),
    (G2, (G2,)),
    (G3, (G3,)),
    (AG3, (AG3,)),
    (PROP, (PROP,)),
]

#: 每个项目许可证行: dep-group -> (结论, 说明模板)
_ROWS: Dict[str, Dict[str, Tuple[str, str]]] = {
    P: {
        PD: ("allow", "公共领域许可证可被任意使用"),
        P: ("allow", "宽松许可证与宽松项目兼容（需保留版权与许可声明）"),
        AL: ("allow", "Apache-2.0 可在 MIT 类项目中使用（需保留 NOTICE）"),
        MPL: ("allow", "MPL-2.0 文件级 copyleft，不影响项目其余代码的许可证"),
        L21: ("review", "LGPL 要求允许用户替换该库，动态/静态链接方式需法务确认"),
        L3: ("review", "LGPL 要求允许用户替换该库，动态/静态链接方式需法务确认"),
        G2: ("deny", "GPL-2.0 强 copyleft：作为依赖进入派生作品后整体须按 GPL-2.0 分发"),
        G3: ("deny", "GPL-3.0 强 copyleft：作为依赖进入派生作品后整体须按 GPL-3.0 分发"),
        AG3: ("deny", "AGPL-3.0 网络强 copyleft：即使仅通过网络提供服务也须开源整体源码"),
        PROP: ("review", "专有许可证条款各异，需逐条确认商用条款"),
    },
    AL: {
        PD: ("allow", "公共领域许可证可被任意使用"),
        P: ("allow", "宽松许可证与 Apache-2.0 兼容（需保留版权声明）"),
        AL: ("allow", "Apache-2.0 与自身兼容（需保留 NOTICE）"),
        MPL: ("allow", "MPL-2.0 与 Apache-2.0 兼容（MPL 2.0 明确允许与宽松许可结合）"),
        L21: ("review", "LGPL 链接/替换义务需法务确认；GPLv2 系与 Apache-2.0 专利条款存在已知争议"),
        L3: ("review", "LGPL-3.0 要求允许用户替换该库，链接方式需法务确认"),
        G2: ("deny", "Apache-2.0 与 GPL-2.0 单向不兼容（专利条款冲突），无法合入 GPL-2.0 作品"),
        G3: ("allow", "GPL-3.0 明确兼容 Apache-2.0（整体可按 GPL-3.0 分发，需注意许可证升级）"),
        AG3: ("allow", "AGPL-3.0 明确兼容 Apache-2.0（整体将受 AGPL-3.0 约束，含网络开源义务）"),
        PROP: ("review", "专有许可证条款各异，需逐条确认商用条款"),
    },
    MPL: {
        PD: ("allow", "公共领域许可证可被任意使用"),
        P: ("allow", "宽松许可证代码可与 MPL 文件共存"),
        AL: ("allow", "Apache-2.0 与 MPL-2.0 兼容（需保留 NOTICE）"),
        MPL: ("allow", "MPL-2.0 与自身兼容（修改过的 MPL 文件须继续以 MPL 开源）"),
        L21: ("review", "MPL 与 LGPL 同时使用时各自义务叠加，建议法务确认"),
        L3: ("review", "MPL 与 LGPL 同时使用时各自义务叠加，建议法务确认"),
        G2: ("allow", "MPL-2.0 设计上可与 GPL 结合（GPL 接管整体许可，MPL 文件保持 MPL）"),
        G3: ("allow", "MPL-2.0 设计上可与 GPL 结合（GPL 接管整体许可，MPL 文件保持 MPL）"),
        AG3: ("allow", "可与 AGPL-3.0 结合，但整体将受 AGPL 网络开源义务约束"),
        PROP: ("review", "专有代码可与 MPL 文件共存，但修改 MPL 文件部分仍须开源，需法务确认边界"),
    },
    L21: {
        PD: ("allow", "公共领域许可证可被任意使用"),
        P: ("allow", "宽松许可证与 LGPL 作品兼容（需保留版权声明）"),
        AL: ("review", "LGPL-2.1 基于 GPLv2，与 Apache-2.0 专利条款存在争议，建议升级 LGPL 或法务确认"),
        MPL: ("review", "MPL 与 LGPL 义务叠加，建议法务确认"),
        L21: ("allow", "LGPL-2.1 与自身版本兼容"),
        L3: ("review", "LGPL 版本混用（2.1 vs 3.0）需按各库声明的版本条款确认"),
        G2: ("allow", "LGPL-2.1 可在 GPL-2.0 作品中使用（GPL 接管整体许可）"),
        G3: ("review", "LGPL-2.1 库需支持「或更高版本」声明才可重许可以配合 GPL-3.0"),
        AG3: ("review", "LGPL 与 AGPL 结合后网络开源义务如何叠加需法务确认"),
        PROP: ("review", "专有程序可按 LGPL 方式链接该库，但须允许用户替换库并提供相关材料"),
    },
    L3: {
        PD: ("allow", "公共领域许可证可被任意使用"),
        P: ("allow", "宽松许可证与 LGPL 作品兼容（需保留版权声明）"),
        AL: ("allow", "LGPL-3.0 基于 GPLv3，兼容 Apache-2.0"),
        MPL: ("review", "MPL 与 LGPL 义务叠加，建议法务确认"),
        L21: ("review", "LGPL 版本混用（2.1 vs 3.0）需按各库声明的版本条款确认"),
        L3: ("allow", "LGPL-3.0 与自身版本兼容"),
        G2: ("deny", "GPL-3.0 系不向下兼容 GPL-2.0 only；GPL-2.0 only 依赖会与 LGPL-3.0 作品冲突"),
        G3: ("allow", "LGPL-3.0 可在 GPL-3.0 作品中使用（GPL 接管整体许可）"),
        AG3: ("allow", "LGPL-3.0 可在 AGPL-3.0 作品中使用（AGPL 网络开源义务覆盖整体）"),
        PROP: ("review", "专有程序可按 LGPL 方式链接该库，但须允许用户替换库并提供相关材料"),
    },
    G2: {
        PD: ("allow", "公共领域许可证可被任意使用"),
        P: ("allow", "宽松许可证代码可被 GPL-2.0 作品吸收"),
        AL: ("deny", "Apache-2.0 与 GPL-2.0 单向不兼容（专利条款冲突）"),
        MPL: ("allow", "MPL-2.0 可与 GPL-2.0 结合（MPL 文件保持 MPL）"),
        L21: ("allow", "LGPL-2.1 兼容 GPL-2.0 作品"),
        L3: ("deny", "LGPL-3.0（GPLv3 系）不能与 GPL-2.0 only 作品结合"),
        G2: ("allow", "GPL-2.0 与自身兼容"),
        G3: ("deny", "GPL-2.0 only 不能与 GPL-3.0 结合（除非声明了 or-later）"),
        AG3: ("deny", "AGPL-3.0 与 GPL-2.0 only 不兼容"),
        PROP: ("deny", "GPL-2.0 强 copyleft 与专有分发不能共存于同一派生作品"),
    },
    G3: {
        PD: ("allow", "公共领域许可证可被任意使用"),
        P: ("allow", "宽松许可证代码可被 GPL-3.0 作品吸收"),
        AL: ("allow", "GPL-3.0 明确兼容 Apache-2.0"),
        MPL: ("allow", "MPL-2.0 可与 GPL-3.0 结合"),
        L21: ("review", "LGPL-2.1 需带有「或更高版本」声明才可配合 GPL-3.0"),
        L3: ("allow", "LGPL-3.0 兼容 GPL-3.0 作品"),
        G2: ("review", "GPL-2.0 依赖若声明 or-later 可升级至 GPL-3.0，否则不兼容"),
        G3: ("allow", "GPL-3.0 与自身兼容"),
        AG3: ("allow", "GPL-3.0 与 AGPL-3.0 兼容，但整体须按 AGPL-3.0 分发（含网络开源义务）"),
        PROP: ("deny", "GPL-3.0 强 copyleft 与专有分发不能共存于同一派生作品"),
    },
    AG3: {
        PD: ("allow", "公共领域许可证可被任意使用"),
        P: ("allow", "宽松许可证代码可被 AGPL-3.0 作品吸收"),
        AL: ("allow", "AGPL-3.0 明确兼容 Apache-2.0"),
        MPL: ("allow", "MPL-2.0 可与 AGPL-3.0 结合"),
        L21: ("review", "LGPL-2.1 需带有「或更高版本」声明才可配合 AGPL-3.0"),
        L3: ("allow", "LGPL-3.0 兼容 AGPL-3.0 作品"),
        G2: ("deny", "GPL-2.0 only 与 AGPL-3.0 不兼容"),
        G3: ("allow", "GPL-3.0 可与 AGPL-3.0 结合（整体按 AGPL-3.0 分发）"),
        AG3: ("allow", "AGPL-3.0 与自身兼容"),
        PROP: ("deny", "AGPL-3.0 网络强 copyleft 与专有分发不能共存，SaaS 场景同样触发开源义务"),
    },
    PROP: {
        PD: ("allow", "公共领域许可证可被任意使用"),
        P: ("allow", "宽松许可证可在专有产品中使用（需保留版权与许可声明）"),
        AL: ("allow", "Apache-2.0 可在专有产品中使用（需保留 NOTICE、承担专利授权条款）"),
        MPL: ("review", "MPL-2.0 修改文件须开源，专有产品须确保仅以未修改方式引用并隔离文件边界"),
        L21: ("deny", "LGPL 要求允许最终用户替换该库并获取链接所需材料，多数专有静态分发场景无法满足"),
        L3: ("deny", "LGPL 要求允许最终用户替换该库并获取链接所需材料，多数专有静态分发场景无法满足"),
        G2: ("deny", "GPL-2.0 强 copyleft 禁止与专有派生作品一同分发"),
        G3: ("deny", "GPL-3.0 强 copyleft 禁止与专有派生作品一同分发"),
        AG3: ("deny", "AGPL-3.0 在 SaaS 场景同样触发整体开源义务，禁止与专有产品结合"),
        PROP: ("review", "第三方专有许可证条款各异，需逐条确认商用条款"),
    },
}


def _build_matrix() -> Dict[str, Dict[str, Tuple[str, str]]]:
    matrix: Dict[str, Dict[str, Tuple[str, str]]] = {}
    for row_key, row in _ROWS.items():
        # 行分组键 -> 该组内的全部真实项目许可证
        row_members = next(members for group, members in _DEPGROUPS if group == row_key)
        expanded: Dict[str, Tuple[str, str]] = {}
        for group_key, members in _DEPGROUPS:
            verdict, note = row[group_key]
            for member in members:
                expanded[member] = (verdict, note)
        for project_license in row_members:
            matrix[project_license] = dict(expanded)
    return matrix


MATRIX: Dict[str, Dict[str, Tuple[str, str]]] = _build_matrix()

#: 项目许可证下拉选项（矩阵中存在的行）
PROJECT_LICENSE_OPTIONS: List[str] = [
    "MIT",
    "Apache-2.0",
    "MPL-2.0",
    "LGPL-2.1",
    "LGPL-3.0",
    "GPL-2.0",
    "GPL-3.0",
    "AGPL-3.0",
    "Proprietary",
]

# ---------------------------------------------------------------------------
# 许可证规范化 / 表达式解析
# ---------------------------------------------------------------------------


def canonicalize(raw: Optional[str]) -> str:
    """把清单中可能出现的许可证字符串规范化为 SPDX 标识。

    无法识别时返回 ``NOASSERTION``。
    """
    if not raw:
        return "NOASSERTION"
    key = raw.strip()
    if key in KNOWN_LICENSES:
        return key
    folded = key.lower()
    if folded in ALIASES:
        return ALIASES[folded]
    return "NOASSERTION"


# --- 极简 SPDX 复合表达式解析（支持 ( ) AND OR WITH，标识符宽松匹配） ---


@dataclass
class Expr:
    op: str  # "license" | "and" | "or"
    value: str = ""
    children: Tuple["Expr", ...] = ()


class LicenseExpressionError(ValueError):
    """许可证表达式无法解析。"""


_TOKEN_AND = "__AND__"
_TOKEN_OR = "__OR__"
_TOKEN_LP = "__LP__"
_TOKEN_RP = "__RP__"


def _tokenize(text: str) -> List[str]:
    tokens: List[str] = []
    i = 0
    while i < len(text):
        ch = text[i]
        if ch.isspace():
            i += 1
        elif ch == "(":
            tokens.append(_TOKEN_LP)
            i += 1
        elif ch == ")":
            tokens.append(_TOKEN_RP)
            i += 1
        else:
            start = i
            while i < len(text) and not text[i].isspace() and text[i] not in "()":
                i += 1
            word = text[start:i]
            upper = word.upper()
            if upper == "AND":
                tokens.append(_TOKEN_AND)
            elif upper == "OR":
                tokens.append(_TOKEN_OR)
            elif upper == "WITH":
                # 跳过 "WITH <exception>"，等价于去掉例外
                i += 1
                while i < len(text) and text[i].isspace():
                    i += 1
                while i < len(text) and not text[i].isspace() and text[i] not in "()":
                    i += 1
            else:
                tokens.append(word)
    return tokens


def _parse_expr(tokens: List[str]) -> Expr:
    pos = 0

    def parse_atom() -> Expr:
        nonlocal pos
        if pos >= len(tokens):
            raise LicenseExpressionError("表达式意外结束")
        tok = tokens[pos]
        if tok == _TOKEN_LP:
            pos += 1
            node = parse_or()
            if pos >= len(tokens) or tokens[pos] != _TOKEN_RP:
                raise LicenseExpressionError("缺少右括号")
            pos += 1
            return node
        if tok in (_TOKEN_AND, _TOKEN_OR, _TOKEN_RP):
            raise LicenseExpressionError(f"意外的 token: {tok}")
        pos += 1
        return Expr(op="license", value=tok)

    def parse_and() -> Expr:
        nonlocal pos
        node = parse_atom()
        values: List[Expr] = [node]
        while pos < len(tokens) and tokens[pos] == _TOKEN_AND:
            pos += 1
            values.append(parse_atom())
        if len(values) == 1:
            return node
        return Expr(op="and", children=tuple(values))

    def parse_or() -> Expr:
        nonlocal pos
        node = parse_and()
        values: List[Expr] = [node]
        while pos < len(tokens) and tokens[pos] == _TOKEN_OR:
            pos += 1
            values.append(parse_and())
        if len(values) == 1:
            return node
        return Expr(op="or", children=tuple(values))

    result = parse_or()
    if pos != len(tokens):
        raise LicenseExpressionError("表达式存在多余 token（括号不匹配？）")
    return result


def parse_expression(raw: Optional[str]) -> Expr:
    """解析 SPDX 风格许可证表达式，如 ``(MIT OR Apache-2.0) AND BSD-3-Clause``。"""
    text = (raw or "").strip()
    if not text:
        return Expr(op="license", value="")
    return _parse_expr(_tokenize(text))


def expression_licenses(raw: Optional[str]) -> List[str]:
    """展开表达式中出现的全部规范化许可证标识。"""
    root = parse_expression(raw)
    found: List[str] = []

    def walk(node: Expr) -> None:
        if node.op == "license":
            found.append(canonicalize(node.value))
        else:
            for child in node.children:
                walk(child)

    walk(root)
    return found


def evaluate_expression(raw: Optional[str], project_license: str) -> Tuple[str, str, List[str]]:
    """对复合表达式做兼容性求值。

    语义：
    * ``OR``  —— 被许可方可以选择，取其中**最兼容**的分支；
    * ``AND`` —— 所有条款同时适用，取其中**最严格**的分支。

    返回 ``(结论, 命中的许可证, 参与判断的许可证列表)``。
    """
    root = parse_expression(raw)

    def eval_node(node: Expr) -> Tuple[str, str]:
        if node.op == "license":
            lic = canonicalize(node.value)
            return compatibility(project_license, lic), lic
        results = [eval_node(c) for c in node.children]
        if node.op == "or":
            order = {"allow": 0, "review": 1, "deny": 2}
            best = min(results, key=lambda r: order[r[0]])
            return best
        # AND：最严格者生效
        order = {"deny": 0, "review": 1, "allow": 2}
        worst = min(results, key=lambda r: order[r[0]])
        return worst

    verdict, hit = eval_node(root)
    return verdict, hit, expression_licenses(raw)


def compatibility(project_license: str, dep_license: str) -> str:
    """返回 ``allow`` / ``deny`` / ``review``。"""
    row = MATRIX.get(project_license)
    if row is None:
        return "review"
    cell = row.get(dep_license)
    if cell is None:
        return "review"
    return cell[0]


def compatibility_note(project_license: str, dep_license: str) -> str:
    row = MATRIX.get(project_license) or {}
    cell = row.get(dep_license)
    return cell[1] if cell else "许可证组合不在内置兼容矩阵中，需要人工审查"
