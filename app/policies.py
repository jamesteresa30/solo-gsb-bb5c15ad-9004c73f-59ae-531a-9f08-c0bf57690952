"""项目许可策略。

策略在兼容矩阵之上叠加两层规则：

1. ``deny``  —— 不论矩阵结论如何，命中许可证家族即判冲突（最高优先级）；
2. ``allow`` —— 矩阵给出 ``review`` 时可被策略放行（矩阵明确 ``deny`` 不覆盖）。

矩阵明确的 ``deny`` 永远不会被策略降级，避免误放行强 copyleft 冲突；
``NOASSERTION``（无法识别/未声明）由策略的 unknown 处理方式决定。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

from . import licenses as lic

# 结论常量
ALLOW = "allow"
DENY = "deny"
REVIEW = "review"

SEVERITY_ERROR = "error"
SEVERITY_WARNING = "warning"


@dataclass(frozen=True)
class Policy:
    key: str
    name: str
    description: str
    default_project_license: str
    #: 命中即冲突的许可证家族
    deny_families: frozenset[str] = field(default_factory=frozenset)
    #: 矩阵 review 时允许放行的许可证家族
    allow_families: frozenset[str] = field(default_factory=frozenset)
    #: 无法识别许可证（NOASSERTION）时的结论
    unknown_verdict: str = REVIEW
    #: 项目许可证可选范围
    allowed_project_licenses: tuple[str, ...] = tuple(lic.PROJECT_LICENSE_OPTIONS)

    def to_dict(self) -> dict:
        return {
            "key": self.key,
            "name": self.name,
            "description": self.description,
            "default_project_license": self.default_project_license,
            "deny_families": sorted(self.deny_families),
            "allow_families": sorted(self.allow_families),
            "unknown_verdict": self.unknown_verdict,
            "allowed_project_licenses": list(self.allowed_project_licenses),
        }


PERMISSIVE = Policy(
    key="permissive",
    name="宽松商业友好",
    description=(
        "项目以宽松许可证（默认 MIT）发布。允许一切宽松许可证与 MPL；"
        "LGPL 链接方式需人工确认；GPL/AGPL 等强 copyleft 与专有许可一律拒绝。"
    ),
    default_project_license="MIT",
    deny_families=frozenset(
        {lic.STRONG_COPYLEFT, lic.NETWORK_COPYLEFT, lic.PROPRIETARY}
    ),
    allow_families=frozenset({lic.WEAK_COPYLEFT}),
    unknown_verdict=REVIEW,
    allowed_project_licenses=("MIT", "Apache-2.0"),
)

COPYLEFT = Policy(
    key="copyleft",
    name="Copyleft 开放专享",
    description=(
        "项目以 GPL-3.0 发布，要求派生作品保持开源。允许宽松许可证与 GPL/AGPL/LGPL 系；"
        "专有许可证与 Apache-2.0 入 GPL-2.0 等已知不兼容组合会被拒绝。"
    ),
    default_project_license="GPL-3.0",
    deny_families=frozenset({lic.PROPRIETARY}),
    allow_families=frozenset(),
    unknown_verdict=REVIEW,
    allowed_project_licenses=(
        "GPL-2.0",
        "GPL-3.0",
        "AGPL-3.0",
        "LGPL-2.1",
        "LGPL-3.0",
        "MPL-2.0",
    ),
)

STRICT = Policy(
    key="strict",
    name="严格白名单",
    description=(
        "仅允许 MIT/BSD/ISC/Apache-2.0 等宽松许可证及公共领域许可证；"
        "任何 copyleft（含 MPL/LGPL）、专有或许可证无法识别的包一律拒绝。"
    ),
    default_project_license="MIT",
    deny_families=frozenset(
        {
            lic.WEAK_COPYLEFT,
            lic.STRONG_COPYLEFT,
            lic.NETWORK_COPYLEFT,
            lic.PROPRIETARY,
            lic.UNKNOWN,
        }
    ),
    allow_families=frozenset(),
    unknown_verdict=DENY,
    allowed_project_licenses=("MIT", "Apache-2.0"),
)

PROP_COMMERCIAL = Policy(
    key="proprietary",
    name="专有闭源商业",
    description=(
        "项目以专有许可证分发。仅允许宽松许可证与 Apache-2.0；"
        "LGPL/GPL/AGPL 一律拒绝；MPL 与第三方专有许可证需人工确认。"
    ),
    default_project_license="Proprietary",
    deny_families=frozenset(
        {
            lic.WEAK_COPYLEFT,
            lic.STRONG_COPYLEFT,
            lic.NETWORK_COPYLEFT,
        }
    ),
    allow_families=frozenset(),
    unknown_verdict=REVIEW,
    allowed_project_licenses=("Proprietary",),
)

POLICIES: Dict[str, Policy] = {
    p.key: p for p in (PERMISSIVE, COPYLEFT, STRICT, PROP_COMMERCIAL)
}

DEFAULT_POLICY = PERMISSIVE.key

#: 触发规则前缀，便于前端/导出区分
RULE_MATRIX = "MATRIX"
RULE_POLICY_DENY = "POLICY_DENY"
RULE_POLICY_ALLOW = "POLICY_ALLOW"
RULE_UNKNOWN = "UNKNOWN_LICENSE"


def list_policies() -> List[dict]:
    return [p.to_dict() for p in POLICIES.values()]


def get_policy(key: str | None) -> Policy:
    if key and key in POLICIES:
        return POLICIES[key]
    return POLICIES[DEFAULT_POLICY]


def judge(
    project_license: str,
    dep_license: str,
    policy: Policy,
) -> dict:
    """对单个（可能是复合表达式的）许可证给出判定。

    返回::

        {"verdict": "allow|deny|review", "severity": "warning|error|",
         "rule": "MATRIX:...", "trigger_license": "GPL-3.0",
         "message": "..."}
    """
    # 1. 复合表达式：先在矩阵语义下求值
    raw_is_expression = any(
        tok in (dep_license or "") for tok in (" OR ", " AND ", "(", ")")
    )
    if raw_is_expression:
        verdict, hit_license, _members = lic.evaluate_expression(
            dep_license, project_license
        )
        matrix_note = lic.compatibility_note(project_license, hit_license)
        display = dep_license
    else:
        hit_license = lic.canonicalize(dep_license)
        verdict = lic.compatibility(project_license, hit_license)
        matrix_note = lic.compatibility_note(project_license, hit_license)
        display = hit_license

    # 2. 策略判定以“实际生效的许可证” hit_license 为准：
    #    OR 表达式被许可方可择一，选到兼容分支后即等同于该单许可证；
    #    AND 表达式取到的是最严格分支，其家族自然是最严格家族。
    if hit_license == "NOASSERTION":
        if policy.unknown_verdict == DENY:
            return {
                "verdict": DENY,
                "severity": SEVERITY_ERROR,
                "rule": f"{RULE_UNKNOWN}: 策略「{policy.name}」不允许无法识别的许可证",
                "trigger_license": display,
                "message": f"许可证 {display!r} 无法识别为已知 SPDX 标识，严格白名单策略下按冲突处理",
            }
        if lic.UNKNOWN in policy.deny_families:
            return {
                "verdict": DENY,
                "severity": SEVERITY_ERROR,
                "rule": f"{RULE_POLICY_DENY}:unknown",
                "trigger_license": display,
                "message": "许可证无法识别，且策略禁止未知许可证",
            }
        return {
            "verdict": REVIEW,
            "severity": SEVERITY_WARNING,
            "rule": f"{RULE_UNKNOWN}: 不在内置矩阵中",
            "trigger_license": display,
            "message": f"许可证 {display!r} 无法识别为已知 SPDX 标识，需要人工确认",
        }

    family = lic.LICENSE_FAMILY.get(hit_license, lic.UNKNOWN)

    # 3. 策略禁止家族优先于矩阵结论（矩阵 allow 也可被策略升级为 deny）
    if family in policy.deny_families:
        return {
            "verdict": DENY,
            "severity": SEVERITY_ERROR,
            "rule": f"{RULE_POLICY_DENY}:{family}",
            "trigger_license": display,
            "message": (
                f"策略「{policy.name}」禁止 {family} 家族许可证"
                f"（{display} 实际适用 {hit_license}），即使兼容矩阵允许也按冲突处理"
            ),
        }

    effective_note = (
        f"（表达式 {display} 实际适用 {hit_license}）" if raw_is_expression else ""
    )

    if verdict == lic.DENY:
        return {
            "verdict": DENY,
            "severity": SEVERITY_ERROR,
            "rule": f"{RULE_MATRIX}:{project_license}!{hit_license}",
            "trigger_license": display,
            "message": f"兼容矩阵：{project_license} 项目不兼容 {display}{effective_note}。{matrix_note}",
        }

    if verdict == lic.REVIEW:
        if family in policy.allow_families:
            return {
                "verdict": ALLOW,
                "severity": "",
                "rule": f"{RULE_POLICY_ALLOW}:{family}",
                "trigger_license": display,
                "message": (
                    f"矩阵建议人工审查（{matrix_note}），"
                    f"但策略「{policy.name}」对 {family} 家族预先放行"
                ),
            }
        return {
            "verdict": REVIEW,
            "severity": SEVERITY_WARNING,
            "rule": f"{RULE_MATRIX}:{project_license}~{hit_license}",
            "trigger_license": display,
            "message": f"兼容矩阵建议人工审查{effective_note}：{matrix_note}",
        }

    return {
        "verdict": ALLOW,
        "severity": "",
        "rule": f"{RULE_MATRIX}:{project_license}={hit_license}",
        "trigger_license": display,
        "message": f"兼容矩阵：{project_license} 与 {display} 兼容{effective_note}。{matrix_note}",
    }
