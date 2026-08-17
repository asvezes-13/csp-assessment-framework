"""
Policy Comparison Engine.

Single responsibility: given two `EffectivePolicy` objects (typically
Enforced vs Report-Only for the same target), produce a semantic
comparison — NOT a string diff. Every directive is compared by its
*effective browser behavior* (permissiveness), not by textual equality.

Also estimates migration readiness: whether the Report-Only policy could
safely be promoted to enforced today, and if not, what blocks it.
"""

from __future__ import annotations

from typing import List, Optional, Set

from csp_auditor.evaluator import FALLBACK_CHAINS, NO_FALLBACK_DIRECTIVES, UNSAFE_KEYWORDS
from csp_auditor.logging_utils import get_logger
from csp_auditor.models import (
    ChangeClassification,
    Directive,
    EffectivePolicy,
    MigrationReadiness,
    DirectiveComparison,
    PolicyComparisonResult,
)
from csp_auditor.utils import safe_join

logger = get_logger("comparator")

# A rough, directive-agnostic "permissiveness score" used to decide whether
# a change tightens or relaxes a directive. Lower = more restrictive.
_KEYWORD_WEIGHT = {
    "none": 0,
    "self": 10,
}
_DEFAULT_TOKEN_WEIGHT = 40  # explicit host/origin allowlist entries
_SCHEME_WEIGHT = 70
_WILDCARD_WEIGHT = 90
_UNSAFE_WEIGHT = 100


def _directive_permissiveness(directive: Optional[Directive]) -> int:
    """
    Heuristic 0-100+ permissiveness score for a directive's effective value.
    Used purely for relative tightened/relaxed classification, not for
    absolute scoring (see scoring.py for that).
    """
    if directive is None:
        return 0  # "not present" is handled separately (unrestricted), see caller
    if not directive.values:
        return 0

    total = 0
    for v in directive.values:
        if v.normalized in UNSAFE_KEYWORDS:
            total += _UNSAFE_WEIGHT
        elif v.is_wildcard:
            total += _WILDCARD_WEIGHT
        elif v.is_scheme:
            total += _SCHEME_WEIGHT
        elif v.normalized in _KEYWORD_WEIGHT:
            total += _KEYWORD_WEIGHT[v.normalized]
        elif v.is_nonce or v.is_hash:
            total += 5  # nonces/hashes are tightly scoped
        else:
            total += _DEFAULT_TOKEN_WEIGHT

    return total


def _summarize(directive: Optional[Directive], is_explicit: bool, inherited_from: Optional[str]) -> str:
    if directive is None:
        return "(unrestricted / not declared)"
    values = safe_join(directive.value_strings())
    if is_explicit:
        return values
    if inherited_from:
        return f"{values}  [inherited from {inherited_from}]"
    return values


def compare_policies(
    enforced: Optional[EffectivePolicy],
    report_only: Optional[EffectivePolicy],
) -> PolicyComparisonResult:
    """
    Compare an enforced EffectivePolicy against a report-only
    EffectivePolicy for the same target. Either may be None (e.g. no
    enforced policy deployed yet, or no report-only policy present).
    """
    result = PolicyComparisonResult()

    if enforced is None and report_only is None:
        result.overall_relationship = "No policies present to compare."
        result.migration_readiness = MigrationReadiness.NOT_APPLICABLE
        return result

    if report_only is None:
        result.overall_relationship = "No Report-Only policy is deployed; nothing to compare against the enforced policy."
        result.migration_readiness = MigrationReadiness.NOT_APPLICABLE
        return result

    if enforced is None:
        result.overall_relationship = (
            "No enforced policy is deployed; the Report-Only policy would become the "
            "site's first enforced CSP if promoted."
        )
        result.migration_readiness = _assess_migration_readiness(report_only, blockers := [])
        result.blockers = blockers
        result.guidance = _guidance_for_blockers(blockers)
        return result

    all_names: Set[str] = set(enforced.effective_directives) | set(report_only.effective_directives)

    improvements = 0
    regressions = 0

    for name in sorted(all_names):
        e_eff = enforced.get_effective(name)
        r_eff = report_only.get_effective(name)

        e_dir = e_eff.directive if e_eff else None
        r_dir = r_eff.directive if r_eff else None

        e_present = e_dir is not None
        r_present = r_dir is not None

        e_summary = _summarize(e_dir, e_eff.is_explicit if e_eff else False, e_eff.inherited_from if e_eff else None)
        r_summary = _summarize(r_dir, r_eff.is_explicit if r_eff else False, r_eff.inherited_from if r_eff else None)

        if not e_present and not r_present:
            continue  # nothing to say about this directive for either policy

        if not e_present and r_present:
            classification = ChangeClassification.ADDED
            explanation = f"'{name}' is newly restricted in the Report-Only policy ({r_summary}), where it was previously unrestricted."
            result.added_directives.append(name)
            improvements += 1

        elif e_present and not r_present:
            classification = ChangeClassification.REMOVED
            explanation = f"'{name}' is restricted in the enforced policy ({e_summary}) but absent/unrestricted in Report-Only."
            result.removed_directives.append(name)
            regressions += 1

        else:
            e_score = _directive_permissiveness(e_dir)
            r_score = _directive_permissiveness(r_dir)
            e_values = {v.normalized for v in (e_dir.values if e_dir else [])}
            r_values = {v.normalized for v in (r_dir.values if r_dir else [])}

            if e_values == r_values:
                classification = ChangeClassification.UNCHANGED
                explanation = f"'{name}' is effectively identical between policies."
            elif r_score < e_score:
                classification = ChangeClassification.IMPROVEMENT
                explanation = f"'{name}' is more restrictive in Report-Only (score {r_score}) than enforced (score {e_score})."
                result.tightened_directives.append(name)
                improvements += 1
            elif r_score > e_score:
                classification = ChangeClassification.REGRESSION
                explanation = f"'{name}' is less restrictive in Report-Only (score {r_score}) than enforced (score {e_score})."
                result.relaxed_directives.append(name)
                regressions += 1
            else:
                classification = ChangeClassification.NEUTRAL
                explanation = f"'{name}' differs textually but is roughly equivalent in estimated permissiveness."

        result.directive_comparisons.append(
            DirectiveComparison(
                directive=name,
                enforced_summary=e_summary,
                report_only_summary=r_summary,
                classification=classification,
                explanation=explanation,
            )
        )

    # ---- overall relationship -------------------------------------------
    if improvements > 0 and regressions == 0:
        result.overall_relationship = "Report-Only represents a stricter future policy than the enforced policy."
    elif regressions > 0 and improvements == 0:
        result.overall_relationship = "Report-Only represents a WEAKER policy than what is currently enforced."
    elif improvements > 0 and regressions > 0:
        result.overall_relationship = "Report-Only is a mixed change: it tightens some directives while relaxing others relative to the enforced policy."
    else:
        result.overall_relationship = "Report-Only is effectively equivalent to the enforced policy."

    blockers = _identify_blockers(report_only)
    result.blockers = blockers
    result.guidance = _guidance_for_blockers(blockers)

    if regressions > 0 and improvements == 0:
        result.migration_readiness = MigrationReadiness.REGRESSION_RISK
    else:
        result.migration_readiness = _assess_migration_readiness(report_only, blockers)

    return result


def _identify_blockers(report_only: EffectivePolicy) -> List[str]:
    """Identify conditions that would block safely promoting Report-Only to enforced."""
    blockers = []
    policy = report_only.policy

    script_src = policy.get("script-src")
    if script_src:
        if script_src.has_keyword("unsafe-inline") and not (script_src.any_nonce() or script_src.any_hash()):
            blockers.append(
                "script-src permits 'unsafe-inline' without a nonce/hash fallback; "
                "inline scripts will break once enforced unless refactored."
            )
        if script_src.has_keyword("strict-dynamic") and not (script_src.any_nonce() or script_src.any_hash()):
            blockers.append(
                "script-src declares 'strict-dynamic' without a nonce/hash to seed trust."
            )
    else:
        blockers.append("script-src is not declared in the Report-Only policy (relies on default-src or is unrestricted).")

    if not policy.has_directive("report-uri") and not policy.has_directive("report-to"):
        blockers.append(
            "No 'report-uri'/'report-to' configured on the Report-Only policy; you will "
            "have no visibility into what would break before enforcing it."
        )

    if policy.parser_issues:
        blockers.append(
            f"{len(policy.parser_issues)} parser issue(s) detected in the Report-Only policy "
            "(duplicates, unknown/obsolete directives, or malformed tokens) — review before promoting."
        )

    return blockers


def _guidance_for_blockers(blockers: List[str]) -> List[str]:
    if not blockers:
        return [
            "Monitor 'report-to'/'report-uri' violation reports for a representative "
            "traffic period, then promote Report-Only to an enforced "
            "Content-Security-Policy header.",
        ]
    guidance = [
        "Resolve the identified blockers before promoting Report-Only to enforced:",
    ]
    guidance.extend(f"  - {b}" for b in blockers)
    guidance.append(
        "After remediation, monitor violation reports for a representative traffic "
        "period before flipping Report-Only to enforced."
    )
    return guidance


def _assess_migration_readiness(report_only: EffectivePolicy, blockers: List[str]) -> MigrationReadiness:
    if not blockers:
        return MigrationReadiness.READY
    if len(blockers) <= 1:
        return MigrationReadiness.NEARLY_READY
    return MigrationReadiness.NOT_READY
