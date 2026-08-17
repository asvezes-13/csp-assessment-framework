"""
Policy Scoring.

Single responsibility: turn a list of `Finding` objects (plus the source
`Policy`, for complexity metrics) into a `Score` — a 0-100 numeric score,
an A-F letter grade, severity distribution, and basic complexity metrics.

Scoring is deliberately simple and transparent (a deduction model) rather
than a black box, so security teams can explain a score to stakeholders.
"""

from __future__ import annotations

from typing import List, Optional

from csp_auditor.logging_utils import get_logger
from csp_auditor.models import Finding, Policy, Score, Severity

logger = get_logger("scoring")

# Points deducted per finding, by severity. Tuned so that a single CRITICAL
# finding (e.g. missing script-src) meaningfully drops the grade, while
# INFO-level observations barely move the needle.
_DEDUCTIONS = {
    Severity.INFO: 1,
    Severity.WARN: 4,
    Severity.VIOLATION: 10,
    Severity.ALARM: 18,
    Severity.CRITICAL: 30,
}

_GRADE_THRESHOLDS = [
    (90, "A"),
    (80, "B"),
    (70, "C"),
    (60, "D"),
    (0, "F"),
]


def _letter_grade(score: float) -> str:
    for threshold, grade in _GRADE_THRESHOLDS:
        if score >= threshold:
            return grade
    return "F"  # pragma: no cover - unreachable given thresholds include 0


def _complexity_metrics(policy: Optional[Policy]) -> dict:
    if policy is None:
        return {}
    directive_count = len(policy.directives)
    total_sources = sum(len(d.values) for d in policy.directives.values())
    duplicate_count = sum(1 for d in policy.directives.values() if d.is_duplicate)
    unknown_count = sum(1 for d in policy.directives.values() if d.is_unknown)
    obsolete_count = sum(1 for d in policy.directives.values() if d.is_obsolete)
    avg_sources = round(total_sources / directive_count, 2) if directive_count else 0.0

    return {
        "directive_count": directive_count,
        "total_source_expressions": total_sources,
        "average_sources_per_directive": avg_sources,
        "duplicate_directives": duplicate_count,
        "unknown_directives": unknown_count,
        "obsolete_directives": obsolete_count,
        "parser_issue_count": len(policy.parser_issues),
        "raw_length_chars": len(policy.raw),
    }


def score_policy(findings: List[Finding], policy: Optional[Policy] = None) -> Score:
    """Compute a Score from a list of findings (already filtered to one policy)."""
    severity_counts = {s: 0 for s in Severity}
    total_deduction = 0

    for f in findings:
        severity_counts[f.severity] += 1
        total_deduction += _DEDUCTIONS.get(f.severity, 0)

    numeric_score = max(0.0, 100.0 - float(total_deduction))
    letter = _letter_grade(numeric_score)

    return Score(
        numeric_score=round(numeric_score, 1),
        letter_grade=letter,
        severity_counts={s.value: c for s, c in severity_counts.items()},
        finding_count=len(findings),
        complexity_metrics=_complexity_metrics(policy),
    )
