"""
Reporting Engine.

Single responsibility: render a `Report` (see models.py) as rich console
output, a timestamped JSON file suitable for CI/CD consumption, or a
self-contained interactive HTML report. This module performs no
evaluation/scoring logic of its own — it only formats already-computed
results. The HTML report reuses the exact same serialization
(`_to_serializable`) as the JSON report, so both are always guaranteed to
agree on content — there is only one place that decides what a "target's
data" looks like.
"""

from __future__ import annotations

import json
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from csp_auditor.exceptions import ReportingError
from csp_auditor.logging_utils import get_logger
from csp_auditor.models import Report, Severity, TargetReport

logger = get_logger("reporter")

_TEMPLATE_PATH = Path(__file__).parent / "report_template.html"
_HTML_DATA_PLACEHOLDER = "__CSP_REPORT_DATA__"

_SEVERITY_COLOR = {
    Severity.INFO: "\033[36m",       # cyan
    Severity.WARN: "\033[33m",       # yellow
    Severity.VIOLATION: "\033[35m",  # magenta
    Severity.ALARM: "\033[91m",      # bright red
    Severity.CRITICAL: "\033[1;41m",  # white on red background
}
_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"


# ==========================================================================
# JSON serialization
# ==========================================================================
def _json_default(obj: Any) -> Any:
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, Severity):
        return obj.value
    if hasattr(obj, "value") and hasattr(obj, "name") and not is_dataclass(obj):
        # Enum instances generally
        try:
            return obj.value
        except Exception:
            return str(obj)
    if is_dataclass(obj):
        return asdict(obj)
    return str(obj)


def _to_serializable(report: Report) -> dict:
    """
    Convert a Report (and its nested dataclasses/enums) into a plain,
    JSON-serializable dict. We build this manually (rather than a blind
    dataclasses.asdict) so we can control shape and avoid dumping huge
    HTML bodies into the report.
    """

    def target_report_dict(tr: TargetReport) -> dict:
        return {
            "target": {
                "url": tr.target.url,
                "name": tr.target.display_name,
                "labels": tr.target.labels,
            },
            "collection": {
                "hop_count": tr.redirect_chain.hop_count if tr.redirect_chain else 0,
                "error": tr.collection_error,
                "hops": [
                    {
                        "url": h.url,
                        "status_code": h.status_code,
                        "is_redirect": h.is_redirect,
                        "redirect_location": h.redirect_location,
                        "content_type": h.content_type,
                        "elapsed_seconds": round(h.elapsed_seconds, 4),
                        "has_enforced_csp": h.header("content-security-policy") is not None,
                        "has_report_only_csp": h.header("content-security-policy-report-only") is not None,
                    }
                    for h in (tr.redirect_chain.hops if tr.redirect_chain else [])
                ],
            },
            "policies": {
                "enforced_raw": tr.enforced_policy.raw if tr.enforced_policy else None,
                "report_only_raw": tr.report_only_policy.raw if tr.report_only_policy else None,
                "meta_raw": [p.raw for p in (tr.meta_policies or [])],
            },
            "findings": [
                {
                    "policy_type": f.policy_type,
                    "directive": f.directive,
                    "severity": f.severity.value,
                    "confidence": f.confidence.value,
                    "title": f.title,
                    "description": f.description,
                    "evidence": f.evidence,
                    "effective_behavior": f.effective_behavior,
                    "recommendation": f.recommendation,
                    "reference": f.reference,
                    "category": f.category,
                }
                for f in tr.findings
            ],
            "scores": {
                "enforced": _score_dict(tr.enforced_score),
                "report_only": _score_dict(tr.report_only_score),
            },
            "comparison": _comparison_dict(tr.comparison) if tr.comparison else None,
        }

    def _score_dict(score):
        if score is None:
            return None
        return {
            "numeric_score": score.numeric_score,
            "letter_grade": score.letter_grade,
            "severity_counts": score.severity_counts,
            "finding_count": score.finding_count,
            "complexity_metrics": score.complexity_metrics,
        }

    def _comparison_dict(cmp):
        return {
            "overall_relationship": cmp.overall_relationship,
            "migration_readiness": cmp.migration_readiness.value,
            "added_directives": cmp.added_directives,
            "removed_directives": cmp.removed_directives,
            "tightened_directives": cmp.tightened_directives,
            "relaxed_directives": cmp.relaxed_directives,
            "blockers": cmp.blockers,
            "guidance": cmp.guidance,
            "directive_comparisons": [
                {
                    "directive": dc.directive,
                    "enforced": dc.enforced_summary,
                    "report_only": dc.report_only_summary,
                    "classification": dc.classification.value,
                    "explanation": dc.explanation,
                }
                for dc in cmp.directive_comparisons
            ],
        }

    return {
        "generated_at": report.generated_at.isoformat(),
        "framework_version": report.framework_version,
        "run_config_summary": report.run_config_summary,
        "target_count": report.target_count,
        "targets": [target_report_dict(tr) for tr in report.target_reports],
    }


def write_json_report(report: Report, output_dir: str) -> str:
    """Write a timestamped JSON report to output_dir. Returns the file path."""
    out_dir = Path(output_dir)
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ReportingError(f"Cannot create output directory '{output_dir}': {exc}") from exc

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    filename = f"csp_report_{timestamp}.json"
    filepath = out_dir / filename

    try:
        with filepath.open("w", encoding="utf-8") as fh:
            json.dump(_to_serializable(report), fh, indent=2, default=_json_default)
    except OSError as exc:
        raise ReportingError(f"Failed to write report to {filepath}: {exc}") from exc

    logger.info("JSON report written to %s", filepath)
    return str(filepath)


# ==========================================================================
# HTML rendering
# ==========================================================================
def render_html_report(report: Report) -> str:
    """
    Render a self-contained, interactive HTML report as a string.

    Reuses `_to_serializable` — the identical data shape the JSON report
    uses — so the HTML and JSON outputs can never drift apart in content,
    only in presentation. The template is a static file
    (`report_template.html`) with inline CSS/JS and zero external
    dependencies (no CDN, no fonts, no network calls), so the generated
    file works fully offline — important for AppSec teams auditing
    internal/air-gapped targets who may not want the report itself to
    "phone home" for assets.
    """
    try:
        template = _TEMPLATE_PATH.read_text(encoding="utf-8")
    except OSError as exc:
        raise ReportingError(f"Failed to read HTML template at {_TEMPLATE_PATH}: {exc}") from exc

    if _HTML_DATA_PLACEHOLDER not in template:
        raise ReportingError(
            f"HTML template at {_TEMPLATE_PATH} is missing the expected "
            f"'{_HTML_DATA_PLACEHOLDER}' placeholder; refusing to generate a report "
            "with no embedded data."
        )

    json_blob = json.dumps(_to_serializable(report), default=_json_default)
    # Defensively escape "</script" sequences that could theoretically appear
    # inside embedded string data (e.g. a raw CSP value or finding evidence),
    # which would otherwise prematurely close the <script> tag in the browser.
    json_blob = json_blob.replace("</", "<\\/")

    return template.replace(_HTML_DATA_PLACEHOLDER, json_blob)


def write_html_report(report: Report, output_dir: str) -> str:
    """Write a timestamped, self-contained HTML report to output_dir."""
    out_dir = Path(output_dir)
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ReportingError(f"Cannot create output directory '{output_dir}': {exc}") from exc

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    filename = f"csp_report_{timestamp}.html"
    filepath = out_dir / filename

    html = render_html_report(report)

    try:
        filepath.write_text(html, encoding="utf-8")
    except OSError as exc:
        raise ReportingError(f"Failed to write report to {filepath}: {exc}") from exc

    logger.info("HTML report written to %s", filepath)
    return str(filepath)


# ==========================================================================
# Console rendering
# ==========================================================================
def render_console_report(report: Report, use_color: bool = True) -> str:
    """Render the full report as a human-readable string (also usable for tests)."""
    lines = []

    def c(code: str, text: str) -> str:
        return f"{code}{text}{_RESET}" if use_color else text

    lines.append(c(_BOLD, "=" * 78))
    lines.append(c(_BOLD, "CSP ASSESSMENT REPORT"))
    lines.append(f"Generated:  {report.generated_at.isoformat()}")
    lines.append(f"Framework:  csp-assessment-framework v{report.framework_version}")
    lines.append(f"Targets:    {report.target_count}")
    lines.append(c(_BOLD, "=" * 78))

    for tr in report.target_reports:
        lines.append("")
        lines.append(c(_BOLD, f"TARGET: {tr.target.display_name}  ({tr.target.url})"))
        lines.append("-" * 78)

        if tr.collection_error:
            lines.append(c(_SEVERITY_COLOR[Severity.CRITICAL], f"  COLLECTION ERROR: {tr.collection_error}"))
            continue

        if tr.redirect_chain:
            lines.append(f"  Redirect chain: {tr.redirect_chain.hop_count} hop(s)")
            for i, hop in enumerate(tr.redirect_chain.hops):
                has_enforced = hop.header("content-security-policy") is not None
                has_ro = hop.header("content-security-policy-report-only") is not None
                marker = []
                if has_enforced:
                    marker.append("CSP")
                if has_ro:
                    marker.append("CSP-RO")
                marker_str = f"[{', '.join(marker)}]" if marker else c(_DIM, "[no CSP]")
                lines.append(
                    f"    hop {i}: {hop.status_code} {hop.url}  {marker_str}"
                )

        if tr.enforced_score:
            lines.append(
                f"  Enforced CSP score:    {tr.enforced_score.numeric_score:5.1f}/100  "
                f"({tr.enforced_score.letter_grade})  "
                f"[{tr.enforced_score.finding_count} findings]"
            )
        else:
            lines.append(c(_SEVERITY_COLOR[Severity.ALARM], "  Enforced CSP score:    NOT DEPLOYED"))

        if tr.report_only_score:
            lines.append(
                f"  Report-Only score:     {tr.report_only_score.numeric_score:5.1f}/100  "
                f"({tr.report_only_score.letter_grade})  "
                f"[{tr.report_only_score.finding_count} findings]"
            )

        if tr.comparison and tr.comparison.migration_readiness.value != "Not applicable":
            lines.append(f"  Migration readiness:   {tr.comparison.migration_readiness.value}")
            lines.append(f"  Relationship:          {tr.comparison.overall_relationship}")

        if tr.findings:
            lines.append("")
            lines.append("  Findings:")
            for f in sorted(tr.findings, key=lambda x: -x.severity.rank):
                color = _SEVERITY_COLOR.get(f.severity, "")
                sev_label = c(color, f"[{f.severity.value:9s}]")
                directive_label = f" ({f.directive})" if f.directive else ""
                lines.append(f"    {sev_label} {f.policy_type}{directive_label}: {f.title}")
                lines.append(f"        {f.description}")
                lines.append(f"        Recommendation: {f.recommendation}")
        else:
            lines.append(c(_SEVERITY_COLOR[Severity.INFO], "  No findings."))

    lines.append("")
    lines.append(c(_BOLD, "=" * 78))
    return "\n".join(lines)


def print_console_report(report: Report, use_color: bool = True) -> None:
    print(render_console_report(report, use_color=use_color))
