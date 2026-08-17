#!/usr/bin/env python3
"""
CLI entry point for the CSP Assessment Framework.

Wires together the full pipeline:

    Configuration -> HTTP Collection -> Redirect Processing ->
    Header/Meta Extraction -> CSP Parsing -> Effective Policy Evaluation ->
    Policy Comparison -> Scoring -> Reporting

Usage:
    python main.py --config config.yaml
    python main.py --config config.yaml --format console
    python main.py --config config.yaml --target https://example.com
    python main.py --config config.yaml --fail-under 70
"""

from __future__ import annotations

import argparse
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import List, Optional

from csp_auditor import __version__
from csp_auditor.collector import HTTPCollector, extract_csp_material
from csp_auditor.comparator import compare_policies
from csp_auditor.configuration import AppConfig, HostAllowlistConfig, load_config
from csp_auditor.evaluator import evaluate_policy, resolve_effective_policy
from csp_auditor.exceptions import CSPAuditorError, ConfigurationError
from csp_auditor.reputation import evaluate_host_allowlist
from csp_auditor.logging_utils import configure_logging, get_logger
from csp_auditor.models import (
    EffectivePolicy,
    Policy,
    PolicySource,
    Report,
    Target,
    TargetReport,
)
from csp_auditor.parser import parse_multiple
from csp_auditor.reporter import print_console_report, render_console_report, write_json_report
from csp_auditor.scoring import score_policy

logger = get_logger("main")


def build_target_report(
    target: Target,
    collector: HTTPCollector,
    host_allowlist_config: Optional[HostAllowlistConfig] = None,
) -> TargetReport:
    """
    Run the full per-target pipeline: collect -> parse -> evaluate ->
    host-allowlist (if configured) -> compare -> score.
    """
    chain = collector.collect(target)

    if chain.error and not chain.hops:
        return TargetReport(
            target=target,
            redirect_chain=chain,
            enforced_policy=None,
            report_only_policy=None,
            meta_policies=[],
            enforced_effective=None,
            report_only_effective=None,
            findings=[],
            enforced_score=None,
            report_only_score=None,
            comparison=None,
            collection_error=chain.error,
        )

    final = chain.final_response

    # -- extract raw CSP material from the FINAL hop (the effective document) --
    enforced_raw, report_only_raw, meta_raw = (
        extract_csp_material(final) if final else ([], [], [])
    )

    enforced_policies = parse_multiple(enforced_raw, PolicySource.HEADER_ENFORCED, origin_url=final.url if final else None)
    report_only_policies = parse_multiple(report_only_raw, PolicySource.HEADER_REPORT_ONLY, origin_url=final.url if final else None)
    meta_policies = parse_multiple(meta_raw, PolicySource.META_TAG, origin_url=final.url if final else None)

    # Multiple CSP headers combine via intersection per spec; for reporting
    # purposes we treat the FIRST as primary (most restrictive analysis
    # target) but retain all raw policies for the record. This keeps the
    # parser/evaluator boundary clean: each Policy is evaluated on its own
    # merits, findings from every header are still surfaced.
    enforced_policy: Optional[Policy] = enforced_policies[0] if enforced_policies else None
    report_only_policy: Optional[Policy] = report_only_policies[0] if report_only_policies else None

    findings = []
    enforced_effective: Optional[EffectivePolicy] = None
    report_only_effective: Optional[EffectivePolicy] = None
    enforced_score = None
    report_only_score = None

    # Evaluate ALL enforced header instances (in case of multiple CSP headers).
    all_enforced_findings = []
    for idx, p in enumerate(enforced_policies):
        eff = resolve_effective_policy(p)
        label = "Enforced" if idx == 0 else f"Enforced (header #{idx + 1})"
        all_enforced_findings.extend(evaluate_policy(eff, target.display_name, label))
        if host_allowlist_config is not None:
            all_enforced_findings.extend(
                evaluate_host_allowlist(p, host_allowlist_config, target.display_name, label)
            )
        if idx == 0:
            enforced_effective = eff
    findings.extend(all_enforced_findings)
    if enforced_policy:
        primary_enforced_findings = [f for f in all_enforced_findings if f.policy_type == "Enforced"]
        enforced_score = score_policy(primary_enforced_findings, enforced_policy)

    all_ro_findings = []
    for idx, p in enumerate(report_only_policies):
        eff = resolve_effective_policy(p)
        label = "Report-Only" if idx == 0 else f"Report-Only (header #{idx + 1})"
        all_ro_findings.extend(evaluate_policy(eff, target.display_name, label))
        if host_allowlist_config is not None:
            all_ro_findings.extend(
                evaluate_host_allowlist(p, host_allowlist_config, target.display_name, label)
            )
        if idx == 0:
            report_only_effective = eff
    findings.extend(all_ro_findings)
    if report_only_policy:
        primary_ro_findings = [f for f in all_ro_findings if f.policy_type == "Report-Only"]
        report_only_score = score_policy(primary_ro_findings, report_only_policy)

    for idx, p in enumerate(meta_policies):
        eff = resolve_effective_policy(p)
        label = "Meta" if idx == 0 else f"Meta (tag #{idx + 1})"
        findings.extend(evaluate_policy(eff, target.display_name, label))
        if host_allowlist_config is not None:
            findings.extend(
                evaluate_host_allowlist(p, host_allowlist_config, target.display_name, label)
            )

    comparison = None
    if enforced_effective is not None or report_only_effective is not None:
        comparison = compare_policies(enforced_effective, report_only_effective)

    return TargetReport(
        target=target,
        redirect_chain=chain,
        enforced_policy=enforced_policy,
        report_only_policy=report_only_policy,
        meta_policies=meta_policies,
        enforced_effective=enforced_effective,
        report_only_effective=report_only_effective,
        findings=findings,
        enforced_score=enforced_score,
        report_only_score=report_only_score,
        comparison=comparison,
        collection_error=chain.error if chain.truncated else None,
    )


def run_audit(config: AppConfig) -> Report:
    """Run the full audit across all configured targets, respecting concurrency."""
    collector = HTTPCollector(config.network)
    target_reports: List[TargetReport] = []

    with ThreadPoolExecutor(max_workers=config.network.concurrency) as pool:
        future_to_target = {
            pool.submit(build_target_report, target, collector, config.host_allowlist): target
            for target in config.targets
        }
        for future in as_completed(future_to_target):
            target = future_to_target[future]
            try:
                target_reports.append(future.result())
            except Exception as exc:  # pragma: no cover - safety net
                logger.exception("Unhandled failure auditing %s", target.url)
                target_reports.append(
                    TargetReport(
                        target=target,
                        redirect_chain=None,
                        enforced_policy=None,
                        report_only_policy=None,
                        meta_policies=[],
                        enforced_effective=None,
                        report_only_effective=None,
                        findings=[],
                        enforced_score=None,
                        report_only_score=None,
                        comparison=None,
                        collection_error=f"Unhandled exception: {exc}",
                    )
                )

    # Deterministic ordering in the final report, matching config order.
    order = {t.url: i for i, t in enumerate(config.targets)}
    target_reports.sort(key=lambda tr: order.get(tr.target.url, 0))

    return Report(
        generated_at=datetime.now(timezone.utc),
        framework_version=__version__,
        target_reports=target_reports,
        run_config_summary={
            "target_count": len(config.targets),
            "concurrency": config.network.concurrency,
            "timeout": config.network.timeout,
            "retry_count": config.network.retry_count,
            "verify_ssl": config.network.verify_ssl,
        },
    )


def _lowest_score(report: Report) -> Optional[float]:
    scores = []
    for tr in report.target_reports:
        if tr.enforced_score:
            scores.append(tr.enforced_score.numeric_score)
        elif not tr.collection_error:
            scores.append(0.0)  # no enforced CSP deployed at all
    return min(scores) if scores else None


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="csp-auditor",
        description="Enterprise-grade Content Security Policy assessment framework.",
    )
    parser.add_argument("--config", default="config.yaml", help="Path to config.yaml (default: config.yaml)")
    parser.add_argument("--target", action="append", help="Audit only this URL (repeatable); overrides config targets.")
    parser.add_argument(
        "--format", choices=["json", "console", "both"], default=None,
        help="Override output.output_format from config.",
    )
    parser.add_argument("--output-dir", default=None, help="Override output.output_dir from config.")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI color in console output.")
    parser.add_argument(
        "--fail-under", type=float, default=None,
        help="Exit with a non-zero status if the lowest enforced-policy score is below this threshold (for CI/CD gates).",
    )
    parser.add_argument("--version", action="version", version=f"csp-auditor {__version__}")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)

    try:
        config = load_config(args.config)
    except ConfigurationError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2

    if args.target:
        config.targets = [Target(url=u) for u in args.target]

    if args.format:
        config.output.output_format = args.format
    if args.output_dir:
        config.output.output_dir = args.output_dir

    configure_logging(config.logging_level)

    try:
        report = run_audit(config)
    except CSPAuditorError as exc:
        print(f"Audit failed: {exc}", file=sys.stderr)
        return 2

    use_color = config.output.console_color and not args.no_color

    if config.output.output_format in ("console", "both"):
        print_console_report(report, use_color=use_color)

    if config.output.output_format in ("json", "both"):
        try:
            path = write_json_report(report, config.output.output_dir)
            print(f"\nJSON report written to: {path}", file=sys.stderr)
        except CSPAuditorError as exc:
            print(f"Failed to write JSON report: {exc}", file=sys.stderr)
            return 2

    if args.fail_under is not None:
        lowest = _lowest_score(report)
        if lowest is not None and lowest < args.fail_under:
            print(
                f"\nFAIL: lowest enforced-policy score {lowest:.1f} is below "
                f"--fail-under threshold {args.fail_under:.1f}",
                file=sys.stderr,
            )
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
