"""
Host Reputation Engine (allowlist mode).

Single responsibility: given an already-resolved `Policy` and a configured
list of trusted domains, flag every host-shaped source expression that is
NOT covered by the allowlist as untrusted.

This module is intentionally a *whitelist*, not a blacklist/threat-intel
lookup: rather than trying to keep a database of known-malicious
infrastructure up to date (which always lags behind new attacker
infrastructure), it fails closed — anything not explicitly trusted is
flagged, regardless of whether it is independently known to be
malicious. A true Threat Intelligence Engine (reputation lookups against
external feeds) remains a distinct, larger future module; this one only
needs `config.yaml` and the already-parsed `Policy`.

This module deliberately follows the same shape as `evaluator.py`
(consumes a `Policy`/`EffectivePolicy`, emits `Finding`s) so it can be
composed into the pipeline without modifying `parser.py` or
`evaluator.py` at all — see docs/architecture.md "Extensibility".

Matching rules
--------------
Each entry in `trusted_domains` is matched against each host found in the
policy using CSP-accurate wildcard semantics:

  - An exact entry (e.g. "cdn.example.com") matches only that exact host.
  - A wildcard entry (e.g. "*.example.com") matches any subdomain of
    example.com (one or more labels), but NOT example.com itself — mirroring
    how browsers interpret `*.example.com` in a CSP source list.
  - A host that is itself a wildcard (e.g. policy declares "*.cdn.example.com")
    is only considered trusted if a wildcard trusted entry for the exact same
    base domain is present; a broader trusted entry does not implicitly
    authorize a narrower or unrelated wildcard.

Keywords ('self', 'none', 'unsafe-inline', ...), nonces, hashes, and bare
schemes (data:, blob:, https:, ...) are not host expressions and are
skipped by this module entirely — they are already covered by the
dangerous-source checks in evaluator.py.
"""

from __future__ import annotations

from typing import List, Optional

from csp_auditor.configuration import HostAllowlistConfig
from csp_auditor.logging_utils import get_logger
from csp_auditor.models import Confidence, Finding, Policy, Severity
from csp_auditor.utils import extract_hostname, safe_join

logger = get_logger("reputation")

_SEVERITY_MAP = {s.value: s for s in Severity}


def _normalize(domain: str) -> str:
    return domain.strip().lower()


def _is_trusted(host: str, trusted_domains: List[str]) -> bool:
    """Apply CSP-accurate wildcard matching between a host and the allowlist."""
    host_norm = _normalize(host)
    host_is_wildcard = host_norm.startswith("*.")
    host_base = host_norm[2:] if host_is_wildcard else host_norm

    for entry in trusted_domains:
        entry_norm = _normalize(entry)
        entry_is_wildcard = entry_norm.startswith("*.")
        entry_base = entry_norm[2:] if entry_is_wildcard else entry_norm

        if entry_is_wildcard:
            if host_is_wildcard:
                # Both wildcards: only trust an identical base domain.
                if host_base == entry_base:
                    return True
            else:
                # Trusted wildcard covers any subdomain (not the bare base).
                if host_norm.endswith("." + entry_base):
                    return True
        else:
            # Exact trusted entry only matches an identical host string.
            if host_norm == entry_norm:
                return True

    return False


def evaluate_host_allowlist(
    policy: Policy,
    config: HostAllowlistConfig,
    target: str,
    policy_type: str,
) -> List[Finding]:
    """
    Produce a Finding for every host-shaped source expression in `policy`
    that is not covered by `config.trusted_domains`.

    Returns an empty list immediately if the module is disabled, so callers
    can invoke this unconditionally without branching.
    """
    if not config.enabled:
        return []

    severity = _SEVERITY_MAP.get(config.severity, Severity.WARN)
    findings: List[Finding] = []
    seen: set = set()  # (directive, host) -> avoid duplicate findings for repeated hosts

    for name, directive in policy.directives.items():
        if name not in config.directives:
            continue

        for value in directive.values:
            if value.is_keyword or value.is_nonce or value.is_hash or value.is_scheme:
                continue  # not a host expression; out of scope for this module

            host = extract_hostname(value.raw)
            if not host:
                continue

            if _is_trusted(host, config.trusted_domains):
                continue

            key = (name, host.lower())
            if key in seen:
                continue
            seen.add(key)

            findings.append(
                Finding(
                    target=target,
                    policy_type=policy_type,
                    directive=name,
                    severity=severity,
                    confidence=Confidence.HIGH,
                    title=f"Untrusted host in {name}: {host}",
                    description=(
                        f"'{host}' is permitted by the '{name}' directive but does not "
                        "match any entry in the configured trusted_domains allowlist."
                    ),
                    evidence=value.raw,
                    effective_behavior=(
                        f"Any resource served from '{host}' may be loaded/executed under "
                        f"the '{name}' directive's permissions, regardless of whether that "
                        "host is actually controlled by your organization."
                    ),
                    recommendation=(
                        f"If '{host}' is a legitimate, intentionally-used origin, add it "
                        "(or a wildcard covering it) to host_allowlist.trusted_domains in "
                        "config.yaml. Otherwise, remove it from the policy."
                    ),
                    reference="OWASP CSP Cheat Sheet; internal host allowlist policy",
                    category="host-reputation",
                )
            )

    if findings:
        logger.debug(
            "Host allowlist: %s untrusted host(s) found for %s (%s)",
            len(findings), target, policy_type,
        )

    return findings
