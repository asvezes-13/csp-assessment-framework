"""
Policy Evaluation Engine.

Single responsibility: given a structured `Policy`, determine

  1. The *effective* policy after applying CSP inheritance / fallback
     rules (`resolve_effective_policy`), and
  2. The security findings that follow from that effective policy
     (`evaluate_policy`).

This module never re-parses strings — it consumes `Policy` objects produced
by `parser.py`. It also never performs HTTP I/O, comparison between
policies, or scoring; those are the responsibilities of collector.py,
comparator.py, and scoring.py respectively.
"""

from __future__ import annotations

from typing import List, Optional

from csp_auditor.logging_utils import get_logger
from csp_auditor.models import (
    Confidence,
    Directive,
    EffectiveDirective,
    EffectivePolicy,
    Finding,
    Policy,
    PolicySource,
    Severity,
)
from csp_auditor.utils import safe_join, truncate

logger = get_logger("evaluator")

# --------------------------------------------------------------------------
# CSP Level 3 fallback / inheritance chains.
# Directives not listed here have NO fallback: if absent, the browser
# treats the resource type as entirely unrestricted (not inherited from
# default-src). See https://www.w3.org/TR/CSP3/#directive-fallback-list
# --------------------------------------------------------------------------
FALLBACK_CHAINS = {
    "script-src": ["default-src"],
    "script-src-elem": ["script-src", "default-src"],
    "script-src-attr": ["script-src", "default-src"],
    "style-src": ["default-src"],
    "style-src-elem": ["style-src", "default-src"],
    "style-src-attr": ["style-src", "default-src"],
    "img-src": ["default-src"],
    "connect-src": ["default-src"],
    "font-src": ["default-src"],
    "media-src": ["default-src"],
    "object-src": ["default-src"],
    "manifest-src": ["default-src"],
    "prefetch-src": ["default-src"],
    "child-src": ["default-src"],
    "frame-src": ["child-src", "default-src"],
    "worker-src": ["child-src", "default-src"],
}

# Directives that have NO default-src fallback whatsoever. If missing, the
# associated behavior is entirely unrestricted by CSP (a distinct, and
# often more dangerous, condition than "falls back to a restrictive
# default-src").
NO_FALLBACK_DIRECTIVES = {
    "base-uri", "form-action", "frame-ancestors", "sandbox", "navigate-to",
    "report-uri", "report-to", "block-all-mixed-content",
    "upgrade-insecure-requests", "require-trusted-types-for", "trusted-types",
}

# Directives ignored by browsers when declared via <meta http-equiv> instead
# of an HTTP header. https://www.w3.org/TR/CSP3/#meta-element
META_IGNORED_DIRECTIVES = {
    "frame-ancestors": "frame-ancestors requires an HTTP response header; browsers ignore it in <meta> tags.",
    "report-uri": "report-uri requires an HTTP response header; browsers ignore it in <meta> tags.",
    "report-to": "report-to requires an HTTP response header; browsers ignore it in <meta> tags.",
    "sandbox": "sandbox requires an HTTP response header; browsers ignore it in <meta> tags.",
}

DANGEROUS_SCHEMES = {"http:", "https:", "data:", "blob:", "filesystem:", "mediastream:", "ftp:"}
UNSAFE_KEYWORDS = {"unsafe-inline", "unsafe-eval", "unsafe-hashes", "unsafe-allow-redirects"}

_MANDATORY_DIRECTIVES = ["default-src", "script-src", "object-src", "base-uri", "frame-ancestors"]


# ==========================================================================
# Effective policy resolution
# ==========================================================================
def resolve_effective_policy(policy: Policy) -> EffectivePolicy:
    """
    Resolve every known fetch/document/navigation directive to its
    *effective* value, applying CSP Level 3 fallback chains.
    """
    effective = EffectivePolicy(policy=policy)

    all_directive_names = set(FALLBACK_CHAINS) | set(NO_FALLBACK_DIRECTIVES) | {"default-src"}
    all_directive_names |= set(policy.directives.keys())

    for name in sorted(all_directive_names):
        explicit = policy.get(name)
        if explicit is not None:
            effective.effective_directives[name] = EffectiveDirective(
                name=name,
                directive=explicit,
                is_explicit=True,
                inherited_from=None,
                explanation=f"'{name}' is explicitly declared.",
            )
            continue

        # Not explicit: walk fallback chain (if any).
        chain = FALLBACK_CHAINS.get(name)
        if not chain:
            effective.effective_directives[name] = EffectiveDirective(
                name=name,
                directive=None,
                is_explicit=False,
                inherited_from=None,
                explanation=(
                    f"'{name}' has no default-src fallback in the CSP specification; "
                    "since it is not declared, this behavior is entirely unrestricted "
                    "by this policy."
                ),
            )
            continue

        resolved = None
        resolved_from = None
        for fallback_name in chain:
            candidate = policy.get(fallback_name)
            if candidate is not None:
                resolved = candidate
                resolved_from = fallback_name
                break

        if resolved is not None:
            explanation = (
                f"'{name}' is not explicitly declared; per CSP fallback rules it "
                f"inherits its effective value from '{resolved_from}'."
            )
        else:
            explanation = (
                f"'{name}' is not explicitly declared, and none of its fallback "
                f"directives ({safe_join(chain)}) are present either; this resource "
                "type is effectively unrestricted."
            )

        effective.effective_directives[name] = EffectiveDirective(
            name=name,
            directive=resolved,
            is_explicit=False,
            inherited_from=resolved_from,
            explanation=explanation,
        )

    return effective


# ==========================================================================
# Finding helpers
# ==========================================================================
def _finding(
    target: str,
    policy_type: str,
    directive: Optional[str],
    severity: Severity,
    confidence: Confidence,
    title: str,
    description: str,
    evidence: str,
    effective_behavior: str,
    recommendation: str,
    category: str = "general",
) -> Finding:
    return Finding(
        target=target,
        policy_type=policy_type,
        directive=directive,
        severity=severity,
        confidence=confidence,
        title=title,
        description=description,
        evidence=truncate(evidence, 300),
        effective_behavior=effective_behavior,
        recommendation=recommendation,
        category=category,
    )


# ==========================================================================
# Main evaluation entry point
# ==========================================================================
def evaluate_policy(
    effective: EffectivePolicy,
    target: str,
    policy_type: str,
) -> List[Finding]:
    """
    Produce the full list of Finding objects for one effective policy.

    `policy_type` is a human label such as "Enforced", "Report-Only", or
    "Meta" used purely for reporting.
    """
    findings: List[Finding] = []
    policy = effective.policy

    findings.extend(_parser_issue_findings(policy, target, policy_type))
    findings.extend(_mandatory_directive_findings(effective, target, policy_type))
    findings.extend(_unsafe_keyword_findings(policy, target, policy_type))
    findings.extend(_dangerous_source_findings(policy, target, policy_type))
    findings.extend(_nonce_hash_strict_dynamic_findings(policy, target, policy_type))
    findings.extend(_reporting_findings(policy, target, policy_type))
    findings.extend(_modern_feature_findings(policy, target, policy_type))
    findings.extend(_object_src_base_uri_findings(effective, target, policy_type))
    findings.extend(_default_src_reliance_findings(policy, target, policy_type))

    if policy.source == PolicySource.META_TAG:
        findings.extend(_meta_specific_findings(policy, target, policy_type))

    return findings


# ==========================================================================
# Individual finding generators
# ==========================================================================
def _parser_issue_findings(policy: Policy, target: str, policy_type: str) -> List[Finding]:
    findings = []
    for issue in policy.parser_issues:
        if "Duplicate directive" in issue.message:
            severity = Severity.WARN
        elif "obsolete" in issue.message.lower():
            severity = Severity.INFO
        elif "Unrecognized" in issue.message:
            severity = Severity.INFO
        else:
            severity = Severity.INFO

        findings.append(
            _finding(
                target=target,
                policy_type=policy_type,
                directive=issue.directive,
                severity=severity,
                confidence=Confidence.HIGH,
                title="Policy parsing observation",
                description=issue.message,
                evidence=issue.raw_fragment or policy.raw,
                effective_behavior=(
                    "Browsers ignore malformed/duplicate/unknown directive content "
                    "as described; this does not necessarily disable the rest of the policy."
                ),
                recommendation="Review and clean up the CSP to remove ambiguity.",
                category="parsing",
            )
        )
    return findings


def _mandatory_directive_findings(
    effective: EffectivePolicy, target: str, policy_type: str
) -> List[Finding]:
    findings = []
    for name in _MANDATORY_DIRECTIVES:
        eff = effective.get_effective(name)
        if eff and (eff.directive is not None):
            continue  # present, explicitly or via inheritance

        if name == "default-src":
            severity, impact = Severity.VIOLATION, (
                "Without default-src, every fetch directive that has no explicit "
                "value and no other fallback is completely unrestricted."
            )
        elif name == "script-src":
            severity, impact = Severity.CRITICAL, (
                "script execution is governed only by default-src (if present) or "
                "is entirely unrestricted, materially increasing XSS impact."
            )
        elif name == "object-src":
            severity, impact = Severity.VIOLATION, (
                "Plugin content (Flash/legacy objects) is unrestricted or falls back "
                "to default-src, which is commonly broader than necessary."
            )
        elif name == "base-uri":
            severity, impact = Severity.VIOLATION, (
                "base-uri has NO default-src fallback; without it, an attacker who "
                "achieves HTML injection can rewrite the document's <base> href to "
                "redirect relative-URL script/resource loads to an attacker origin."
            )
        elif name == "frame-ancestors":
            severity, impact = Severity.WARN, (
                "frame-ancestors has NO default-src fallback; without it, the page "
                "may be framed by any origin, enabling clickjacking unless a legacy "
                "X-Frame-Options header compensates."
            )
        else:  # pragma: no cover - exhaustive by construction
            severity, impact = Severity.WARN, "Directive missing."

        findings.append(
            _finding(
                target=target,
                policy_type=policy_type,
                directive=name,
                severity=severity,
                confidence=Confidence.HIGH,
                title=f"Missing mandatory directive: {name}",
                description=(
                    f"'{name}' is not present, explicitly or via inheritance, in "
                    f"this policy."
                ),
                evidence=effective.policy.raw,
                effective_behavior=impact,
                recommendation=_recommendation_for_missing(name),
                category="mandatory-directive",
            )
        )
    return findings


def _recommendation_for_missing(name: str) -> str:
    return {
        "default-src": "Add a restrictive default-src (e.g. 'self') as a safety net for undeclared fetch directives.",
        "script-src": "Add an explicit script-src using nonces/hashes with 'strict-dynamic', avoiding 'unsafe-inline'/'unsafe-eval'.",
        "object-src": "Add `object-src 'none'` unless legacy plugin content is genuinely required.",
        "base-uri": "Add `base-uri 'self'` (or 'none') to prevent base-tag injection attacks.",
        "frame-ancestors": "Add `frame-ancestors 'self'` (or 'none') to mitigate clickjacking.",
    }.get(name, f"Add an explicit '{name}' directive.")


def _unsafe_keyword_findings(policy: Policy, target: str, policy_type: str) -> List[Finding]:
    findings = []
    for name, directive in policy.directives.items():
        for kw in UNSAFE_KEYWORDS:
            if directive.has_keyword(kw):
                severity = Severity.CRITICAL if kw in ("unsafe-inline", "unsafe-eval") and name.startswith("script") \
                    else Severity.ALARM
                findings.append(
                    _finding(
                        target=target,
                        policy_type=policy_type,
                        directive=name,
                        severity=severity,
                        confidence=Confidence.CERTAIN,
                        title=f"Unsafe keyword '{kw}' in {name}",
                        description=(
                            f"The directive '{name}' permits '{kw}', which substantially "
                            "weakens CSP's XSS mitigation for this resource type."
                        ),
                        evidence=safe_join(directive.value_strings()),
                        effective_behavior=_unsafe_keyword_behavior(kw, name),
                        recommendation=_unsafe_keyword_recommendation(kw),
                        category="unsafe-keyword",
                    )
                )
    return findings


def _unsafe_keyword_behavior(kw: str, directive_name: str) -> str:
    if kw == "unsafe-inline":
        return (
            f"Inline scripts/styles in '{directive_name}' execute regardless of "
            "origin controls, largely defeating CSP's core XSS protection for "
            "this resource type (unless a nonce/hash is also present, which "
            "browsers use to ignore 'unsafe-inline' under CSP Level 2+ rules)."
        )
    if kw == "unsafe-eval":
        return (
            "String-to-code APIs (eval, new Function, setTimeout with a string, "
            "etc.) are permitted, enabling execution of attacker-controlled "
            "strings as code."
        )
    if kw == "unsafe-hashes":
        return (
            "Inline event handlers (onclick, etc.) matching an allow-listed hash "
            "are permitted, broadening the inline-execution surface."
        )
    return "Automatic redirects following a fetch are exempted from target-based restrictions."


def _unsafe_keyword_recommendation(kw: str) -> str:
    return {
        "unsafe-inline": "Replace with nonce-based or hash-based allowlisting and adopt 'strict-dynamic'.",
        "unsafe-eval": "Remove 'unsafe-eval'; refactor code to avoid eval()/new Function()/string timers.",
        "unsafe-hashes": "Move inline event handlers into external scripts controlled by nonce/hash.",
        "unsafe-allow-redirects": "Remove unless strictly required; it weakens redirect-target restrictions.",
    }.get(kw, "Remove this unsafe keyword.")


def _dangerous_source_findings(policy: Policy, target: str, policy_type: str) -> List[Finding]:
    findings = []
    for name, directive in policy.directives.items():
        for v in directive.values:
            if v.is_wildcard:
                findings.append(
                    _finding(
                        target=target,
                        policy_type=policy_type,
                        directive=name,
                        severity=Severity.ALARM if name.startswith("script") else Severity.VIOLATION,
                        confidence=Confidence.HIGH,
                        title=f"Wildcard source in {name}",
                        description=f"'{v.raw}' allows resources from an overly broad set of origins.",
                        evidence=v.raw,
                        effective_behavior=(
                            "Any origin (or any subdomain, for '*.example.com') matching "
                            "the wildcard can supply content for this directive."
                        ),
                        recommendation="Replace wildcard sources with an explicit allowlist of required origins.",
                        category="dangerous-source",
                    )
                )
            elif v.normalized in DANGEROUS_SCHEMES:
                sev = Severity.ALARM if v.normalized in ("data:", "http:") and name.startswith("script") \
                    else Severity.VIOLATION
                findings.append(
                    _finding(
                        target=target,
                        policy_type=policy_type,
                        directive=name,
                        severity=sev,
                        confidence=Confidence.HIGH,
                        title=f"Broad scheme source '{v.raw}' in {name}",
                        description=(
                            f"'{v.raw}' allows any resource served over that scheme, "
                            "from any host."
                        ),
                        evidence=v.raw,
                        effective_behavior=_scheme_behavior(v.normalized, name),
                        recommendation="Prefer specific origins over scheme-wide allowlisting.",
                        category="dangerous-source",
                    )
                )
    return findings


def _scheme_behavior(scheme: str, directive_name: str) -> str:
    if scheme == "data:" and directive_name.startswith("script"):
        return (
            "data: URIs allow inline-equivalent script execution via "
            "<script src=\"data:...\">, which is a well-known CSP bypass vector."
        )
    if scheme == "http:":
        return "Any plaintext-HTTP origin may supply this resource, including on-path attackers."
    return f"Any host reachable via the '{scheme}' scheme is permitted."


def _nonce_hash_strict_dynamic_findings(policy: Policy, target: str, policy_type: str) -> List[Finding]:
    findings = []
    for name in ("script-src", "script-src-elem", "style-src", "style-src-elem"):
        directive = policy.get(name)
        if not directive:
            continue

        has_nonce = directive.any_nonce()
        has_hash = directive.any_hash()
        has_strict_dynamic = directive.has_keyword("strict-dynamic")
        has_unsafe_inline = directive.has_keyword("unsafe-inline")

        if has_strict_dynamic and not (has_nonce or has_hash):
            findings.append(
                _finding(
                    target=target,
                    policy_type=policy_type,
                    directive=name,
                    severity=Severity.VIOLATION,
                    confidence=Confidence.HIGH,
                    title=f"'strict-dynamic' without nonce/hash in {name}",
                    description=(
                        "'strict-dynamic' relies on a nonce or hash to establish the "
                        "initial trusted script(s); without one, no script can "
                        "bootstrap trust and legitimate scripts may silently fail, "
                        "or the directive provides no practical benefit."
                    ),
                    evidence=safe_join(directive.value_strings()),
                    effective_behavior=(
                        "Host/scheme allowlists in this directive are ignored by "
                        "browsers that support 'strict-dynamic' unless a nonce/hash "
                        "seeds initial trust."
                    ),
                    recommendation="Add a per-response nonce (or hash) alongside 'strict-dynamic'.",
                    category="modern-csp",
                )
            )

        if (has_nonce or has_hash) and not has_strict_dynamic and name.startswith("script"):
            findings.append(
                _finding(
                    target=target,
                    policy_type=policy_type,
                    directive=name,
                    severity=Severity.INFO,
                    confidence=Confidence.MEDIUM,
                    title=f"nonce/hash present without 'strict-dynamic' in {name}",
                    description=(
                        "A nonce or hash allowlist is used without 'strict-dynamic', "
                        "meaning dynamically created scripts (e.g. inserted by a "
                        "trusted, nonce'd bootstrap script) will NOT be trusted "
                        "unless they also carry the nonce/hash."
                    ),
                    evidence=safe_join(directive.value_strings()),
                    effective_behavior=(
                        "Only script tags carrying a matching nonce/hash execute; "
                        "any host allowlist present is still enforced independently."
                    ),
                    recommendation=(
                        "Consider adding 'strict-dynamic' to simplify trust propagation "
                        "for dynamically inserted scripts, if applicable to your app."
                    ),
                    category="modern-csp",
                )
            )

        if has_unsafe_inline and (has_nonce or has_hash):
            findings.append(
                _finding(
                    target=target,
                    policy_type=policy_type,
                    directive=name,
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    title=f"'unsafe-inline' redundant/ignored in {name}",
                    description=(
                        "CSP Level 2+ browsers ignore 'unsafe-inline' when a nonce or "
                        "hash source is also present in the same directive, so modern "
                        "browsers are unaffected."
                    ),
                    evidence=safe_join(directive.value_strings()),
                    effective_behavior=(
                        "Modern browsers: 'unsafe-inline' is ignored. Legacy browsers "
                        "without nonce/hash support: 'unsafe-inline' still applies and "
                        "materially weakens protection for those clients."
                    ),
                    recommendation="Retain 'unsafe-inline' only intentionally as a legacy-browser fallback; otherwise remove it.",
                    category="modern-csp",
                )
            )
    return findings


def _reporting_findings(policy: Policy, target: str, policy_type: str) -> List[Finding]:
    findings = []
    if not policy.has_directive("report-uri") and not policy.has_directive("report-to"):
        findings.append(
            _finding(
                target=target,
                policy_type=policy_type,
                directive=None,
                severity=Severity.WARN,
                confidence=Confidence.HIGH,
                title="No CSP violation reporting configured",
                description=(
                    "Neither 'report-uri' nor 'report-to' is present, so violation "
                    "reports are not collected."
                ),
                evidence=policy.raw,
                effective_behavior="Violations are still enforced by the browser, but no telemetry reaches the application/security team.",
                recommendation="Configure 'report-to' (and 'report-uri' as a fallback for older browsers) to capture violation reports.",
                category="reporting",
            )
        )
    if policy.has_directive("report-uri") and not policy.has_directive("report-to"):
        ru = policy.get("report-uri")
        findings.append(
            _finding(
                target=target,
                policy_type=policy_type,
                directive="report-uri",
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                title="Using legacy 'report-uri' without 'report-to'",
                description="'report-uri' is deprecated in favor of 'report-to' (which requires a Reporting-Endpoints/Report-To header).",
                evidence=safe_join(ru.value_strings()) if ru else "",
                effective_behavior="Modern browsers increasingly prefer/require 'report-to'; relying solely on 'report-uri' risks losing reports over time.",
                recommendation="Add 'report-to' alongside 'report-uri' for forward compatibility.",
                category="reporting",
            )
        )
    return findings


def _modern_feature_findings(policy: Policy, target: str, policy_type: str) -> List[Finding]:
    findings = []

    if policy.has_directive("script-src") and not policy.has_directive("require-trusted-types-for"):
        findings.append(
            _finding(
                target=target,
                policy_type=policy_type,
                directive="require-trusted-types-for",
                severity=Severity.INFO,
                confidence=Confidence.LOW,
                title="Trusted Types not enforced",
                description=(
                    "'require-trusted-types-for' is not set; Trusted Types provide "
                    "strong DOM-XSS sink protection in supporting browsers."
                ),
                evidence=policy.raw,
                effective_behavior="Dangerous DOM sinks (innerHTML, etc.) are not restricted to Trusted Types objects.",
                recommendation="Consider `require-trusted-types-for 'script'` with a `trusted-types` policy allowlist where feasible.",
                category="modern-csp",
            )
        )

    if not policy.has_directive("upgrade-insecure-requests"):
        findings.append(
            _finding(
                target=target,
                policy_type=policy_type,
                directive="upgrade-insecure-requests",
                severity=Severity.INFO,
                confidence=Confidence.LOW,
                title="'upgrade-insecure-requests' not set",
                description="Mixed-content HTTP subresource requests are not automatically upgraded to HTTPS by CSP.",
                evidence=policy.raw,
                effective_behavior="HTTP subresource requests on an HTTPS page are not auto-upgraded (browsers may still block/warn via mixed-content rules independently).",
                recommendation="Add 'upgrade-insecure-requests' if the site is fully HTTPS-capable.",
                category="modern-csp",
            )
        )

    return findings


def _object_src_base_uri_findings(effective: EffectivePolicy, target: str, policy_type: str) -> List[Finding]:
    findings = []
    obj = effective.get_effective("object-src")
    if obj and obj.directive is not None:
        if not obj.directive.has_keyword("none"):
            findings.append(
                _finding(
                    target=target,
                    policy_type=policy_type,
                    directive="object-src",
                    severity=Severity.WARN,
                    confidence=Confidence.MEDIUM,
                    title="object-src is not restricted to 'none'",
                    description="OWASP and CSP best practice recommend `object-src 'none'` unless legacy plugins are required.",
                    evidence=safe_join(obj.directive.value_strings()),
                    effective_behavior="Plugin-driven content (e.g. Flash/legacy objects) may still be embeddable, which is a historically common XSS/UXSS vector.",
                    recommendation="Set `object-src 'none'` unless plugin content is explicitly required.",
                    category="best-practice",
                )
            )
    return findings


def _default_src_reliance_findings(policy: Policy, target: str, policy_type: str) -> List[Finding]:
    findings = []
    default_src = policy.get("default-src")
    explicit_fetch_directives = {n for n in policy.directives if n in FALLBACK_CHAINS}
    if default_src and len(explicit_fetch_directives) == 0:
        findings.append(
            _finding(
                target=target,
                policy_type=policy_type,
                directive="default-src",
                severity=Severity.INFO,
                confidence=Confidence.MEDIUM,
                title="Sole reliance on default-src",
                description=(
                    "No fetch directives besides 'default-src' are explicitly set; "
                    "every resource type shares the same, likely broader-than-necessary, allowlist."
                ),
                evidence=safe_join(default_src.value_strings()),
                effective_behavior="script-src, style-src, img-src, connect-src, etc. all inherit exactly default-src's value.",
                recommendation="Define explicit, minimally-scoped directives (especially script-src and object-src) rather than relying solely on default-src.",
                category="best-practice",
            )
        )
    return findings


def _meta_specific_findings(policy: Policy, target: str, policy_type: str) -> List[Finding]:
    findings = []
    for name, explanation in META_IGNORED_DIRECTIVES.items():
        if policy.has_directive(name):
            d = policy.get(name)
            findings.append(
                _finding(
                    target=target,
                    policy_type=policy_type,
                    directive=name,
                    severity=Severity.WARN,
                    confidence=Confidence.CERTAIN,
                    title=f"'{name}' has no effect in a <meta> CSP",
                    description=explanation,
                    evidence=safe_join(d.value_strings()) if d else "",
                    effective_behavior="Browsers silently ignore this directive when delivered via <meta http-equiv>.",
                    recommendation=f"Deliver '{name}' via the Content-Security-Policy HTTP header instead.",
                    category="meta-csp",
                )
            )
    return findings
