"""
CSP Parser.

Single responsibility: turn a raw CSP header/meta string into a structured
`Policy` object (see models.py). This module performs NO security
evaluation and NO scoring — it only parses, and it does so defensively:
malformed input must never raise or crash the pipeline. Problems are
recorded as `ParserIssue` entries on the resulting `Policy`.

Reference behavior modeled here follows the CSP Level 3 grammar
(https://www.w3.org/TR/CSP3/#framework-directives):

  serialized-CSP       = directive-list
  directive-list       = [ directive *( ";" [ directive ] ) ]
  directive             = directive-name [ RWS directive-value ]
  directive-name        = 1*( ALPHA / DIGIT / "-" )
  directive-value       = *( %x09 / %x20-%x2B / %x2D-%x3A / %x3C-%x7E )

In practice, browsers are lenient: directives are split on ';', values are
split on runs of whitespace, unknown directives are preserved-but-ignored,
and duplicate directive names within one policy are resolved by browsers
using "first occurrence wins" (subsequent duplicates are ignored for
enforcement purposes, but we still surface them as a finding-worthy
condition upstream).
"""

from __future__ import annotations

import re
from typing import Optional

from csp_auditor.exceptions import CSPParseError
from csp_auditor.logging_utils import get_logger
from csp_auditor.models import Directive, ParserIssue, Policy, PolicySource, SourceExpression
from csp_auditor.utils import is_scheme_source, is_wildcard_source, strip_quotes

logger = get_logger("parser")

# Recognized CSP Level 2/3 directives (kept broad so "unknown directive"
# detection has a meaningful baseline). Obsolete/deprecated directives are
# tracked separately so they can be flagged rather than silently accepted.
KNOWN_DIRECTIVES = {
    # Fetch directives
    "child-src", "connect-src", "default-src", "font-src", "frame-src",
    "img-src", "manifest-src", "media-src", "object-src", "prefetch-src",
    "script-src", "script-src-elem", "script-src-attr", "style-src",
    "style-src-elem", "style-src-attr", "worker-src",
    # Document directives
    "base-uri", "sandbox",
    # Navigation directives
    "form-action", "frame-ancestors", "navigate-to",
    # Reporting directives
    "report-uri", "report-to",
    # Other directives
    "block-all-mixed-content", "upgrade-insecure-requests",
    "require-trusted-types-for", "trusted-types",
}

OBSOLETE_DIRECTIVES = {
    "reflected-xss": "Removed from CSP; use the X-XSS-Protection header (also deprecated) or rely on script-src.",
    "referrer": "Removed from CSP; use the Referrer-Policy header instead.",
    "plugin-types": "Deprecated alongside <object>/<embed> plugin usage; use object-src 'none'.",
    "disown-opener": "Never standardized/removed; has no effect in modern browsers.",
    "child-src": "Superseded by frame-src and worker-src in CSP Level 3 (still honored as fallback, not fully obsolete).",
}

# Directives whose value grammar is a source-list (as opposed to a keyword,
# boolean, or URI-list with different semantics).
SOURCE_LIST_DIRECTIVES = {
    "child-src", "connect-src", "default-src", "font-src", "frame-src",
    "img-src", "manifest-src", "media-src", "object-src", "prefetch-src",
    "script-src", "script-src-elem", "script-src-attr", "style-src",
    "style-src-elem", "style-src-attr", "worker-src", "base-uri",
    "form-action", "frame-ancestors", "navigate-to",
}

_KEYWORD_TOKENS = {
    "self", "unsafe-inline", "unsafe-eval", "unsafe-hashes",
    "unsafe-allow-redirects", "none", "strict-dynamic", "report-sample",
}

_NONCE_RE = re.compile(r"^nonce-.+$", re.IGNORECASE)
_HASH_RE = re.compile(r"^(sha256|sha384|sha512)-[A-Za-z0-9+/_=\-]+$", re.IGNORECASE)

_DIRECTIVE_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9\-]*$")


def _classify_token(token: str) -> SourceExpression:
    """Build a SourceExpression, classifying keyword/nonce/hash/scheme/wildcard."""
    raw = token
    malformed = False

    # Quoted tokens: 'self', 'none', 'nonce-...', 'sha256-...'
    if token.startswith("'") or token.endswith("'"):
        if not (token.startswith("'") and token.endswith("'") and len(token) >= 2):
            malformed = True
        inner = strip_quotes(token)
    else:
        inner = token

    normalized = inner.lower()

    is_keyword = normalized in _KEYWORD_TOKENS
    is_nonce = bool(_NONCE_RE.match(normalized))
    is_hash = bool(_HASH_RE.match(normalized))
    is_scheme = is_scheme_source(inner)
    is_wildcard = is_wildcard_source(inner)

    # A quoted token that isn't a recognized keyword/nonce/hash pattern is
    # suspicious (e.g. a typo'd keyword like 'unsafe-inlin').
    if token.startswith("'") and token.endswith("'") and not (
        is_keyword or is_nonce or is_hash
    ):
        malformed = True

    return SourceExpression(
        raw=raw,
        normalized=normalized,
        is_keyword=is_keyword,
        is_nonce=is_nonce,
        is_hash=is_hash,
        is_scheme=is_scheme,
        is_wildcard=is_wildcard,
        malformed=malformed,
    )


def parse_policy(
    raw_policy: str,
    source: PolicySource,
    origin_url: Optional[str] = None,
) -> Policy:
    """
    Parse a single raw CSP string into a structured Policy.

    This function never raises for malformed CSP content; it only raises
    CSPParseError for programmer errors (non-string input).
    """
    if not isinstance(raw_policy, str):
        raise CSPParseError(f"Expected str for raw_policy, got {type(raw_policy)!r}")

    policy = Policy(raw=raw_policy, source=source, origin_url=origin_url)

    if not raw_policy.strip():
        policy.parser_issues.append(
            ParserIssue(message="Policy string is empty after stripping whitespace.")
        )
        return policy

    # Directives are separated by ';'. Multiple ';' or trailing ';' are
    # tolerated by browsers and simply yield empty directive fragments,
    # which we skip.
    raw_directives = [d for d in raw_policy.split(";")]

    for raw_directive in raw_directives:
        fragment = raw_directive.strip()
        if not fragment:
            continue

        # Split directive-name from directive-value on the first run of
        # whitespace.
        parts = fragment.split(None, 1)
        raw_name = parts[0]
        value_str = parts[1] if len(parts) > 1 else ""

        if not _DIRECTIVE_NAME_RE.match(raw_name):
            policy.parser_issues.append(
                ParserIssue(
                    message=f"Skipping malformed directive token: '{raw_name}'",
                    raw_fragment=fragment,
                )
            )
            continue

        name = raw_name.lower()
        is_unknown = name not in KNOWN_DIRECTIVES and name not in OBSOLETE_DIRECTIVES
        is_obsolete = name in OBSOLETE_DIRECTIVES

        is_duplicate = name in policy.directives
        if is_duplicate:
            policy.parser_issues.append(
                ParserIssue(
                    message=(
                        f"Duplicate directive '{name}' encountered; per CSP spec, "
                        "browsers honor only the first occurrence within a single "
                        "policy and ignore subsequent duplicates."
                    ),
                    directive=name,
                    raw_fragment=fragment,
                )
            )
            # First occurrence wins per spec — do not overwrite.
            # Still mark the *original* directive as having a duplicate seen.
            existing = policy.directives[name]
            existing.is_duplicate = True
            if is_unknown:
                continue
            continue

        values = []
        if value_str.strip():
            tokens = value_str.split()
            for tok in tokens:
                values.append(_classify_token(tok))

        directive = Directive(
            name=name,
            raw_name=raw_name,
            values=values,
            is_duplicate=False,
            is_unknown=is_unknown,
            is_obsolete=is_obsolete,
        )

        if is_unknown:
            policy.parser_issues.append(
                ParserIssue(
                    message=f"Unrecognized/unknown directive '{raw_name}'.",
                    directive=name,
                    raw_fragment=fragment,
                )
            )

        if is_obsolete:
            policy.parser_issues.append(
                ParserIssue(
                    message=(
                        f"Directive '{raw_name}' is obsolete/deprecated: "
                        f"{OBSOLETE_DIRECTIVES.get(name, 'no longer effective in modern browsers.')}"
                    ),
                    directive=name,
                    raw_fragment=fragment,
                )
            )

        # Flag malformed tokens within an otherwise valid directive.
        for v in values:
            if v.malformed:
                policy.parser_issues.append(
                    ParserIssue(
                        message=f"Malformed source expression '{v.raw}' in directive '{name}'.",
                        directive=name,
                        raw_fragment=fragment,
                    )
                )

        policy.directives[name] = directive

    return policy


def parse_multiple(
    raw_policies: list,
    source: PolicySource,
    origin_url: Optional[str] = None,
) -> list:
    """
    Parse a list of raw CSP strings (e.g. multiple CSP headers on one
    response, or multiple <meta> tags) into a list of Policy objects.

    Per spec, multiple Content-Security-Policy headers are combined by the
    browser via *intersection* (each additional header can only further
    restrict, never relax). We deliberately do NOT merge them here — the
    evaluator is responsible for modeling that intersection behavior against
    structured Policy objects; the parser's job is limited to producing one
    Policy per raw string.
    """
    return [
        parse_policy(raw, source=source, origin_url=origin_url)
        for raw in raw_policies
        if raw is not None
    ]
