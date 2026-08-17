"""
Small, dependency-free helper functions shared across modules.

Nothing in this module should depend on any other csp_auditor module except
`exceptions`, to keep it safely importable from anywhere without risking
circular imports.
"""

from __future__ import annotations

import re
from typing import Iterable, Optional
from urllib.parse import urlparse

_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+\-.]*:$")


def is_scheme_source(token: str) -> bool:
    """True for bare-scheme sources like `https:`, `data:`, `blob:`."""
    return bool(_SCHEME_RE.match(token.strip()))


def strip_quotes(token: str) -> str:
    """Strip a single layer of matching single quotes, if present."""
    t = token.strip()
    if len(t) >= 2 and t.startswith("'") and t.endswith("'"):
        return t[1:-1]
    return t


def is_wildcard_source(token: str) -> bool:
    t = token.strip()
    return t == "*" or t.startswith("*.")


def truncate(text: Optional[str], length: int = 240) -> str:
    if not text:
        return ""
    text = text.strip()
    if len(text) <= length:
        return text
    return text[: length - 1].rstrip() + "\u2026"


def host_of(url: str) -> str:
    try:
        return urlparse(url).netloc
    except Exception:
        return url


_SCHEME_PREFIX_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")


def extract_hostname(source_expression: str) -> Optional[str]:
    """
    Extract the hostname portion of a CSP source expression, tolerating an
    optional scheme prefix, path, port, and a leading '*.' wildcard label.

    Returns None for values that aren't host-shaped at all (empty string).
    Examples:
        "https://cdn.example.com/path"  -> "cdn.example.com"
        "cdn.example.com:8443"          -> "cdn.example.com"
        "*.example.com"                 -> "*.example.com"
        "wss://sub.example.com"         -> "sub.example.com"
    """
    s = source_expression.strip()
    if not s:
        return None

    is_wildcard = s.startswith("*.")
    remainder = s[2:] if is_wildcard else s

    remainder = _SCHEME_PREFIX_RE.sub("", remainder)
    remainder = remainder.split("/", 1)[0]
    remainder = remainder.split(":", 1)[0]

    if not remainder:
        return None

    return f"*.{remainder}" if is_wildcard else remainder


def dedupe_preserve_order(items: Iterable[str]) -> list:
    seen = set()
    out = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def safe_join(items: Iterable[str], sep: str = ", ", empty: str = "(none)") -> str:
    items = list(items)
    if not items:
        return empty
    return sep.join(items)
