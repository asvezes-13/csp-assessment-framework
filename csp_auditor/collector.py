"""
HTTP Collector.

Single responsibility: perform HTTP collection for a Target, manually
walking the redirect chain (so every hop can be individually inspected for
CSP presence/absence/change), extracting raw CSP-related material:

  - Content-Security-Policy header(s)          -> enforced
  - Content-Security-Policy-Report-Only header(s) -> report-only
  - <meta http-equiv="Content-Security-Policy"> tags in HTML responses

This module does NOT parse CSP strings into structured Policy objects
(that's parser.py's job) and does NOT evaluate security posture. It emits
raw strings plus the RedirectChain / HTTPResponse models so downstream
stages have full context (evidence, ordering, which hop introduced/dropped
a policy, etc).

Reliability behavior:
  - Configurable timeout, retries with exponential backoff, SSL verification
  - Manual redirect following up to `max_redirects`, guarding redirect loops
  - Any failure for one target is captured on RedirectChain.error and never
    propagates to crash the whole audit run.
"""

from __future__ import annotations

import re
import time
from typing import List, Optional, Tuple

import httpx

from csp_auditor.configuration import NetworkConfig
from csp_auditor.exceptions import NetworkError, RedirectLoopError
from csp_auditor.logging_utils import get_logger
from csp_auditor.models import HTTPResponse, RedirectChain, Target

logger = get_logger("collector")

CSP_HEADER = "content-security-policy"
CSP_RO_HEADER = "content-security-policy-report-only"

_META_CSP_RE = re.compile(
    r"""<meta\s+[^>]*http-equiv\s*=\s*["']content-security-policy["'][^>]*>""",
    re.IGNORECASE,
)
# Uses a backreference to the opening quote char so that CSP values which
# themselves contain the *other* quote character (e.g. content="default-src
# 'self'") are captured in full rather than truncated at the first inner
# quote.
_META_CONTENT_RE = re.compile(
    r"""content\s*=\s*(["'])(.*?)\1""",
    re.IGNORECASE | re.DOTALL,
)


def extract_meta_csps(html: str) -> List[str]:
    """Extract every <meta http-equiv="Content-Security-Policy"> content value."""
    if not html:
        return []
    results = []
    for tag_match in _META_CSP_RE.finditer(html):
        tag = tag_match.group(0)
        content_match = _META_CONTENT_RE.search(tag)
        if content_match:
            results.append(content_match.group(2))
    return results


class HTTPCollector:
    """
    Collects redirect-chain-aware HTTP data for a single Target, with retry
    and backoff. One instance can be reused across multiple targets.
    """

    def __init__(self, network: NetworkConfig, transport: Optional["httpx.BaseTransport"] = None):
        """
        `transport` is exposed primarily for testability (inject an
        httpx.MockTransport instead of hitting the real network); production
        callers should leave it as None.
        """
        self.network = network
        self._transport = transport

    # ----------------------------------------------------------------
    def collect(self, target: Target) -> RedirectChain:
        """Collect the full redirect chain for a target. Never raises."""
        chain = RedirectChain(target=target)

        max_redirects = target.max_redirects or self.network.max_redirects
        timeout = target.timeout or self.network.timeout
        verify_ssl = self.network.verify_ssl if target.verify_ssl is None else target.verify_ssl

        current_url = target.url
        visited = set()

        try:
            with httpx.Client(
                verify=verify_ssl,
                follow_redirects=False,
                timeout=timeout,
                headers={"User-Agent": self.network.user_agent},
                transport=self._transport,
            ) as client:
                for hop_index in range(max_redirects + 1):
                    if current_url in visited:
                        chain.error = f"Redirect loop detected at {current_url}"
                        chain.truncated = True
                        logger.warning("Redirect loop detected for %s at hop %s", target.url, hop_index)
                        break
                    visited.add(current_url)

                    response = self._fetch_with_retry(client, current_url)
                    http_resp = self._to_http_response(current_url, response)
                    chain.hops.append(http_resp)

                    if http_resp.is_redirect and http_resp.redirect_location:
                        current_url = self._resolve_redirect(current_url, http_resp.redirect_location)
                        continue
                    break
                else:
                    chain.truncated = True
                    chain.error = (
                        f"Exceeded max_redirects ({max_redirects}) without reaching a final response."
                    )
                    logger.warning(
                        "Target %s exceeded max_redirects=%s", target.url, max_redirects
                    )

        except NetworkError as exc:
            chain.error = str(exc)
            logger.error("Collection failed for %s: %s", target.url, exc)
        except Exception as exc:  # pragma: no cover - absolute last-resort guard
            chain.error = f"Unexpected collection failure: {exc}"
            logger.exception("Unexpected error collecting %s", target.url)

        return chain

    # ----------------------------------------------------------------
    def _fetch_with_retry(self, client: "httpx.Client", url: str) -> "httpx.Response":
        last_exc: Optional[Exception] = None
        for attempt in range(self.network.retry_count + 1):
            try:
                start = time.monotonic()
                resp = client.get(url)
                resp.elapsed_override = time.monotonic() - start  # type: ignore[attr-defined]
                return resp
            except (httpx.ConnectTimeout, httpx.ReadTimeout, httpx.ConnectError,
                     httpx.RemoteProtocolError, httpx.PoolTimeout) as exc:
                last_exc = exc
                if attempt < self.network.retry_count:
                    backoff = self.network.retry_backoff * (2 ** attempt)
                    logger.debug(
                        "Retry %s/%s for %s after %s (%.2fs backoff)",
                        attempt + 1, self.network.retry_count, url, exc.__class__.__name__, backoff,
                    )
                    time.sleep(backoff)
                else:
                    break
            except httpx.HTTPError as exc:
                last_exc = exc
                break

        raise NetworkError(f"Failed to fetch {url} after retries: {last_exc}")

    # ----------------------------------------------------------------
    @staticmethod
    def _to_http_response(url: str, response: "httpx.Response") -> HTTPResponse:
        is_redirect = 300 <= response.status_code < 400 and "location" in response.headers
        redirect_location = response.headers.get("location") if is_redirect else None

        content_type = response.headers.get("content-type")
        body: Optional[str] = None

        # Only decode body text for HTML/XHTML content, and only if not a
        # redirect (redirect bodies are irrelevant and may be huge).
        if not is_redirect and content_type and (
            "text/html" in content_type.lower() or "application/xhtml+xml" in content_type.lower()
        ):
            try:
                body = response.text
            except Exception:
                body = None

        elapsed = getattr(response, "elapsed_override", None)
        if elapsed is None:
            try:
                elapsed = response.elapsed.total_seconds()
            except Exception:
                elapsed = 0.0

        return HTTPResponse(
            url=url,
            status_code=response.status_code,
            headers=dict(response.headers),
            content_type=content_type,
            body=body,
            elapsed_seconds=elapsed,
            is_redirect=is_redirect,
            redirect_location=redirect_location,
        )

    # ----------------------------------------------------------------
    @staticmethod
    def _resolve_redirect(current_url: str, location: str) -> str:
        return str(httpx.URL(current_url).join(location))


def extract_csp_material(response: HTTPResponse) -> Tuple[List[str], List[str], List[str]]:
    """
    Given a single HTTPResponse, return (enforced_csps, report_only_csps,
    meta_csps) as raw strings, without merging them.
    """
    enforced = response.all_headers(CSP_HEADER)
    report_only = response.all_headers(CSP_RO_HEADER)
    meta = extract_meta_csps(response.body) if response.is_html and response.body else []
    return enforced, report_only, meta
