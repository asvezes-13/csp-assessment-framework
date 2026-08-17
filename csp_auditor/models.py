"""
Structured data models shared across the entire pipeline.

Design intent
--------------
Every stage of the pipeline (collector -> parser -> evaluator -> comparator
-> scoring -> reporter) communicates exclusively through these dataclasses.
No stage after the parser should ever re-parse a raw CSP string; instead it
operates on `Policy` / `Directive` / `SourceExpression` objects.

All models are intentionally "dumb" data containers (no business logic
beyond simple derived properties) so that behavior stays in the dedicated
engine modules (evaluator, comparator, scoring) and each concern remains
independently testable.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


# ==========================================================================
# Enums
# ==========================================================================
class PolicySource(str, enum.Enum):
    """Where a policy string was found."""

    HEADER_ENFORCED = "header_enforced"
    HEADER_REPORT_ONLY = "header_report_only"
    META_TAG = "meta_tag"


class Severity(str, enum.Enum):
    """Finding severity, ordered from least to most severe."""

    INFO = "INFO"
    WARN = "WARN"
    VIOLATION = "VIOLATION"
    ALARM = "ALARM"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        order = [
            Severity.INFO,
            Severity.WARN,
            Severity.VIOLATION,
            Severity.ALARM,
            Severity.CRITICAL,
        ]
        return order.index(self)


class Confidence(str, enum.Enum):
    """How certain the evaluator is about a given finding."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CERTAIN = "CERTAIN"


class ChangeClassification(str, enum.Enum):
    """Classification applied by the comparator to a single directive diff."""

    IMPROVEMENT = "Improvement"
    REGRESSION = "Regression"
    NEUTRAL = "Neutral"
    ADDED = "Added"
    REMOVED = "Removed"
    UNCHANGED = "Unchanged"


class MigrationReadiness(str, enum.Enum):
    """Overall assessment of Report-Only -> Enforced migration readiness."""

    READY = "Ready to enforce"
    NEARLY_READY = "Nearly ready — minor blockers"
    NOT_READY = "Not ready — significant blockers"
    NOT_APPLICABLE = "Not applicable"
    REGRESSION_RISK = "Report-Only is weaker than enforced — do not promote"


# ==========================================================================
# Target / HTTP models
# ==========================================================================
@dataclass
class Target:
    """A single audit target as defined in config.yaml."""

    url: str
    name: Optional[str] = None
    timeout: Optional[float] = None
    verify_ssl: Optional[bool] = None
    max_redirects: Optional[int] = None
    labels: dict = field(default_factory=dict)

    @property
    def display_name(self) -> str:
        return self.name or self.url


@dataclass
class HTTPResponse:
    """A single HTTP response captured during collection (one hop)."""

    url: str
    status_code: int
    headers: dict
    content_type: Optional[str]
    body: Optional[str]
    elapsed_seconds: float
    is_redirect: bool
    redirect_location: Optional[str] = None
    fetched_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def header(self, name: str) -> Optional[str]:
        """Case-insensitive header lookup."""
        target = name.lower()
        for key, value in self.headers.items():
            if key.lower() == target:
                return value
        return None

    def all_headers(self, name: str) -> list:
        """Return all values for a (possibly repeated) header, case-insensitive."""
        target = name.lower()
        return [v for k, v in self.headers.items() if k.lower() == target]

    @property
    def is_html(self) -> bool:
        if not self.content_type:
            return False
        ct = self.content_type.lower()
        return "text/html" in ct or "application/xhtml+xml" in ct


@dataclass
class RedirectChain:
    """The full sequence of HTTP responses observed for one Target."""

    target: Target
    hops: list = field(default_factory=list)  # list[HTTPResponse]
    truncated: bool = False
    error: Optional[str] = None

    @property
    def final_response(self) -> Optional[HTTPResponse]:
        return self.hops[-1] if self.hops else None

    @property
    def hop_count(self) -> int:
        return len(self.hops)


# ==========================================================================
# CSP structural models
# ==========================================================================
@dataclass
class SourceExpression:
    """
    A single token within a directive's value list.

    e.g. 'self', 'unsafe-inline', https://example.com, *.cdn.com,
    'nonce-abc123', 'sha256-abcd...'
    """

    raw: str
    normalized: str  # lower-cased, quote-stripped where applicable
    is_keyword: bool = False
    is_nonce: bool = False
    is_hash: bool = False
    is_scheme: bool = False
    is_wildcard: bool = False
    malformed: bool = False


@dataclass
class Directive:
    """A single CSP directive, e.g. `script-src 'self' https://cdn.example.com`."""

    name: str  # normalized (lower-case) directive name
    raw_name: str  # original casing as encountered
    values: list = field(default_factory=list)  # list[SourceExpression]
    is_duplicate: bool = False  # True if this directive name repeated within one policy
    is_unknown: bool = False  # True if not a recognized CSP directive
    is_obsolete: bool = False  # True if directive is deprecated/ignored by modern browsers

    def has_keyword(self, keyword: str) -> bool:
        keyword = keyword.strip("'").lower()
        return any(v.normalized == keyword for v in self.values)

    def has_value(self, value: str) -> bool:
        value = value.lower()
        return any(v.normalized == value for v in self.values)

    def any_nonce(self) -> bool:
        return any(v.is_nonce for v in self.values)

    def any_hash(self) -> bool:
        return any(v.is_hash for v in self.values)

    def value_strings(self) -> list:
        return [v.raw for v in self.values]


@dataclass
class ParserIssue:
    """A non-fatal problem encountered while parsing a policy string."""

    message: str
    directive: Optional[str] = None
    raw_fragment: Optional[str] = None


@dataclass
class Policy:
    """
    A fully parsed CSP, independent of where it was found.

    `source` distinguishes enforced header / report-only header / meta tag
    policies. `raw` retains the original string for auditability/evidence.
    """

    raw: str
    source: PolicySource
    directives: dict = field(default_factory=dict)  # name -> Directive
    parser_issues: list = field(default_factory=list)  # list[ParserIssue]
    origin_url: Optional[str] = None

    def get(self, name: str) -> Optional[Directive]:
        return self.directives.get(name.lower())

    def has_directive(self, name: str) -> bool:
        return name.lower() in self.directives

    @property
    def is_empty(self) -> bool:
        return len(self.directives) == 0 and not self.raw.strip()


@dataclass
class EffectiveDirective:
    """
    The *effective* resolution of a directive after applying CSP inheritance
    rules (fallback to default-src, etc).
    """

    name: str
    directive: Optional[Directive]  # None if nothing applies even after fallback
    is_explicit: bool  # True if directive was explicitly declared
    inherited_from: Optional[str] = None  # e.g. "default-src" if fallback applied
    explanation: str = ""


@dataclass
class EffectivePolicy:
    """
    The resolved, browser-accurate view of a Policy after applying
    inheritance / fallback semantics.
    """

    policy: Policy
    effective_directives: dict = field(default_factory=dict)  # name -> EffectiveDirective

    def get_effective(self, name: str) -> Optional[EffectiveDirective]:
        return self.effective_directives.get(name.lower())


# ==========================================================================
# Findings / Reporting models
# ==========================================================================
@dataclass
class Finding:
    """A single security-relevant observation."""

    target: str
    policy_type: str  # e.g. "Enforced", "Report-Only", "Meta"
    directive: Optional[str]
    severity: Severity
    confidence: Confidence
    title: str
    description: str
    evidence: str
    effective_behavior: str
    recommendation: str
    reference: str = "CSP Level 3 Specification; OWASP CSP Cheat Sheet"
    category: str = "general"


@dataclass
class DirectiveComparison:
    """Side-by-side comparison of one directive across enforced vs report-only."""

    directive: str
    enforced_summary: str
    report_only_summary: str
    classification: ChangeClassification
    explanation: str


@dataclass
class PolicyComparisonResult:
    """Full comparison result between an enforced and a report-only policy."""

    directive_comparisons: list = field(default_factory=list)  # list[DirectiveComparison]
    added_directives: list = field(default_factory=list)
    removed_directives: list = field(default_factory=list)
    tightened_directives: list = field(default_factory=list)
    relaxed_directives: list = field(default_factory=list)
    overall_relationship: str = "Unrelated configuration"
    migration_readiness: MigrationReadiness = MigrationReadiness.NOT_APPLICABLE
    blockers: list = field(default_factory=list)
    guidance: list = field(default_factory=list)


@dataclass
class Score:
    """Numeric + qualitative scoring for a single policy."""

    numeric_score: float  # 0-100
    letter_grade: str  # A-F
    severity_counts: dict = field(default_factory=dict)  # Severity -> count
    finding_count: int = 0
    complexity_metrics: dict = field(default_factory=dict)


@dataclass
class TargetReport:
    """Full assessment result for a single target."""

    target: Target
    redirect_chain: Optional[RedirectChain]
    enforced_policy: Optional[Policy]
    report_only_policy: Optional[Policy]
    meta_policies: list  # list[Policy]
    enforced_effective: Optional[EffectivePolicy]
    report_only_effective: Optional[EffectivePolicy]
    findings: list  # list[Finding]
    enforced_score: Optional[Score]
    report_only_score: Optional[Score]
    comparison: Optional[PolicyComparisonResult]
    collection_error: Optional[str] = None


@dataclass
class Report:
    """Top-level report aggregating all targets in an audit run."""

    generated_at: datetime
    framework_version: str
    target_reports: list  # list[TargetReport]
    run_config_summary: dict = field(default_factory=dict)

    @property
    def target_count(self) -> int:
        return len(self.target_reports)
