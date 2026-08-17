"""
Exception hierarchy for csp_auditor.

Keeping a dedicated exceptions module avoids circular imports (every other
module can safely import from here without depending on the rest of the
package) and gives callers a stable, documented set of failure modes to
catch.
"""

from __future__ import annotations


class CSPAuditorError(Exception):
    """Base class for all csp_auditor exceptions."""


# --------------------------------------------------------------------------
# Configuration errors
# --------------------------------------------------------------------------
class ConfigurationError(CSPAuditorError):
    """Raised when config.yaml is missing, malformed, or invalid."""


# --------------------------------------------------------------------------
# Collection errors
# --------------------------------------------------------------------------
class CollectionError(CSPAuditorError):
    """Base class for HTTP collection failures."""


class NetworkError(CollectionError):
    """Raised for connection failures, DNS errors, timeouts, etc."""


class RedirectLoopError(CollectionError):
    """Raised when a redirect chain exceeds the configured limit or loops."""


class TLSVerificationError(CollectionError):
    """Raised when certificate verification fails and is not overridden."""


# --------------------------------------------------------------------------
# Parsing errors
# --------------------------------------------------------------------------
class CSPParseError(CSPAuditorError):
    """
    Raised for unrecoverable parser failures.

    Note: per spec, most malformed CSP constructs should NOT raise -- the
    parser should degrade gracefully and record a ParserIssue on the
    resulting Policy object instead. This exception is reserved for truly
    exceptional situations (e.g. non-string input).
    """


# --------------------------------------------------------------------------
# Evaluation / comparison / scoring errors
# --------------------------------------------------------------------------
class EvaluationError(CSPAuditorError):
    """Raised when the evaluation engine cannot process a Policy."""


class ComparisonError(CSPAuditorError):
    """Raised when two policies cannot be meaningfully compared."""


class ScoringError(CSPAuditorError):
    """Raised when scoring cannot be computed from a set of findings."""


# --------------------------------------------------------------------------
# Reporting errors
# --------------------------------------------------------------------------
class ReportingError(CSPAuditorError):
    """Raised when a report cannot be generated or written to disk."""
