"""
csp_auditor
===========

A production-grade Content Security Policy (CSP) assessment framework.

This package collects, parses, evaluates, compares, scores, and reports on
Content Security Policies deployed by web applications, modeling effective
browser behavior rather than performing naive string validation.

Public API is intentionally small; consumers should typically drive the
framework through `main.py` (CLI) or by composing the pipeline stages
found in the individual modules:

    csp_auditor.collector      -> HTTP collection / redirect handling
    csp_auditor.parser         -> CSP string -> structured Policy objects
    csp_auditor.evaluator      -> effective-policy evaluation & findings
    csp_auditor.comparator     -> enforced vs report-only comparison
    csp_auditor.scoring        -> numeric/letter-grade scoring
    csp_auditor.reporter       -> console + JSON reporting
    csp_auditor.configuration  -> config.yaml loading & validation
    csp_auditor.models         -> shared dataclasses
    csp_auditor.exceptions     -> exception hierarchy
    csp_auditor.logging_utils  -> centralized logger factory
    csp_auditor.utils          -> small shared helpers
"""

__version__ = "1.0.0"
