"""
Centralized logger factory.

Rationale: rather than each module calling `logging.basicConfig` (which is
global, order-dependent, and awkward to test), we expose a single
`get_logger()` used everywhere, plus a `configure_logging()` called once by
the CLI entry point after config.yaml has been loaded.
"""

from __future__ import annotations

import logging
import sys

_CONFIGURED = False

_LEVEL_MAP = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "WARN": logging.WARNING,
    "ERROR": logging.ERROR,
    "CRITICAL": logging.CRITICAL,
}


def configure_logging(level: str = "INFO") -> None:
    """Configure root logging once. Safe to call multiple times (idempotent)."""
    global _CONFIGURED
    root = logging.getLogger("csp_auditor")
    root.setLevel(_LEVEL_MAP.get(level.upper(), logging.INFO))

    if not _CONFIGURED:
        handler = logging.StreamHandler(stream=sys.stderr)
        formatter = logging.Formatter(
            fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S%z",
        )
        handler.setFormatter(formatter)
        root.addHandler(handler)
        root.propagate = False
        _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    """Return a namespaced child logger, e.g. csp_auditor.collector."""
    if not _CONFIGURED:
        configure_logging("INFO")
    return logging.getLogger(f"csp_auditor.{name}")
