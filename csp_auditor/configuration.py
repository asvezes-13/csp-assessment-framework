"""
Configuration Manager.

Loads and validates config.yaml, producing a strongly-typed `AppConfig`
object. All other modules receive already-validated configuration values;
nothing downstream should read environment variables or files directly,
and no configuration values are hardcoded elsewhere in the package.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml

from csp_auditor.exceptions import ConfigurationError
from csp_auditor.models import Target

_DEFAULT_REQUIRED_DIRECTIVES = ["default-src", "object-src", "base-uri"]
_DEFAULT_FORBIDDEN_KEYWORDS = ["unsafe-inline", "unsafe-eval"]


@dataclass
class NetworkConfig:
    timeout: float = 10.0
    retry_count: int = 3
    retry_backoff: float = 0.5
    verify_ssl: bool = True
    max_redirects: int = 10
    concurrency: int = 8
    user_agent: str = "csp-auditor/1.0 (+https://github.com/your-org/csp-assessment-framework)"


@dataclass
class PolicyRulesConfig:
    required_directives: list = field(default_factory=lambda: list(_DEFAULT_REQUIRED_DIRECTIVES))
    forbidden_keywords: list = field(default_factory=lambda: list(_DEFAULT_FORBIDDEN_KEYWORDS))


@dataclass
class OutputConfig:
    output_dir: str = "reports"
    output_format: str = "json"  # json | console | both
    console_color: bool = True


@dataclass
class HostAllowlistConfig:
    """
    Configuration for the Host Reputation (allowlist) module.

    Disabled by default: an empty/absent 'host_allowlist' section in
    config.yaml means the module is skipped entirely, so existing configs
    keep working unchanged.
    """

    enabled: bool = False
    trusted_domains: list = field(default_factory=list)
    severity: str = "WARN"
    directives: list = field(
        default_factory=lambda: [
            "default-src", "script-src", "script-src-elem", "script-src-attr",
            "style-src", "style-src-elem", "style-src-attr", "img-src",
            "connect-src", "font-src", "media-src", "object-src",
            "manifest-src", "prefetch-src", "child-src", "frame-src",
            "worker-src", "form-action", "frame-ancestors", "base-uri",
            "navigate-to",
        ]
    )


@dataclass
class AppConfig:
    targets: list  # list[Target]
    network: NetworkConfig
    policy_rules: PolicyRulesConfig
    output: OutputConfig
    host_allowlist: HostAllowlistConfig
    logging_level: str = "INFO"
    raw: dict = field(default_factory=dict)


def _require(d: dict, key: str, path: str):
    if key not in d:
        raise ConfigurationError(f"Missing required configuration key: '{path}.{key}'")
    return d[key]


def load_config(path: str) -> AppConfig:
    """Load and validate config.yaml, returning a populated AppConfig."""
    config_path = Path(path)
    if not config_path.exists():
        raise ConfigurationError(f"Configuration file not found: {path}")

    try:
        with config_path.open("r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh) or {}
    except yaml.YAMLError as exc:
        raise ConfigurationError(f"Failed to parse YAML in {path}: {exc}") from exc

    if not isinstance(raw, dict):
        raise ConfigurationError(f"Top-level configuration in {path} must be a mapping.")

    # ---- targets -------------------------------------------------------
    raw_targets = raw.get("targets")
    if not raw_targets or not isinstance(raw_targets, list):
        raise ConfigurationError(
            "Configuration must define a non-empty 'targets' list."
        )

    targets = []
    for idx, t in enumerate(raw_targets):
        if isinstance(t, str):
            targets.append(Target(url=t))
        elif isinstance(t, dict):
            if "url" not in t:
                raise ConfigurationError(f"targets[{idx}] is missing required 'url' field.")
            targets.append(
                Target(
                    url=t["url"],
                    name=t.get("name"),
                    timeout=t.get("timeout"),
                    verify_ssl=t.get("verify_ssl"),
                    max_redirects=t.get("max_redirects"),
                    labels=t.get("labels", {}) or {},
                )
            )
        else:
            raise ConfigurationError(f"targets[{idx}] must be a string or mapping.")

    # ---- network ---------------------------------------------------------
    net_raw = raw.get("network", {}) or {}
    network = NetworkConfig(
        timeout=float(net_raw.get("timeout", 10.0)),
        retry_count=int(net_raw.get("retry_count", 3)),
        retry_backoff=float(net_raw.get("retry_backoff", 0.5)),
        verify_ssl=bool(net_raw.get("verify_ssl", True)),
        max_redirects=int(net_raw.get("max_redirects", 10)),
        concurrency=int(net_raw.get("concurrency", 8)),
        user_agent=str(
            net_raw.get(
                "user_agent",
                "csp-auditor/1.0 (+https://github.com/your-org/csp-assessment-framework)",
            )
        ),
    )
    if network.timeout <= 0:
        raise ConfigurationError("network.timeout must be > 0")
    if network.retry_count < 0:
        raise ConfigurationError("network.retry_count must be >= 0")
    if network.concurrency < 1:
        raise ConfigurationError("network.concurrency must be >= 1")

    # ---- policy rules ------------------------------------------------------
    rules_raw = raw.get("policy_rules", {}) or {}
    policy_rules = PolicyRulesConfig(
        required_directives=list(
            rules_raw.get("required_directives", _DEFAULT_REQUIRED_DIRECTIVES)
        ),
        forbidden_keywords=list(
            rules_raw.get("forbidden_keywords", _DEFAULT_FORBIDDEN_KEYWORDS)
        ),
    )

    # ---- output ------------------------------------------------------------
    out_raw = raw.get("output", {}) or {}
    output_format = str(out_raw.get("output_format", "json")).lower()
    if output_format not in ("json", "console", "both"):
        raise ConfigurationError(
            f"output.output_format must be one of json|console|both, got '{output_format}'"
        )
    output = OutputConfig(
        output_dir=str(out_raw.get("output_dir", "reports")),
        output_format=output_format,
        console_color=bool(out_raw.get("console_color", True)),
    )

    logging_level = str(raw.get("logging", {}).get("level", "INFO")).upper() if isinstance(
        raw.get("logging"), dict
    ) else str(raw.get("logging_level", "INFO")).upper()

    # ---- host allowlist (reputation) ---------------------------------------
    allow_raw = raw.get("host_allowlist", {}) or {}
    allow_severity = str(allow_raw.get("severity", "WARN")).upper()
    valid_severities = {"INFO", "WARN", "VIOLATION", "ALARM", "CRITICAL"}
    if allow_severity not in valid_severities:
        raise ConfigurationError(
            f"host_allowlist.severity must be one of {sorted(valid_severities)}, got '{allow_severity}'"
        )
    trusted_domains = allow_raw.get("trusted_domains", []) or []
    if not isinstance(trusted_domains, list) or not all(isinstance(d, str) for d in trusted_domains):
        raise ConfigurationError("host_allowlist.trusted_domains must be a list of strings")

    host_allowlist = HostAllowlistConfig(
        enabled=bool(allow_raw.get("enabled", False)),
        trusted_domains=list(trusted_domains),
        severity=allow_severity,
        directives=list(allow_raw.get("directives", HostAllowlistConfig().directives)),
    )
    if host_allowlist.enabled and not host_allowlist.trusted_domains:
        raise ConfigurationError(
            "host_allowlist.enabled is true but trusted_domains is empty; every host "
            "would be flagged as untrusted. Add at least one trusted domain or disable "
            "the module."
        )

    return AppConfig(
        targets=targets,
        network=network,
        policy_rules=policy_rules,
        output=output,
        host_allowlist=host_allowlist,
        logging_level=logging_level,
        raw=raw,
    )
