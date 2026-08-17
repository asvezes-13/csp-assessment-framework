# csp-assessment-framework

A production-grade **Content Security Policy (CSP) assessment framework** for
enterprise AppSec teams, CI/CD security gates, and web security
assessments.

This is not a linter. It determines the **effective security posture** of
deployed CSPs by collecting, parsing, evaluating, comparing, and scoring
policies the way a modern browser actually interprets them — including
directive inheritance/fallback, `strict-dynamic`/nonce/hash semantics,
Report-Only vs Enforced comparison, and `<meta>`-tag-specific limitations.

---

## Features

- **Redirect-aware HTTP collection** — every hop is inspected independently
  for CSP presence, absence, and change, with retries/backoff, configurable
  timeouts, and optional SSL verification.
- **Standards-compliant CSP parsing** — handles malformed policies,
  duplicate directives, unknown/obsolete directives, and malformed tokens
  without ever crashing the audit.
- **Effective policy evaluation** — models CSP Level 3 directive fallback
  (e.g. `script-src` inheriting from `default-src`; `base-uri` and
  `frame-ancestors` which have **no** fallback at all).
- **Enforced vs Report-Only comparison** — a semantic (not textual) diff
  engine that classifies every directive as an Improvement, Regression,
  Neutral, Added, or Removed change, plus a migration-readiness assessment
  with concrete blockers and guidance.
- **Meta-tag validation** — flags directives (`frame-ancestors`,
  `report-uri`, `report-to`, `sandbox`) that browsers silently ignore when
  delivered via `<meta http-equiv>`.
- **Host Reputation (allowlist)** — optional, config-driven: any host
  permitted by the policy that isn't covered by `host_allowlist.trusted_domains`
  is flagged as untrusted, with CSP-accurate wildcard matching
  (`*.example.com` trusts subdomains, not the bare domain). Fails closed —
  unlisted hosts are flagged even if not independently known to be malicious.
- **Modern CSP feature analysis** — `strict-dynamic`, nonces, hashes,
  Trusted Types, `upgrade-insecure-requests`, and more.
- **Transparent scoring** — a 0-100 score and A-F letter grade computed via
  an explainable severity-weighted deduction model, plus complexity
  metrics.
- **Rich reporting** — colorized console output and timestamped JSON
  reports suitable for CI/CD pipelines, with a `--fail-under` gate.
- **Reliability by design** — configurable concurrency, retries, redirect
  loop detection, and per-target error isolation (one bad target never
  aborts the run).

---

## Installation

```bash 
pip install -r requirements.txt
python3 main.py --config config.yaml

# To guarantee proper security and avoid leaving artifacts behind, follow
# the bellow procedure.

#Create and activate the environment:
python3 -m venv .venv               
source .venv/bin/activate
pip install -r requirements.txt
#Run the script:
python3 main.py --config config.yaml
#Clean up and delete all installed dependencies:
deactivate && rm -rf .venv

Requires **Python 3.10+**.

---

## Quick start

1. Edit `config.yaml` with your targets (or use the provided example).
2. Run an audit:

```bash
python main.py --config config.yaml
```

This produces colorized console output *and* a timestamped JSON report in
`reports/` (per the default `output_format: both` in `config.yaml`).

### CLI usage examples

```bash
# Audit everything in config.yaml
python main.py --config config.yaml

# Audit a single URL, ignoring config.yaml's targets list
python main.py --config config.yaml --target https://example.com

# Audit multiple ad-hoc URLs
python main.py --config config.yaml --target https://a.example.com --target https://b.example.com

# Console output only, no JSON file
python main.py --config config.yaml --format console

# JSON only, custom output directory (for CI artifact upload)
python main.py --config config.yaml --format json --output-dir ./ci-reports

# CI/CD security gate: fail the build if any target's enforced-policy score
# drops below 70
python main.py --config config.yaml --fail-under 70
echo "Exit code: $?"
```

Exit codes: `0` success, `1` `--fail-under` threshold breached, `2`
configuration or audit-level failure.

---

## Configuration reference (`config.yaml`)

```yaml
targets:
  - url: "https://example.com"
    name: "example-marketing-site"     # optional friendly name
    timeout: 20                          # optional per-target override
    verify_ssl: false                    # optional per-target override
    max_redirects: 5                     # optional per-target override
    labels:                              # optional free-form metadata
      env: "staging"

network:
  timeout: 10            # seconds, per HTTP request
  retry_count: 3          # retries per hop on transient network failure
  retry_backoff: 0.5      # exponential backoff base, in seconds
  verify_ssl: true        # set false only for internal/self-signed hosts
  max_redirects: 10       # ceiling to guard against redirect loops
  concurrency: 8           # number of targets audited in parallel
  user_agent: "csp-auditor/1.0 ..."

policy_rules:
  required_directives: ["default-src", "script-src", "object-src", "base-uri", "frame-ancestors"]
  forbidden_keywords: ["unsafe-inline", "unsafe-eval", "unsafe-allow-redirects"]

output:
  output_dir: "reports"
  output_format: "both"   # json | console | both
  console_color: true

# Optional — disabled by default. When enabled, flags any host permitted by
# the policy that isn't in trusted_domains. Wildcard entries ("*.example.com")
# trust subdomains only, not the bare domain, mirroring CSP semantics.
host_allowlist:
  enabled: false
  severity: "WARN"        # INFO | WARN | VIOLATION | ALARM | CRITICAL
  trusted_domains:
    - "*.example.com"
    - "cdn.jsdelivr.net"
  # directives: ["script-src", "connect-src"]   # optional; defaults to all host-bearing directives

logging:
  level: "INFO"           # DEBUG | INFO | WARNING | ERROR | CRITICAL
```

All fields have sane defaults (see `csp_auditor/configuration.py`) if
omitted; only `targets` is required. No configuration values are
hardcoded elsewhere in the codebase — everything flows through `AppConfig`.

---

## How results are structured

Each target produces a `TargetReport` containing:

- The full **redirect chain** (every hop, its status, and which CSP
  headers it carried).
- The parsed **Enforced**, **Report-Only**, and **Meta** policies
  (kept independent, never merged during collection).
- A list of **`Finding`s**, each with severity (`INFO` → `CRITICAL`),
  confidence, a description, the *effective browser behavior*, a concrete
  recommendation, and a spec/OWASP reference.
- Independent **`Score`s** (0-100 + letter grade) for the Enforced and
  Report-Only policies.
- A **comparison** between Enforced and Report-Only: added/removed/
  tightened/relaxed directives, an overall relationship summary, a
  migration-readiness verdict, and actionable blockers/guidance.

See `docs/architecture.md` for the full pipeline and module breakdown, and
`examples/` for a sample console transcript and JSON report.

---

## Browser behavior modeled

This framework encodes CSP Level 3 semantics beyond simple keyword
matching:

- **Directive fallback**: `script-src`, `style-src`, `img-src`,
  `connect-src`, `font-src`, `media-src`, `object-src`, `manifest-src`,
  `prefetch-src`, `child-src`, `frame-src`, and `worker-src` fall back to
  `default-src` (with `frame-src`/`worker-src` first checking `child-src`).
  `base-uri`, `form-action`, `frame-ancestors`, `sandbox`, and the
  reporting directives have **no fallback** — if absent, that behavior is
  entirely unrestricted, not "defaulted".
- **Multiple headers combine via intersection**, per spec — the framework
  parses and evaluates each header instance independently and surfaces
  findings for all of them, rather than silently merging/overwriting.
- **`strict-dynamic`** requires a nonce/hash to establish initial trust;
  without one it provides no practical benefit. When present, it also
  causes browsers to **ignore** host/scheme allowlists in the same
  directive.
- **`unsafe-inline`** is ignored by CSP Level 2+ browsers whenever a
  nonce or hash is also present in the same directive — flagged as
  informational (legacy-browser-only impact) rather than critical in that
  case.
- **`<meta http-equiv="Content-Security-Policy">`** cannot carry
  `frame-ancestors`, `report-uri`, `report-to`, or `sandbox` — browsers
  silently ignore these when delivered this way; the framework flags this
  explicitly rather than reporting a false sense of protection.

References:
[CSP Level 3 Specification](https://www.w3.org/TR/CSP3/) ·
[OWASP CSP Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)

---

## Developer guide

### Project layout

```
csp-assessment-framework/
├── README.md
├── requirements.txt
├── pyproject.toml
├── config.yaml
├── main.py                  # CLI entry point / pipeline orchestrator
├── csp_auditor/
│   ├── models.py             # shared dataclasses (Policy, Finding, Report, ...)
│   ├── exceptions.py         # exception hierarchy
│   ├── logging_utils.py      # centralized logger factory
│   ├── utils.py              # small stateless helpers
│   ├── configuration.py      # config.yaml -> AppConfig
│   ├── collector.py          # HTTP collection + redirect handling + meta extraction
│   ├── parser.py             # raw CSP string -> Policy
│   ├── evaluator.py          # Policy -> EffectivePolicy -> Finding[]
│   ├── comparator.py         # Enforced vs Report-Only semantic diff
│   ├── reputation.py         # Host allowlist: flags untrusted hosts
│   ├── scoring.py            # Finding[] -> Score
│   └── reporter.py           # Report -> console text / JSON file
├── docs/architecture.md      # pipeline & module design
└── reports/                  # default JSON report output directory
```


```
Tests cover the parser (malformed CSP, duplicates, nonces, wildcards),
evaluator (fallback inheritance, mandatory directives, unsafe keywords,
`strict-dynamic`/nonce combinations, meta-tag limitations), comparator
(improvement/regression classification, migration readiness, blockers),
scoring (deduction model, complexity metrics, score floor), and collector
(redirect chains, loop detection, retry/error isolation, meta extraction)
using `httpx.MockTransport` — no real network access is required to run
the test suite.

### Design principles

- Every module has a single responsibility; see `docs/architecture.md` for
  the full dependency table (no circular imports).
- No stage after `parser.py` re-parses a CSP string — all downstream logic
  operates on the `Policy` / `Directive` / `SourceExpression` dataclasses.
- No global state; configuration and results are threaded explicitly
  through function arguments and return values.
- Composition over inheritance: the pipeline is a sequence of pure(-ish)
  functions operating on shared dataclasses, not a class hierarchy.

### Extending the framework

The architecture is intentionally designed so that future modules —
Threat Intelligence, Host Reputation, JSONP Detection, Open Redirect
Detection, CSP Bypass Testing, Browser Compatibility Analysis — can be
added as new modules that consume `Policy` / `EffectivePolicy` / `Finding`
objects, without modifying `parser.py` or `evaluator.py`. See "Extensibility"
in `docs/architecture.md` for the specific integration seams.


### License

MIT