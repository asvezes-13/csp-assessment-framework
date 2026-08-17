# Architecture

## Goals

This framework determines the **effective security posture** of deployed
Content Security Policies, modeling actual browser behavior rather than
performing naive string/regex validation. It is built as a modular,
independently testable Python package so it can be extended over time
(Threat Intelligence, Host Reputation, Bypass Testing, etc.) without
architectural rewrites.

## Pipeline

```
Configuration
  │  (config.yaml -> AppConfig)
  ▼
HTTP Collection
  │  (HTTPCollector walks the redirect chain, hop by hop)
  ▼
Redirect Processing
  │  (RedirectChain retains every HTTPResponse encountered)
  ▼
Header / Meta Extraction
  │  (extract_csp_material: enforced / report-only / meta, kept separate)
  ▼
CSP Parsing
  │  (parser.py: raw string -> structured Policy, never raises on bad input)
  ▼
Effective Policy Evaluation
  │  (evaluator.py: default-src fallback resolution -> EffectivePolicy,
  │   then Finding generation)
  ▼
Policy Comparison
  │  (comparator.py: Enforced vs Report-Only, semantic diff)
  ▼
Scoring
  │  (scoring.py: Findings -> Score, 0-100 + letter grade)
  ▼
Reporting
     (reporter.py: console + timestamped JSON)
```

Every arrow above is a hard boundary: each stage consumes only the
structured output of the previous stage. In particular, **nothing after
`parser.py` re-parses a CSP string** — all downstream logic operates on
`Policy` / `Directive` / `SourceExpression` objects (see `models.py`).

## Module responsibilities

| Module              | Responsibility                                                                 | Depends on                     |
|---------------------|----------------------------------------------------------------------------------|---------------------------------|
| `models.py`         | Shared dataclasses/enums for the entire pipeline                                | (nothing internal)             |
| `exceptions.py`     | Exception hierarchy                                                              | (nothing internal)             |
| `logging_utils.py`  | Centralized logger factory                                                      | (nothing internal)             |
| `utils.py`          | Small stateless helpers (quote-stripping, wildcard detection, etc.)             | (nothing internal)             |
| `configuration.py`  | Load & validate `config.yaml` into `AppConfig`                                  | `models`, `exceptions`         |
| `collector.py`      | HTTP collection, manual redirect walking, meta-tag extraction                   | `models`, `configuration`, `exceptions` |
| `parser.py`         | Raw CSP string -> `Policy` (structural parsing only, never evaluates security)  | `models`, `exceptions`, `utils`|
| `evaluator.py`      | `Policy` -> `EffectivePolicy` (fallback resolution) -> `Finding[]`              | `models`, `utils`              |
| `comparator.py`     | `EffectivePolicy` x `EffectivePolicy` -> `PolicyComparisonResult`                | `models`, `evaluator`, `utils` |
| `scoring.py`        | `Finding[]` -> `Score`                                                          | `models`                       |
| `reporter.py`       | `Report` -> console text / JSON file                                            | `models`, `exceptions`         |
| `reputation.py`     | Host Reputation (allowlist): flags hosts not in `host_allowlist.trusted_domains`| `models`, `configuration`, `utils` |
| `main.py`           | CLI orchestration: wires every stage together, concurrency, CI/CD exit codes    | everything above               |

There are **no circular dependencies**: data flows strictly downward
through this table. `evaluator.py` and `parser.py` do not import
`collector.py`, `comparator.py`, `scoring.py`, or `reporter.py` — this is
what makes future modules (Threat Intelligence, Host Reputation, JSONP
Detection, Open Redirect Detection, CSP Bypass Testing, Browser
Compatibility) safe to add later as new, independent consumers of
`Policy` / `EffectivePolicy` / `Finding` without touching the core engine.

## Data model highlights

- **`Policy`** is source-agnostic structurally, but tagged with a
  `PolicySource` (`HEADER_ENFORCED` / `HEADER_REPORT_ONLY` / `META_TAG`) so
  downstream logic (e.g. "these directives are ignored in `<meta>`") can
  apply source-specific rules without re-parsing.
- **`EffectivePolicy`** captures, for every known directive, whether it was
  explicitly declared, or inherited via the CSP Level 3 fallback chain
  (e.g. `script-src` falling back to `default-src`), or entirely
  unrestricted (directives like `base-uri`/`frame-ancestors` have **no**
  `default-src` fallback — a distinct and often more dangerous condition
  than "restricted, just broadly").
- **`Finding`** is the unit of security signal: every finding carries
  severity, confidence, a plain-English description, the *effective
  browser behavior*, a recommendation, and a specification/OWASP
  reference — enough for a finding to stand alone in a ticket or CI/CD gate
  failure message.
- **`PolicyComparisonResult`** never compares raw strings; every directive
  comparison is judged on a permissiveness heuristic derived from the
  *parsed* source expressions (keyword class, wildcard, scheme, nonce/hash)
  so that e.g. reordering the same origins doesn't register as a change,
  while swapping `'self'` for `*` does.

## Reliability model

- `HTTPCollector` performs manual (not `httpx`-automatic) redirect
  following so every hop can be individually recorded, with configurable
  `max_redirects`, loop detection (revisit-tracking), retries with
  exponential backoff on transient network errors, and configurable TLS
  verification.
- Collection failures for one target are captured on
  `RedirectChain.error` / `TargetReport.collection_error` and **never**
  raise out of `build_target_report`, so one bad target cannot abort an
  entire audit run across many targets.
- The parser never raises on malformed CSP content; problems are recorded
  as `ParserIssue` entries and later surfaced as low-severity `Finding`s,
  keeping "this policy is weird" separate from "this policy is insecure".

## Extensibility

Planned future modules plug in at specific, well-defined seams:

- **Host Reputation Engine (implemented, allowlist mode)**: `reputation.py`
  consumes `Policy.directives[...].values` directly (via
  `SourceExpression`/`extract_hostname`) and emits `Finding`s for any host
  not covered by `host_allowlist.trusted_domains` — no changes were needed
  to `parser.py` or `evaluator.py` to add it. It is disabled by default
  and opt-in per `config.yaml`.
- **Threat Intelligence Engine (still future work)**: a denylist/reputation
  *lookup* against external threat feeds (as opposed to the local
  allowlist above) — same integration seam as `reputation.py`, just backed
  by a live/cached intel source instead of static config.
- **JSONP Detection / Open Redirect Detection**: consume
  `RedirectChain` / `HTTPResponse` from `collector.py`, plus the resolved
  allow-listed hosts from `EffectivePolicy`, to check known JSONP/open
  redirect endpoints against `script-src`/`connect-src` allowlists.
- **CSP Bypass Testing**: a new module that takes an `EffectivePolicy` and
  a bypass-technique database and emits additional `Finding`s — reusing
  the exact same `Finding` model consumed by `scoring.py`/`reporter.py`.
- **Browser Compatibility Engine**: a new module mapping directives/
  keywords (e.g. `'strict-dynamic'`, `require-trusted-types-for`) to
  browser support tables, annotating existing `Finding`s or emitting new
  `INFO`-level ones.

None of these require modifying `models.py`'s core shape, only additive
fields/new modules — this is why the framework favors composition
(independent modules operating on shared data models) over deep
inheritance hierarchies.
