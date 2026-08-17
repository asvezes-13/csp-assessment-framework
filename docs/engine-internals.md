# Engine Internals

This document is a level deeper than the other two docs:

- `architecture.md` describes module **boundaries** — what talks to what.
- `findings-reference.md` is a flat **lookup table** — one row per finding, severity, and why.
- **This document** explains the internal **logic and algorithms** inside
  each module — the "how does it actually decide that" reference for
  anyone modifying, debugging, or extending a specific module.

If you change an algorithm described here, update this document in the
same change.

---

## 1. The Confidence system

Every `Finding` carries two independent axes: `Severity` and
`Confidence`. They answer different questions:

- **Severity** — "how bad is this *if it's a real problem*?"
- **Confidence** — "how sure is the engine that this is actually a
  problem, versus a matter of interpretation or a soft suggestion?"

### How it's determined

Confidence is **not computed by any formula or heuristic function**.
There is no scoring logic behind it — it is a static value the developer
assigns per finding-generator in `evaluator.py`/`reputation.py`, chosen
by how mechanically certain that specific rule is:

| Level | What it signals | How it's decided |
|---|---|---|
| `CERTAIN` | The finding is a direct, unambiguous fact about the CSP spec — no room for interpretation. | Used when the *presence of a token* is itself the entire rule, e.g. an `unsafe-*` keyword being present, or a directive being provably meaningless inside `<meta>` per spec. |
| `HIGH` | Strong rule-based detection; correct in essentially every real-world case given the parsed structure. | Used for structural facts derived directly from the `Policy`/`EffectivePolicy` objects: a mandatory directive resolving to `None` after fallback, a wildcard/scheme token being present, `strict-dynamic` co-occurring (or not) with a nonce/hash, a host failing the allowlist match. |
| `MEDIUM` | Technically accurate, but the "problem" is really a best-practice judgment rather than a hard spec violation. | Used where reasonable engineers could disagree on whether the pattern is actually wrong for a given app — e.g. `object-src` present but not `'none'`, or relying solely on `default-src`. |
| `LOW` | A soft, defense-in-depth suggestion. | Used for forward-looking hardening recommendations that aren't gaps in the traditional sense — e.g. not using Trusted Types, not setting `upgrade-insecure-requests`. |

### Why it's a separate axis instead of folded into Severity

A `CRITICAL` finding with `LOW` confidence and a `WARN` finding with
`CERTAIN` confidence should be triaged very differently even though the
numbers might suggest otherwise — this is why the two are kept
orthogonal rather than combined into one score. In practice, most
findings in this framework pair high severity with high/certain
confidence (the rules are structural, not probabilistic), but the axis
exists so that future modules — especially ones with genuinely
uncertain signals, like a future Threat Intelligence Engine scoring a
domain's reputation from an external feed — have somewhere to express
"I think this is bad, but I'm not sure" without having to lie about
severity to communicate that uncertainty.

### Current limitation

**Confidence has no effect on the numeric score.** `scoring.py`'s
deduction model (see §4 below) only reads `Severity`. Confidence is
currently display-only metadata (shown in console/JSON output) meant to
help a human triage findings, not an input to automated scoring. If you
want low-confidence findings to be discounted in the score, that's a
localized, single-function change in `scoring.py::score_policy` — it
would need a discount multiplier per confidence level applied before
summing deductions.

---

## 2. Severity assignment philosophy

The severity levels (`INFO` → `WARN` → `VIOLATION` → `ALARM` →
`CRITICAL`) aren't assigned arbitrarily; the same handful of principles
recur across every check in `evaluator.py`. Knowing them makes it
possible to predict what severity a *new* check should get, rather than
guessing:

1. **Script execution outranks everything else.** Any issue affecting
   `script-src` (or its `-elem`/`-attr` variants) is bumped at least one
   level above the identical issue in a non-script directive. This is
   why `unsafe-inline`/`unsafe-eval` in `script-src` is `CRITICAL` but
   the same keyword in `style-src` is only `ALARM` — script execution is
   the mechanism CSP exists to control; everything else is secondary
   blast radius.
2. **No-fallback directives are penalized higher than fallback
   directives**, given equal "missingness." `base-uri` (no fallback —
   completely unrestricted if absent) is `VIOLATION`; `frame-ancestors`
   (also no fallback, but the attack requires UI interaction and a
   legacy header often compensates) is `WARN`. Directives that *do* fall
   back to `default-src` are individually less urgent because there's
   usually at least some restriction inherited.
3. **A rule that's unambiguous in the spec gets high confidence; a rule
   that's a judgment call gets `MEDIUM`/`LOW` confidence** (see §1) —
   but note this is orthogonal to severity, not a substitute for it.
4. **Findings that describe browser behavior mismatches (not
   vulnerabilities) sit at `INFO`.** E.g. nonce present without
   `strict-dynamic` isn't a hole, it's a "this might not behave how you
   expect" observation.
5. **Missing telemetry (`WARN`) is treated as materially different from
   missing protection.** No `report-to`/`report-uri` doesn't weaken
   enforcement at all — the browser still blocks violations — so it
   can never be `VIOLATION` or higher; the finding exists purely because
   it removes your ability to safely iterate.

For the full list of severities per finding, see
`findings-reference.md`; this section is the reasoning behind that
table, not a duplicate of it.

---

## 3. `csp_auditor/parser.py` — CSP Parser

**Purpose:** raw CSP string → structured `Policy`. Nothing past this
module ever touches a raw string again.

**Core algorithm:**
1. Split the raw policy on `;`. Empty fragments (from `;;` or a trailing
   `;`) are silently dropped — browsers tolerate this, so the parser
   does too.
2. For each fragment, split on the *first* run of whitespace to separate
   `directive-name` from `directive-value`. Everything after that first
   split is the value string, whitespace-split into individual tokens.
3. Directive name validation: must match `^[A-Za-z][A-Za-z0-9\-]*$`.
   Anything that doesn't match this shape is dropped with a
   `ParserIssue` — this is the "malformed directive token" case, and is
   different from an *unknown* directive (see below), which has valid
   shape but isn't in the recognized set.
4. **First-occurrence-wins for duplicates.** If a directive name repeats
   within one policy string, the *first* instance is kept as the
   authoritative `Directive` object (per the CSP spec — browsers ignore
   later duplicates), and the original directive is marked
   `is_duplicate = True`. This is why the finding says "the duplicate
   directive was ignored," not "the values were merged" — they are
   never merged.
5. Each value token is classified into a `SourceExpression` via
   `_classify_token`: quote-stripped, then checked against known keyword
   set (`self`, `unsafe-inline`, `none`, `strict-dynamic`, ...), a nonce
   regex (`^nonce-.+$`), a hash regex
   (`^(sha256|sha384|sha512)-[A-Za-z0-9+/_=\-]+$`), a bare-scheme regex
   (`^[a-zA-Z][a-zA-Z0-9+\-.]*:$`), and a wildcard check (`*` or starts
   with `*.`). A token that's quoted but doesn't match any recognized
   keyword/nonce/hash pattern is flagged `malformed` — this catches
   typos like `'unsafe-inlin'` that would otherwise silently do nothing
   in a real browser.
6. Directive names are checked against `KNOWN_DIRECTIVES` (a fixed set
   covering all CSP Level 2/3 fetch, document, navigation, and reporting
   directives) and `OBSOLETE_DIRECTIVES` (a small map of deprecated
   names to an explanation string, e.g. `reflected-xss`, `referrer`,
   `plugin-types`). Anything in neither set is marked `is_unknown`.

**Design decision — never raise on bad input:** every one of the checks
above degrades to a `ParserIssue` appended to `Policy.parser_issues`
rather than an exception. The only thing that raises `CSPParseError` is
a programmer error (passing a non-`str`) — genuinely malformed CSP
content from the wild, no matter how broken, always produces *some*
`Policy` object so the rest of the pipeline can proceed.

**Gotcha to know:** multiple `Content-Security-Policy` headers on one
response are parsed as **separate** `Policy` objects
(`parse_multiple`), never merged — per spec, browsers combine multiple
headers via intersection (each additional header can only further
restrict). The parser deliberately does not attempt to model that
intersection; it stays a pure string→structure step. `main.py` evaluates
each header instance independently and surfaces findings from all of
them (see §9).

---

## 4. `csp_auditor/evaluator.py` — Policy Evaluation Engine

**Purpose:** `Policy` → `EffectivePolicy` (fallback resolution) →
`Finding[]`.

### 4.1 Fallback resolution (`resolve_effective_policy`)

This is the part of the engine that turns "what's literally written" into
"what the browser will actually enforce." The fallback chains are
hardcoded from the CSP Level 3 spec:

```
script-src, script-src-elem, script-src-attr  -> default-src (script-src-elem/attr check script-src first)
style-src, style-src-elem, style-src-attr     -> default-src (style-src-elem/attr check style-src first)
img-src, connect-src, font-src, media-src,
object-src, manifest-src, prefetch-src,
child-src                                      -> default-src
frame-src, worker-src                          -> child-src -> default-src
```

For each directive name, the algorithm:
1. If explicitly declared in the `Policy`, use it directly —
   `is_explicit = True`, `inherited_from = None`.
2. Otherwise, walk that directive's fallback chain in order, using the
   first directive in the chain that *is* explicitly declared.
   `is_explicit = False`, `inherited_from = <name of the directive that
   supplied the value>`.
3. If nothing in the chain is declared either, the directive resolves to
   `None` (not "restricted," genuinely **unrestricted**) — this is the
   single most important distinction the engine makes, because it's
   what separates "missing `script-src`, but at least `default-src`
   covers it" from "missing `base-uri`, and nothing covers it at all."

`base-uri`, `form-action`, `frame-ancestors`, `sandbox`, `navigate-to`,
and the reporting directives are in `NO_FALLBACK_DIRECTIVES` — they
never inherit from `default-src` under any circumstances, mirroring the
spec exactly.

### 4.2 Finding generation

`evaluate_policy` runs nine independent finding-generator functions
against every policy and concatenates their output — they don't interact
or short-circuit each other, so a single directive can (and often does)
produce multiple findings from different generators. Each generator's
logic is documented per-check in `findings-reference.md`; the ones worth
calling out algorithmically:

- **`_unsafe_keyword_findings`** iterates every directive's values
  looking for membership in a fixed `UNSAFE_KEYWORDS` set
  (`unsafe-inline`, `unsafe-eval`, `unsafe-hashes`,
  `unsafe-allow-redirects`), branching severity only on
  `directive_name.startswith("script")` — this string-prefix check is
  what implements "script directives are worse" from §2, and covers
  `script-src`, `script-src-elem`, and `script-src-attr` uniformly.
- **`_nonce_hash_strict_dynamic_findings`** only examines
  `script-src`/`script-src-elem`/`style-src`/`style-src-elem` and looks
  at three boolean facts per directive — `any_nonce()`, `any_hash()`,
  `has_keyword("strict-dynamic")`, `has_keyword("unsafe-inline")` — then
  branches on the truth table of those four booleans to decide which (if
  any) of three distinct findings to emit. This is the most
  interaction-heavy check in the module; if you're debugging why a
  particular nonce/strict-dynamic combination isn't flagged as expected,
  start here.
- **`_default_src_reliance_findings`** computes
  `explicit_fetch_directives = {names in policy.directives that are also
  keys in FALLBACK_CHAINS}` — if that set is empty while `default-src` is
  present, it means literally every fetch directive is inheriting the
  same value, which is the trigger condition.

---

## 5. `csp_auditor/comparator.py` — Policy Comparison Engine

**Purpose:** compare two `EffectivePolicy` objects (Enforced vs
Report-Only) by *behavior*, not by string equality.

### 5.1 The permissiveness heuristic

This is the core trick that makes the comparison semantic instead of
textual. `_directive_permissiveness(directive)` sums a weight per source
token:

| Token type | Weight |
|---|---|
| `unsafe-*` keyword | 100 |
| Wildcard (`*`, `*.domain`) | 90 |
| Bare scheme (`data:`, `https:`, ...) | 70 |
| Explicit host/origin (e.g. `cdn.example.com`) | 40 |
| `'self'` | 10 |
| `'none'` | 0 |
| Nonce or hash | 5 |

The total is a directive-agnostic "how much does this allow" score with
**no upper bound** — it's not a percentage, it's a relative ranking
used only to compare the *same* directive across two policies, never
compared across different directives. Two policies for the same
directive are then classified by comparing scores:

- Enforced score > Report-Only score → **Improvement** (Report-Only is
  stricter)
- Enforced score < Report-Only score → **Regression** (Report-Only is
  looser)
- Equal scores but different token sets → **Neutral** ("differs
  textually but roughly equivalent")
- Identical token sets (as a Python `set` comparison, so order and
  duplicates don't matter) → **Unchanged**
- Present in one policy but entirely absent in the other → **Added** or
  **Removed** (handled before the scoring step, since there's no score
  to compare against `None`)

**Design decision — why weights, not exact enforcement modeling:** doing
this exactly (i.e. actually computing which origins are a strict subset
of which) would require resolving DNS/CIDR-level relationships between
arbitrary origins, which is out of scope. The weighted heuristic is
intentionally conservative: it will correctly rank
"`'self'` vs `*`" or "`nonce` vs `unsafe-inline`" (the common real-world
cases), but two *different* explicit-host allowlists of the same size
score identically even if one is objectively broader — this is a known,
accepted simplification.

### 5.2 Migration readiness and blockers

`_identify_blockers` runs three independent checks against the
Report-Only policy only (not a comparison — a standalone health check):

1. `script-src` present with `unsafe-inline` and **no** nonce/hash
   fallback — this would break under Level 2+ enforcement in the opposite
   direction of what the developer probably wants (nonce/hash is what
   makes `unsafe-inline` inert; without one, it's fully active and fully
   dangerous once you're relying on it for legacy support).
2. `script-src` declares `strict-dynamic` with no nonce/hash to seed
   trust.
3. Neither `report-uri` nor `report-to` configured — flagged as a
   blocker (not just a finding) because promoting a policy you can't
   observe is explicitly risky.
4. Any parser issues at all on the Report-Only policy (duplicates,
   unknown/obsolete directives, malformed tokens) — surfaced as a
   blocker to force a manual review pass before promotion, even though
   none of these individually break enforcement.

`_assess_migration_readiness` is a simple threshold on blocker count:
zero blockers → `READY`; exactly one → `NEARLY_READY`; two or more →
`NOT_READY`. This is deliberately coarse — the intent is to force a human
to read the specific blocker list (always included in the report),
not to trust a single readiness label as sufficient on its own.
`REGRESSION_RISK` overrides all of the above and is set instead whenever
the *comparison* step (§5.1) found only regressions and zero
improvements — a Report-Only policy that's strictly weaker than what's
already enforced should never be described as "nearly ready."

---

## 6. `csp_auditor/scoring.py` — Scoring

**Purpose:** `Finding[]` → 0-100 score + letter grade. Deliberately the
simplest module in the pipeline — a transparent deduction model, not a
black box, specifically so a score can be explained to a non-engineer in
one sentence ("you lost 30 points for a missing script-src").

**Exact deduction table** (subtracted from a starting baseline of 100,
floored at 0 — see `max(0.0, 100.0 - total_deduction)`):

| Severity | Points deducted |
|---|---|
| `CRITICAL` | 30 |
| `ALARM` | 18 |
| `VIOLATION` | 10 |
| `WARN` | 4 |
| `INFO` | 1 |

**Letter grade thresholds** (first matching threshold wins, checked
highest-first): `A` ≥ 90, `B` ≥ 80, `C` ≥ 70, `D` ≥ 60, `F` otherwise.

**No cap on total deductions besides the floor** — a policy with three
`CRITICAL` findings (90 points) plus a handful of smaller ones can and
will legitimately hit 0/F. This is intentional: the model doesn't try to
be "fair" about diminishing returns on multiple severe findings, because
in practice a policy with 3+ `CRITICAL`-level gaps genuinely offers close
to zero protection regardless of what else it gets right.

**Complexity metrics** (`_complexity_metrics`) are computed directly from
the `Policy` object, independent of findings: directive count, total
source-expression count, average sources per directive, duplicate/
unknown/obsolete directive counts, parser issue count, and raw string
length. These exist purely as descriptive metadata in reports (e.g. "this
policy has 40 directives and is 3,200 characters long" is useful context
even when the score is fine) — they do not feed into the numeric score
at all.

---

## 7. `csp_auditor/collector.py` — HTTP Collector

**Purpose:** redirect-aware HTTP collection with retries and loop
detection, without ever raising out to the caller.

### 7.1 Redirect walking

Redirects are followed **manually** (`follow_redirects=False` on the
underlying `httpx.Client`), one hop at a time, up to
`max_redirects + 1` total requests. This is deliberate: `httpx`'s
built-in auto-redirect would only give you the final response, losing
the ability to say "hop 2 dropped the CSP header that hop 1 had." Each
hop becomes its own `HTTPResponse` appended to `RedirectChain.hops`.

**Loop detection** is a simple visited-URL set: before each hop, if the
current URL has already been visited in this chain, the loop is
recorded as `chain.error` and collection stops immediately — this
catches both a direct self-redirect and an indirect cycle (A→B→A)
equally, since it's tracking exact URLs already seen, not just the
previous hop.

### 7.2 Retry / backoff

Retries only apply to *transient* exceptions —
`ConnectTimeout`, `ReadTimeout`, `ConnectError`, `RemoteProtocolError`,
`PoolTimeout` — not to HTTP error status codes (a `500` or `404`
response is a valid `HTTPResponse`, not a retry trigger; only failures
to get a response at all are retried. Backoff is exponential:

```
backoff_seconds = retry_backoff * (2 ** attempt)
```

With the default `retry_backoff = 0.5`, that's 0.5s, 1s, 2s, 4s... for
consecutive attempts. After `retry_count` retries are exhausted, the
accumulated last exception is wrapped into a `NetworkError` and raised
— but only *within* `_fetch_with_retry`; the outer `collect()` method
catches this and records it as `chain.error` rather than propagating it,
which is what guarantees one bad target can never abort an entire
multi-target audit run.

### 7.3 Content-type gating

Response bodies are only decoded into text (`response.text`, which can
be expensive for large payloads) when **both** conditions hold: the hop
is not itself a redirect, and the `Content-Type` header contains
`text/html` or `application/xhtml+xml`. Every other content type (JSON,
images, binaries, streams) gets `body = None` — this is what keeps the
collector from wasting memory/time decoding a multi-megabyte binary just
to discard it, and it's also why meta-tag extraction is safe to call
unconditionally: `extract_csp_material` checks `response.is_html and
response.body` before ever touching the (possibly `None`) body.

### 7.4 Meta-tag extraction

Two regexes, applied in sequence: `_META_CSP_RE` finds the entire `<meta
http-equiv="Content-Security-Policy" ...>` tag (case-insensitive, tag
contents up to the next `>`), then `_META_CONTENT_RE` extracts the
`content="..."` attribute value from *within* that tag. The content
regex uses a **backreference to the opening quote character**
(`(["'])(.*?)\1`) rather than a plain `[^"']*` character class — this
matters because a CSP value legitimately contains the *other* quote
character (e.g. `content="default-src 'self'"` has single quotes inside
double-quote delimiters); a naive `[^"']*` pattern would truncate at the
first inner quote and silently produce a broken policy string. (This was
an actual bug caught by the test suite during development — see
`test_extract_meta_csps_finds_tag` in `tests/test_collector.py`.)

---

## 8. `csp_auditor/reputation.py` — Host Reputation (allowlist)

**Purpose:** flag any host-shaped source expression not covered by a
configured `trusted_domains` allowlist. Covered in detail in
`findings-reference.md` §9; the algorithmic core is the wildcard matcher,
worth explaining precisely since it's the part most likely to surprise
someone:

```
_is_trusted(host, trusted_domains):
  for each entry in trusted_domains:
    if entry is a wildcard ("*.base"):
        if host is also a wildcard: trust only if host's base == entry's base
        else:                       trust if host ends with "." + entry's base
    else (entry is an exact host):
        trust only if host == entry, exactly
  return False if nothing matched
```

The two asymmetric cases worth internalizing:
- A trusted wildcard `*.example.com` does **not** trust the bare
  `example.com` — only genuine subdomains (`x.example.com`,
  `a.b.example.com`). If you also want the bare domain trusted, you must
  list it separately.
- An exact trusted entry (`cdn.jsdelivr.net`) never trusts a superficially
  similar host like `evil.jsdelivr.net.attacker.com` — there is no
  substring or prefix matching anywhere in this function, only exact
  string equality or genuine dot-boundary subdomain matching. This is
  what prevents a classic domain-suffix spoofing bypass.

`extract_hostname` (in `utils.py`, shared with nothing else) strips an
optional scheme prefix via regex
(`^[a-zA-Z][a-zA-Z0-9+.\-]*://`), then truncates at the first `/` (path)
and first `:` (port), preserving a leading `*.` if present. Deduplication
(`seen` set keyed on `(directive, host.lower())`) prevents the same host
repeated within one directive from generating multiple identical
findings.

---

## 9. `csp_auditor/configuration.py` — Configuration Manager

**Purpose:** the single point where `config.yaml` becomes validated,
strongly-typed Python objects. No other module reads YAML or environment
variables directly.

**Validation philosophy:** fail fast and specifically. Every constraint
violation raises `ConfigurationError` with a message naming the exact
key path (e.g. `"host_allowlist.severity must be one of [...]"`) rather
than a generic parse failure — this is deliberate so a misconfigured
`config.yaml` is diagnosable from the error message alone, without
needing to read `configuration.py`.

**Notable cross-field validation:** `host_allowlist.enabled = true` with
an empty `trusted_domains` list is rejected outright (`ConfigurationError`,
not a silent no-op) — because an empty allowlist combined with the
module being "on" would flag literally every host in every policy, which
is virtually never the intent. This is the one place in the codebase
where one config field's validity depends on another field's value.

**Backward-compatible defaults:** every new config section added since
the framework's initial version (`host_allowlist` most recently) defaults
to fully disabled/empty when absent from `config.yaml`, so existing
config files never need to be touched to keep working after an upgrade.

---

## 10. `csp_auditor/reporter.py` — Reporting Engine

**Purpose:** render an already-fully-computed `Report` as console text or
JSON. Contains zero evaluation/scoring logic — if you find yourself
wanting to change *what* counts as a finding or *how* severity is
decided, you're in the wrong module; this one only changes *how results
look*.

**JSON shape is hand-built, not `dataclasses.asdict`:** `_to_serializable`
manually walks the `Report` tree rather than blindly serializing every
dataclass field. Two reasons: (1) HTML response bodies and other large
transient fields are deliberately excluded from the JSON output, and (2)
enums are normalized to their `.value` string rather than Python's
default enum repr, which keeps the JSON diffable/greppable in CI logs.

**Console findings are sorted by severity descending**
(`sorted(tr.findings, key=lambda x: -x.severity.rank)`) using
`Severity.rank`, a property on the enum that returns its index in a
fixed ordering list — so `CRITICAL` findings always surface at the top
of a target's block regardless of the order the finding-generators ran
in.

---

## Where new modules plug in

If you add a new check (either inside `evaluator.py` or as a fully
separate module like `reputation.py` was), the integration contract is
always the same three things:

1. Consume a `Policy` and/or `EffectivePolicy` — never a raw string.
2. Emit `Finding` objects with all fields populated (see
   `models.py::Finding`), choosing Severity per the principles in §2 and
   Confidence per the levels in §1.
3. Get called from `main.py::build_target_report` alongside the existing
   `evaluate_policy`/`evaluate_host_allowlist` calls, appending into the
   same findings list — `scoring.py` and `reporter.py` require no
   changes at all to pick up a new module's output, since they only ever
   consume `List[Finding]`.
