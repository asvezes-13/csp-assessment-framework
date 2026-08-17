# Findings Reference

This is the reference guide for every finding the framework can raise:
what triggers it, why it's flagged, what severity it gets, and what to do
about it. It exists so a developer looking at a report doesn't have to
read `evaluator.py`/`reputation.py` to understand *why* something was
flagged everything here is a static description of what's currently
implemented, cross-checked against the code that generates it.

If you change a severity or add a check in the code, update this
document in the same change.

---

## Severity scale

| Severity | Score deduction | Meaning |
|---|---|---|
| `CRITICAL` | -30 | Directly and materially enables script execution bypass (XSS) with no mitigating factor. Treat as a build-breaking issue. |
| `ALARM` | -18 | Substantially weakens a core protection (script/style execution or a broad, high-risk allowlist). Fix before the next release. |
| `VIOLATION` | -10 | A concrete gap in policy scope or a directive that permits more than it should. Should be scheduled and fixed. |
| `WARN` | -4 | A weaker-than-recommended configuration or a missing best practice. Worth fixing, not urgent. |
| `INFO` | -1 | An observation, a hygiene note, or something to be aware of but not necessarily wrong. |

Deductions are subtracted from a baseline of 100 (floor 0) to produce the
numeric score; see `scoring.py`. Letter grades: A ≥ 90, B ≥ 80, C ≥ 70,
D ≥ 60, F < 60.

**Confidence** (separate from severity) reflects how certain the engine is
that the finding is a real issue, not how severe it is: `CERTAIN` (rule is
unambiguous, e.g. presence of a keyword), `HIGH`, `MEDIUM`, `LOW`
(heuristic/contextual judgment, e.g. "sole reliance on default-src").

---

## 1. Mandatory directives

*Category: `mandatory-directive` — `csp_auditor/evaluator.py::_mandatory_directive_findings`*

Triggered when one of these five directives is missing **after** applying
CSP fallback/inheritance rules (i.e. it's not just absent, it's genuinely
unrestricted or falls back to something broader than intended).

| Directive | Severity | Why it's dangerous when missing |
|---|---|---|
| `script-src` | `CRITICAL` | Falls back to `default-src` if present, or is otherwise completely unrestricted. Script execution is the highest-impact resource type CSP controls — an attacker who can inject markup can run arbitrary JS from any origin. |
| `default-src` | `VIOLATION` | Every fetch directive without its own explicit value and no other fallback becomes completely unrestricted. This is the safety net for anything you forgot to declare. |
| `object-src` | `VIOLATION` | Legacy plugin content (Flash/Java applets/etc.) is unrestricted or inherits a likely-too-broad `default-src`. Plugin content has historically been a common XSS/UXSS vector, independent of script-src. |
| `base-uri` | `VIOLATION` | **Has no `default-src` fallback at all.** If missing, an attacker who achieves any HTML injection can rewrite `<base href>` and hijack every relative-URL script/resource load on the page to an attacker-controlled origin — even with a strong `script-src`. |
| `frame-ancestors` | `WARN` | **Has no `default-src` fallback.** If missing, any origin can iframe the page, enabling clickjacking, unless a legacy `X-Frame-Options` header compensates. Lower severity than `base-uri` because a compensating legacy header is common and the attack requires UI interaction. |

**Programmer takeaway:** these five are the "always specify these"
baseline. `base-uri` and `frame-ancestors` are the two easiest to forget
precisely *because* they have no fallback — a strict `script-src` gives a
false sense of complete coverage without them.

---

## 2. Unsafe keywords

*Category: `unsafe-keyword` — `csp_auditor/evaluator.py::_unsafe_keyword_findings`*

Triggered whenever any directive contains one of these CSP keywords.

| Keyword | Severity | Condition | Why it's dangerous |
|---|---|---|---|
| `unsafe-inline` | `CRITICAL` | in any `script-*` directive | Allows any inline `<script>` or event handler to execute. This is the single most common way CSP gets defeated — it re-opens the exact XSS vector CSP exists to close. Only reduced to informational if a nonce/hash is *also* present (modern browsers then ignore it — see §4). |
| `unsafe-eval` | `CRITICAL` | in any `script-*` directive | Permits `eval()`, `new Function()`, string-form `setTimeout`/`setInterval`, etc. — lets attacker-controlled strings run as code even without inline `<script>` injection. |
| `unsafe-inline` | `ALARM` | in any non-script directive (e.g. `style-src`) | Same mechanism, lower blast radius — CSS injection can still exfiltrate data (attribute selectors) or deface pages, but can't directly run JS. |
| `unsafe-eval` | `ALARM` | in any non-script directive | Rare in practice; still permits dynamic-code evaluation for that resource type. |
| `unsafe-hashes` | `ALARM` | any directive | Allows inline **event handlers** (`onclick=`, etc.) matching an allow-listed hash. Broadens the inline-execution surface beyond `<script>` tags specifically. |
| `unsafe-allow-redirects` | `ALARM` | any directive | Exempts automatic redirects following a fetch from target-based restrictions — an allowed origin can redirect to a disallowed one and still be honored. |

**Programmer takeaway:** any `unsafe-*` keyword in `script-src` is a hard
stop for a mature CSP. If you have `unsafe-inline` because of legacy
inline `<script>` blocks, the fix is nonces/hashes, not leaving it in
place indefinitely.

---

## 3. Dangerous source expressions

*Category: `dangerous-source` — `csp_auditor/evaluator.py::_dangerous_source_findings`*

Triggered for wildcard sources (`*`, `*.example.com`) and broad scheme
sources (`data:`, `blob:`, `http:`, `https:`, `filesystem:`,
`mediastream:`, `ftp:`) in any directive.

| Pattern | Severity | Condition | Why it's dangerous |
|---|---|---|---|
| `*` or `*.domain` (wildcard) | `ALARM` | in `script-*` directives | Any origin (or any subdomain) matching the pattern can supply executable script. For script execution specifically, this is nearly as bad as `unsafe-inline` — you're trusting the security posture of every matched origin. |
| `*` or `*.domain` (wildcard) | `VIOLATION` | in any other directive | Still overly broad, lower impact than script (e.g. wildcard `img-src` mostly affects tracking/defacement risk, not code execution). |
| `data:` | `ALARM` | in `script-*` directives | `<script src="data:...">` is a well-documented, direct CSP bypass — it allows inline-equivalent script execution without touching `unsafe-inline`. |
| `http:` | `ALARM` | in `script-*` directives | Allows script from **any plaintext HTTP origin**, including on-path/MITM attackers on shared networks. |
| `data:` / `http:` / `blob:` / `filesystem:` / `mediastream:` / `https:` / `ftp:` | `VIOLATION` | in any non-script directive | Broad scheme-wide allowlisting for non-script resources (images, media, fonts, etc.) — lower risk than script but still means "any host reachable via this scheme," which defeats the purpose of an origin allowlist. |

**Programmer takeaway:** if you see `ALARM` here, check whether you
actually need scheme-wide or wildcard access, or whether a specific list
of origins would work — it almost always would.

---

## 4. Modern CSP feature analysis (nonce / hash / strict-dynamic)

*Category: `modern-csp` — `csp_auditor/evaluator.py::_nonce_hash_strict_dynamic_findings` and `_modern_feature_findings`*

These check the interaction between `strict-dynamic`, nonces, hashes, and
`unsafe-inline` in `script-src`/`script-src-elem`/`style-src`/`style-src-elem`,
plus two general modern-CSP hygiene checks.

| Condition | Severity | Explanation |
|---|---|---|
| `strict-dynamic` present **without** a nonce or hash in the same directive | `VIOLATION` | `strict-dynamic` needs a nonce/hash to establish the initial trusted script(s) that then propagate trust to dynamically-created scripts. Without one, no script can bootstrap trust — either legitimate scripts silently fail, or (in browsers that don't support `strict-dynamic`) the directive is a no-op and any host/scheme allowlist in the same directive is what actually governs behavior. |
| Nonce or hash present **without** `strict-dynamic` (script directives only) | `INFO` | Not wrong, just worth knowing: dynamically-inserted scripts (e.g. from a trusted, nonce'd bootstrap script) will **not** be trusted unless they also carry the nonce/hash. `strict-dynamic` is what lets a bootstrap script's own dynamically-created children inherit trust automatically. |
| `unsafe-inline` present **alongside** a nonce or hash in the same directive | `INFO` | CSP Level 2+ browsers **ignore** `unsafe-inline` whenever a nonce/hash source is also present — so modern browsers are unaffected. Flagged at INFO rather than CRITICAL specifically because of this ignore-rule; it only matters for legacy browsers without nonce/hash support (where `unsafe-inline` still fully applies). |
| `require-trusted-types-for` not set, while `script-src` is declared | `INFO` | Trusted Types is a strong DOM-XSS sink defense (blocks dangerous sinks like `innerHTML` from accepting raw strings) in supporting browsers. Not having it isn't a vulnerability by itself, but it's a meaningful defense-in-depth gap for apps handling untrusted DOM content. |
| `upgrade-insecure-requests` not set | `INFO` | Mixed-content HTTP subresource requests on an HTTPS page are not automatically upgraded by CSP. Browsers may still separately block/warn on mixed content, so this is a "nice to have" rather than a gap, hence low severity. |

**Programmer takeaway:** `strict-dynamic` + nonce is the modern
recommended pattern for `script-src`; if you have one without the other,
you're not getting the intended protection model.

---

## 5. Reporting configuration

*Category: `reporting` — `csp_auditor/evaluator.py::_reporting_findings`*

| Condition | Severity | Why it matters |
|---|---|---|
| Neither `report-uri` nor `report-to` present | `WARN` | The browser still **enforces** the policy without reporting — this is not a security hole in the policy itself — but you get zero visibility into what's being blocked, which makes it impossible to safely tighten the policy over time or detect active exploitation attempts hitting the policy. |
| `report-uri` present but `report-to` absent | `INFO` | `report-uri` is deprecated in favor of `report-to` (which needs a companion `Reporting-Endpoints`/`Report-To` header). Relying solely on the legacy directive risks silently losing reports as browser support for it is phased out. |

---

## 6. Best-practice / structural checks

*Category: `best-practice` — `csp_auditor/evaluator.py::_object_src_base_uri_findings` and `_default_src_reliance_findings`*

| Condition | Severity | Why it matters |
|---|---|---|
| `object-src` present but not set to `'none'` | `WARN` | OWASP/CSP best practice is `object-src 'none'` unless legacy plugin content is genuinely required — there's rarely a legitimate reason for a modern web app to allow object/embed content at all. |
| Policy declares `default-src` but no other fetch directives at all | `INFO` | Every resource type (script, style, img, connect, etc.) shares exactly the same allowlist. This is usually broader than necessary for at least one resource type — most commonly `script-src` should be tighter than what's appropriate for images/fonts. |

---

## 7. Meta-tag-specific checks

*Category: `meta-csp` — `csp_auditor/evaluator.py::_meta_specific_findings`, applied only when `policy.source == META_TAG`*

Certain directives are **silently ignored by browsers** when delivered via
`<meta http-equiv="Content-Security-Policy">` instead of the HTTP header.
If found in a meta-delivered policy, each is flagged:

| Directive | Severity | Why |
|---|---|---|
| `frame-ancestors` | `WARN` | Meaningless in `<meta>` — clickjacking protection you believe you have is not actually enforced. |
| `report-uri` | `WARN` | Meaningless in `<meta>` — you believe you have reporting, but no reports are sent. |
| `report-to` | `WARN` | Same as above. |
| `sandbox` | `WARN` | Meaningless in `<meta>` — sandboxing restrictions are not applied. |

**Programmer takeaway:** this is a "false sense of security" class of bug
— the policy *looks* complete when read, but silently does less than it
appears to. If your app relies on a `<meta>` CSP (common for static sites
without server-side header control), double-check none of these four
appear in it.

---

## 8. Parsing observations

*Category: `parsing` — `csp_auditor/evaluator.py::_parser_issue_findings`, sourced from `csp_auditor/parser.py`*

Not security findings in the traditional sense — these describe how the
parser interpreted ambiguous or malformed input. Always non-fatal; the
rest of the policy is still evaluated normally.

| Condition | Severity | Behavior |
|---|---|---|
| Duplicate directive name within one policy | `WARN` | Per spec, browsers honor only the **first** occurrence and silently ignore later ones. If your second `script-src` was meant to be authoritative, it isn't — this is a common cause of "I added a directive but it's not working." |
| Obsolete/deprecated directive (`reflected-xss`, `referrer`, `plugin-types`, `disown-opener`, `child-src` used past its CSP3 role) | `INFO` | No longer has any effect (or has a narrowed effect) in modern browsers. Harmless to leave in for backward compatibility, but shouldn't be relied on. |
| Unrecognized/unknown directive name | `INFO` | Browsers ignore directives they don't recognize (typos, vendor-specific extensions, or genuinely new directives not yet in this framework's known-directive list). Worth double-checking for typos (e.g. `scrip-src`). |
| Malformed quoted token (e.g. `'unsafe-inlin'`) | `INFO` (surfaces via the same mechanism as above) | A quoted value that isn't a recognized keyword/nonce/hash pattern — almost always a typo that silently does nothing. |

---

## 9. Host Reputation (allowlist) — optional module

*Category: `host-reputation` — `csp_auditor/reputation.py`, only active when `host_allowlist.enabled: true` in `config.yaml`*

Unlike the checks above, this module is **config-driven and opt-in**: it
doesn't ship with any built-in judgment about which hosts are dangerous.
Instead, you provide `trusted_domains`, and it flags **any host in the
configured directives that is not covered by that list** — a fail-closed
whitelist, not a threat-intelligence blacklist.

| Condition | Severity | Configurable? |
|---|---|---|
| A host-shaped source expression does not match any entry in `trusted_domains` (exact match, or CSP-accurate wildcard subdomain match) | `WARN` by default | Yes — set `host_allowlist.severity` to `INFO`/`WARN`/`VIOLATION`/`ALARM`/`CRITICAL` per your org's risk tolerance |

**What counts as "host-shaped":** anything that isn't a keyword (`'self'`,
`'none'`, `'unsafe-inline'`, ...), a nonce, a hash, or a bare scheme
(`data:`, `https:`, ...) — those are out of scope for this module because
they're either not hosts or already covered by §3 above.

**Why flag unlisted hosts even if they're not known-bad:** a blacklist can
only catch infrastructure that's already known to be malicious — it
always lags behind newly-registered attacker domains, typosquats, and
compromised-but-previously-legitimate hosts. A whitelist has no such lag:
if a host was never approved, it's flagged, full stop. The tradeoff is
maintenance burden (you must keep `trusted_domains` current), which is why
this module is opt-in rather than baked into the default checks.

**Programmer takeaway:** when you see an `Untrusted host in <directive>:
<host>` finding, the decision is binary — either add the host (or a
`*.domain` wildcard covering it) to `trusted_domains` because it's a
legitimate, intentional dependency, or remove it from the CSP because it
isn't.

---

## Quick lookup: severity by check type

| Severity | Checks that can produce it |
|---|---|
| `CRITICAL` | Missing `script-src` · `unsafe-inline`/`unsafe-eval` in a `script-*` directive |
| `ALARM` | `unsafe-hashes` / `unsafe-allow-redirects` (any directive) · `unsafe-inline`/`unsafe-eval` in non-script directives · wildcard or `data:`/`http:` sources in `script-*` |
| `VIOLATION` | Missing `default-src` / `object-src` / `base-uri` · wildcard or broad-scheme sources in non-script directives · `strict-dynamic` without nonce/hash |
| `WARN` | Missing `frame-ancestors` · duplicate directive · no reporting configured · `object-src` not `'none'` · meta-tag-ignored directives · host allowlist (default) |
| `INFO` | Parsing observations (unknown/obsolete directives) · legacy `report-uri` without `report-to` · nonce/hash without `strict-dynamic` · `unsafe-inline` redundant next to nonce/hash · missing Trusted Types / `upgrade-insecure-requests` · sole reliance on `default-src` |

---

## Where this maps in the codebase

| Section above | Module | Function(s) |
|---|---|---|
| 1. Mandatory directives | `evaluator.py` | `_mandatory_directive_findings` |
| 2. Unsafe keywords | `evaluator.py` | `_unsafe_keyword_findings` |
| 3. Dangerous sources | `evaluator.py` | `_dangerous_source_findings` |
| 4. Modern CSP features | `evaluator.py` | `_nonce_hash_strict_dynamic_findings`, `_modern_feature_findings` |
| 5. Reporting | `evaluator.py` | `_reporting_findings` |
| 6. Best practice | `evaluator.py` | `_object_src_base_uri_findings`, `_default_src_reliance_findings` |
| 7. Meta-tag | `evaluator.py` | `_meta_specific_findings` |
| 8. Parsing | `parser.py` + `evaluator.py` | `parse_policy`, `_parser_issue_findings` |
| 9. Host Reputation | `reputation.py` | `evaluate_host_allowlist` |

To change a severity or wording, edit the corresponding function and
update the matching row in this document in the same commit.
