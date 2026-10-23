# Testing Methodology (v2)

Three attack points were selected to each represent a distinct vulnerability
class, rather than three variants of the same flaw (injection / access
control / access control), and to build toward a cross-module correlation
step that demonstrates compounded risk.

---

## Attack Point 1: Authentication — SQL Injection login bypass

**Endpoint:** `POST /rest/user/login`
**Why selected:** The login endpoint is the application's primary trust
boundary and is reachable without any prior authentication, making it a
high-value, externally-exposed target.

**What was tested:**
1. Five SQL-injection tautology payloads (e.g. `' OR 1=1--`) submitted as
   the `email` field, each paired with a **negative control** payload of
   identical shape engineered to evaluate false (e.g. `' AND 1=2--`).
2. A 10-attempt rapid login-failure burst against a fixed account, with
   per-request latency captured, to test for rate limiting.

**Verification logic:** A bypass is only reported as **confirmed (critical)**
if the positive payload returns HTTP 200 with an auth token **and** its
paired negative control still returns 401. This rules out a generically
broken endpoint (one that accepts anything) as an alternative explanation,
isolating the cause to SQL truth-value injection specifically.

**Result:** 2/5 payloads confirmed (`' OR 1=1--`, `x' OR 'a'='a' LIMIT 1--`),
both of which returned a valid JWT for the real `admin@juice-sh.op` account
(`id:1`). One payload pair (`' OR 1=1#`) produced an HTTP 500 on both the
positive and negative control, flagged separately as a medium-severity
"unhandled server error" finding since no bypass could be confirmed but the
crash itself is informative. The rate-limiting burst showed 10/10 attempts
processed normally with no latency increase (medium severity).

---

## Attack Point 2: API Input Trust — Mass Assignment

**Endpoint:** `POST /api/Users/` (registration)
**Why selected:** This targets a different vulnerability class entirely —
not broken sanitization, but a backend trusting client-supplied fields that
the UI never exposes, binding them directly to the stored data model
(OWASP API Security Top 10: Broken Object Property Level Authorization).

**What was tested:** A baseline account was registered with only the
UI-exposed fields (email/password). Separate test accounts were then
registered, each adding one additional, non-UI field to the JSON body:
`role`, `isAdmin`, `admin`, `permissions`.

**Verification logic:** `/rest/user/whoami` was found during testing to
return only `{id, email}` and **not** a role field — relying on it would
produce false negatives regardless of whether the vulnerability is present.
The fix: each test account's role is read directly from the `data.role`
claim inside its own freshly-issued JWT (decoded, not trusted — no signature
verification is performed or required to read a claim). A finding is only
confirmed by comparing this value against the baseline account's role.

**Result:** The `role: "admin"` field was accepted and persisted — the test
account's issued JWT carried `"role":"admin"`, versus `"customer"` for the
baseline account, and the registration response itself (HTTP 201) echoed the
field back. Manually confirmed separately (see Evidence) by intercepting the
registration request, adding `"role":"admin"`, and subsequently loading
`/#/administration` successfully under that account.

---

## Attack Point 3: Authorization & Token Integrity — IDOR + JWT forgery (merged)

**Endpoints:** `GET /rest/basket/{id}`, `GET /rest/user/whoami`
**Why selected:** Structured as two phases sharing one legitimately-issued
token, so the module can report not just two isolated bugs but how they
compound: object-level authorization (do I need the right ID?) and token
integrity (do I need a real account at all?).

**Phase 1 — IDOR:** A test account's own basket ID was used as a center
point; the 10 adjacent IDs were requested using only that account's valid
token. Rather than one finding per accessible ID, results are aggregated
into a single finding with a **computed exposure rate** (`exposed / checked`),
and severity scales with that rate (≥80% → high, ≥30% → medium, otherwise low).

**Phase 2 — JWT signature integrity:** The Phase 1 token was decoded, and a
new token was forged with header `{"alg":"none","typ":"JWT"}`, no signature,
and a **fabricated identity** (`id:999999`, a never-registered email,
`role:"admin"`) substituted into the payload's `data` object. This forged
token was replayed against both `/rest/user/whoami` and `/rest/basket/{id}`.
Using a fabricated identity rather than reusing the real account's claims is
the key design choice: success proves the server will trust *any* token an
attacker cares to construct, not merely that one specific account's
signature is weak.

**Result:** Phase 1 — 10/10 adjacent basket IDs accessible (100% exposure,
high severity). Phase 2 — the forged token was rejected at `/rest/user/whoami`
but **accepted at `/rest/basket/{id}` (HTTP 200)**, confirming the server
does not validate JWT signatures or restrict accepted algorithms on at least
that endpoint — critical severity, since this required no valid account at
all, fabricated or otherwise.

---

## Cross-module correlation

After all three modules run, the tool checks for compounding conditions
across their results and emits synthesis findings that no single module
could produce on its own:

- **IDOR + JWT forgery** → an anonymous attacker needs neither a legitimate
  account nor correct object ownership to read arbitrary basket data.
- **Mass assignment + JWT forgery** → the privilege model is broken two
  independent ways: an attacker can either register a privileged account
  directly, or skip registration entirely and forge one.

## Common principles across all three modules

- A shared `requests.Session`, uniform timeout/retry-with-backoff error
  handling, and a consistent `Finding` data model, so the three modules
  function as one pipeline rather than three disconnected scripts.
- Every "confirmed" finding is backed by a comparison against a baseline or
  negative control — not a single request's status code in isolation.
- Severity is computed from measured impact (exposure rate, confirmed
  identity spoofing) rather than hardcoded per test.
