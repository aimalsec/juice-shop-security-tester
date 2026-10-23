# Limitations and Possible Improvements

## Limitations

1. **Payload coverage is intentionally small.** Each module uses a short,
   representative payload/field set rather than exhaustive fuzzing, to keep
   output reviewable. A true positive could be missed if a vulnerable query
   or model only reacts to a payload/field shape not included here.

2. **A real detection bug was found and fixed during development, and is
   worth documenting as part of the methodology.** The Mass Assignment
   module originally verified role elevation via `/rest/user/whoami`, which
   returns only `{id, email}` and never includes a role field at all —
   producing a false negative regardless of whether the vulnerability was
   present. This was caught by manually inspecting a captured JWT and
   noticing the role claim lived in `data.role` inside the token itself, not
   in the whoami response. The fix: decode the issued JWT and read the claim
   directly. This is a concrete example of why a single verification source
   should be sanity-checked against raw evidence (here, a manually decoded
   token) before trusting a "no finding" result.

3. **JWT decoding/forging does not verify signatures — by design.** The tool
   reads and rewrites JWT claims without ever needing the server's private
   key, which is exactly the property being tested (does the server itself
   verify the signature). This means a sufficiently different JWT library
   configuration on another target could behave differently in ways the
   tool doesn't account for (e.g. an endpoint that rejects `alg:none` but
   accepts a stripped/garbage signature on the original algorithm — not
   currently tested as a separate case).

4. **IDOR Phase 1 only probes a narrow numeric ID range** around the test
   account's own basket ID, and only on the basket endpoint. It does not
   test other IDOR-prone endpoints (order history, user profile by ID).

5. **The HTTP 500 on `' OR 1=1#` was flagged but not root-caused.** The tool
   correctly identifies it as noteworthy but cannot inspect server-side
   logs/stack traces to explain *why* it failed differently from the other
   four payloads — that required manually checking the container logs,
   which is outside the tool's reach by design (it only sees HTTP responses).

6. **Single-instance, single-run, sequential tool.** No historical run
   comparison, no concurrency (each request has a fixed delay), so a full
   scan takes longer than it would with parallelism.

7. **No WAF/IPS evasion handling.** Behind a WAF, payloads may be blocked or
   mangled in ways the tool reports as inconclusive rather than specifically
   identifying WAF interference.

8. **Mass assignment's candidate field list is a fixed guess list** (`role`,
   `isAdmin`, `admin`, `permissions`). A model with a differently-named
   privilege field (e.g. `userType`, `accessLevel`) would be missed entirely
   unless added to the list manually.

## Possible Improvements

- **Expand payload/field libraries** with a "quick" vs. "thorough" mode so
  default runs stay fast while allowing deeper coverage on demand.
- **Add a second JWT integrity test**: a tampered-signature (not just
  `alg:none`) variant, to distinguish "algorithm not restricted" from
  "signature not checked at all" as two separate, differently-severe findings.
- **Broaden IDOR coverage** to order history and profile endpoints, and
  support non-numeric (UUID-style) ID enumeration.
- **Add concurrency** (bounded thread pool) to reduce scan time while
  keeping the existing per-request delay as a per-thread rate limit.
- **Capture server-side evidence where possible** — e.g. an optional mode
  that also greps a provided Docker container's logs after a 500 response,
  for environments where the tester controls the container.
- **Persist run history** (e.g. append to a local SQLite file) to support
  regression testing between Juice Shop versions or configuration changes.
- **Extend the correlation pass** to a general rule engine (any N findings
  matching a declared pattern produce a synthesis finding) rather than the
  two hand-coded correlation rules currently implemented.
