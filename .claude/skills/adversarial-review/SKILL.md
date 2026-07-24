---
name: adversarial-review
description: Mandatory red-team pass over a completed net-did diff (CLAUDE.md §2) — independent adversarial subagents attempt to defeat the change, per-finding CONFIRMED/refuted, encoding the accumulated trust-boundary/crypto lessons. Use after implementing any security-sensitive net-did change (crypto, key handling, did:webvh log validation, serialization, parsing, trust boundaries) and before opening the PR. Complements built-in /security-review with net-did's specific failure modes.
---

# net-did adversarial review

CLAUDE.md §2: "Always use adversarial agents to attempt to exploit the code that is being generated." Run this on the **completed** diff, not the plan. Goal: make the change fail before an attacker does.

## Process
1. Spawn one or more **independent** adversarial subagents (use several diverse lenses for high-value changes — e.g. correctness / crypto / trust-boundary / spec-conformance / does-it-actually-reproduce). Each is prompted to **refute** the change's security claims, not confirm them.
2. For each finding, verify per-finding: reproduce it or refute it. Classify **CONFIRMED / out-of-scope / refuted**. Default to "real" only when demonstrated.
3. Fix every CONFIRMED finding, then **re-run** the affected validation (and `net-did-verify`).
4. Record a final verdict line ("verdict: clean" only when it is).
5. **Disclosure discipline:** if you find a vulnerability in a *different* subsystem, report it to the maintainer **out-of-band** — keep unpatched issues out of public artifacts (PR text, committed task files, issue bodies).

## The net-did red-team checklist (from lessons.md — check each)

**Trust boundaries / TOCTOU**
- Treat every caller-supplied interface-typed collection (`IReadOnlyList<T>`, `IEnumerable<T>`) as **adversarial**: an implementation can return different contents per enumeration. **Snapshot once at entry** and use the private copy for validation, comparison, hashing/signing, serialization, AND reported evidence. A post-return defensive copy alone only fixes the last read. Model hostile *implementations of interfaces*, not just mutation of a concrete `List<T>`.

**Security postconditions**
- State them in **exclusive/complete** form. A membership check ("new key present, retired key absent") silently admits **supersets** with unexpected extra keys. Exclusive rotation requires **set-equality** against the intended post-rotation set — assert it and document it that way.

**Spec conformance vs. self-consistency**
- Writer/reader parity **inside one library is not spec conformance.** Before publishing any security contract about a spec-governed format, fetch the **normative spec text and quote the rule.** (Precedent: a #91 evidence contract repeated NetDid's did:webvh pre-rotation deviation as a promise — see #93. did:webvh v1.0 authorizes a pre-rotation entry with the *current* entry's own `updateKeys`; the prior-keys rule only holds when pre-rotation is inactive.)

**Crypto key material**
- Never emit private JWK members (`d`, RSA private fields) from `publicKeyJwk` — sanitize or reject non-public JWKs before serialization (issue: private-JWK leak).
- Validate EC public keys are **valid points on the curve** (`KeyTypeExtensions.IsValidEcPoint()`), not just the right byte length. A correct-length malformed point must be rejected on resolution.
- Normalize caller-supplied `ExistingKey.PublicKey` to compressed SEC1 (33/49 bytes) before building an identifier — don't trust external bytes as-is.

**Parsing / input validation**
- Bare-DID validation must reject fragments, queries, paths, spaces, percent-encoding — a permissive `^did:[a-z0-9]+:.+$` lets DID URLs and illegal chars into the `Did` value object. Use `DidParser.IsValidDidReference()` for relative refs; `ParseDidUrl` only for absolute URLs.
- Map malformed fetched content to an error **only at the trust boundary that consumed it** (e.g. a bad timestamp in a fetched did:webvh log is `invalidDidLog`) — a broad catch relabels unrelated format errors and changes Create/Update exception contracts.

**Limits / knobs**
- A timeout or size limit layered on a framework default must turn in **both** directions. `HttpClient.Timeout` (100s default) enforces its own linked token, so a per-request CTS can only *shorten* it — neutralize the hidden default (`Timeout.InfiniteTimeSpan`) on library-owned resources, leave caller-injected ones untouched, and test the raise-above-default direction.
- SSRF: vet connection targets (ConnectCallback) on outbound did:webvh fetches; enforce response size/time resource limits.

**Breaking-change framing**
- A secure-by-default restriction that removes a previously tested workflow is still a **breaking change** — document every affected public path, whether customization can bypass it, and the supported replacement.

## Output
Per finding: severity, `file:line`, exploit scenario, CONFIRMED/refuted, and the fix (or why out-of-scope). End with the overall verdict and confirm the affected validation was re-run.
