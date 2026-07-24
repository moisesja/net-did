---
name: spec-conformance-audit
description: Audit net-did against the normative DID specs and file one GitHub issue per finding — read claims, green baseline, targeted repros, cross-check external spec text, severity+impact+file:line, residual-risk statement. Use when asked to audit conformance/security, review the codebase against the spec, hunt for gaps the tests miss, or "check we actually comply with did:key/did:peer/did:webvh/DID Core".
---

# net-did spec-conformance audit

Finds what a **passing** test suite misses: behavior that is internally self-consistent but externally non-compliant. The output is one filed issue per validated finding — not a fix (that's `net-did-fix`).

## 1. Set scope + read the claims
- Pick the surface (a method, a serializer, a resolver, a whole spec section).
- Read the project's own claims: `NetDidPRD.md` (source of truth), `README.md`, `AGENTS.md`, `SECURITY.md`, `CONTRIBUTING.md`, `w3c-conformance-report.md`. Note where docs overstate reality (precedent: AGENTS.md claimed 5 methods, PRD claimed W3C-suite-in-CI, neither backed by the solution/CI).

## 2. Establish a green baseline
- Run the full suite (`net-did-verify` or at least `dotnet test netdid.sln -c Release`) and record the total. The audit's premise is that these all pass yet gaps remain — "current automated coverage does not detect these issues."

## 3. Cross-check against the NORMATIVE spec
- Fetch the actual spec text and **quote the rule** — do not audit from memory. Relevant specs:
  - **DID Core 1.0** (identifier ABNF, document structure)
  - **DID Resolution** (dereferencing algorithm, `representationNotSupported`, relative-ref normalization)
  - **did:key**, **peer-DID method** (numalgo 0/2/4, purpose codes `A/E/V/I/D/S`), **did:webvh v1.0** (SCID/entryHash multihash wire, `eddsa-jcs-2022`, pre-rotation `nextKeyHashes` state machine, JCS/RFC 8785)
- Writer/reader parity within the library is **not** proof of conformance — verify round-trips against external/real-world example values, not just NetDid's own output.

## 4. Build targeted repros
- Minimal throwaway harness (a `/tmp` console or a scratch xUnit fact) that demonstrates each suspected divergence concretely. Pin the observed vs. expected behavior.

## 5. Write findings
Each finding: **title**, **summary**, **affected code** (`path/File.cs:line`), **why it matters**, **reproduction** (runnable snippet), **expected vs. actual behavior**, **suggested fix**, **severity** (High/Medium/Low). Match the shape of the existing `tasks/issue-audit-*.md` files.

## 6. File issues + residual-risk
- Draft each body as `tasks/issue-<slug>.md`, then `gh issue create` one issue **per validated finding**; record the issue URLs.
- Write a **"Scope and limitations / residual risk"** section stating explicitly what was NOT covered (e.g. no external W3C test-suite run, no fuzzing, no CVE enumeration) — never imply the audit was exhaustive.

## Where findings land later (for the fix phase)
- DID-Core statement gaps → `NetDid.Tests.W3CConformance` (and add a row to `w3c-conformance-report.md`).
- Method-specific hostile-input behavior → the per-method `NetDid.Method.*.Tests` project, linked from the conformance report's audit table.

## Recurring gap classes seen in this repo (start here)
- Loose parser regexes accepting DID URLs / illegal chars as bare DIDs.
- Resolution validating key **length** only, not EC-point-on-curve validity.
- Serializers leaking private JWK `d`, or dropping object-valued `@context`.
- Dereferencer ignoring embedded verification methods / not returning `representationNotSupported`.
- did:webvh wire encodings self-consistent but not multihash/multibase-conformant.
- numalgo 4 resolution not fully rewriting placeholder DIDs / dropping `@context` + `AdditionalProperties`.
- Docs/CI claims exceeding what the solution actually implements.
