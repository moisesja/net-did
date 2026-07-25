# PR #104 Round-Two Fix Plan

## Context

The second validation of PR #104 found four confirmed correctness/security issues in the
`did:ethr` resolver:

1. A history block containing both valid and malformed authorization logs can still be
   accepted, allowing a malformed revocation to be skipped while a valid authorization
   remains active.
2. Missing or duplicate `logIndex` values can make same-block event replay
   nondeterministic and authorization-sensitive.
3. Invalid or mutually exclusive historical resolution options silently fall back to
   latest-state resolution.
4. A generated secp256k1 key pair is not deterministically disposed after DID creation.

This is an in-place fix on the existing PR branch. It will not create another branch or
PR, and it will not merge PR #104.

## Scope

Close the full invalid-state classes behind the reported defects rather than only the
individual examples:

- Treat every matching registry log in an asserted `previousChange` block as an
  all-or-nothing input set.
- Reject malformed/null logs and inconsistent registry, identity, block-number, or
  ordering metadata.
- Require explicit, valid, unique `logIndex` values while allowing legitimate
  non-contiguous indices.
- Reject invalid historical selector syntax and the simultaneous use of `versionId`
  and `versionTime` before any RPC request.
- Deterministically dispose generated private-key material.
- Harden ABI dynamic offset/length decoding against non-zero high bytes because those
  malformed words currently bypass the same fail-closed log boundary.

Out of scope: unrelated service-endpoint JSON interoperability changes and other
feature expansion not required to close these findings.

## Plan

- [x] Add fail-first regression tests named `Pr104Round2_*` covering:
  - a same-block valid authorization followed by a malformed revocation;
  - null JSON entries returned by `eth_getLogs`;
  - missing, null, and malformed `logIndex` values in RPC responses;
  - duplicate same-block log indices, including reverse-order add/revoke input;
  - foreign registry address, foreign identity, mismatched block number, and
    forward-pointing `previousChange` values;
  - legitimate non-contiguous log indices;
  - malformed ABI dynamic offset/length words with non-zero high bytes;
  - invalid `versionId` forms (empty, whitespace, signs, hexadecimal, and overflow);
  - invalid `versionTime` forms (offsets, fractional seconds, and non-timestamps);
  - simultaneous `versionId` and `versionTime`;
  - valid canonical selectors;
  - no RPC interaction for invalid resolution options;
  - disposal of a generated key pair after `CreateAsync`.
- [x] Run the focused tests before implementation and record the expected failures.
- [x] Implement one fail-closed validation path for historical registry logs:
  - materialize the returned log set once;
  - fail resolution on any malformed/null entry;
  - require matching registry address, identity, and requested block number;
  - reject forward-pointing history links;
  - require unique `logIndex` values and replay in ascending order;
  - retain support for non-contiguous indices.
- [x] Make the HTTP RPC decoder reject absent, null, or malformed `logIndex` fields.
- [x] Validate full 256-bit ABI dynamic offsets and lengths before narrowing them to
  platform-sized indices.
- [x] Add a core `invalidOptions` resolution-result factory and validate selectors
  before opening an RPC client:
  - `versionId` must be an unsigned canonical base-10 block number;
  - `versionTime` must be normalized UTC `yyyy-MM-dd'T'HH:mm:ss'Z'`;
  - the two selectors are mutually exclusive.
- [x] Dispose generated key pairs with deterministic lifetime while retaining the
  defensively copied public key.
- [x] Run focused tests after implementation.
- [x] Run the complete `net-did-verify` gate:
  - zero-warning Release build;
  - every test project with per-project counts;
  - W3C conformance at 233/233 and restore timestamp-only report churn;
  - all affected samples end-to-end;
  - `git diff --check`.
- [x] Run an independent adversarial review of the completed diff, verify every
  reported concern against code/tests, fix all confirmed findings, and repeat the
  full verification gate if code changes.
- [x] Update `NetDidPRD.md`, `README.md`, and `CHANGELOG.md` with the strict
  fail-closed and historical-option behavior.
- [x] Update `tasks/lessons.md` with the correction pattern: security fixes must close
  the entire invalid-state class, including mixed-validity input and missing ordering
  metadata, rather than only the originally demonstrated case.
- [x] Complete the review record below, commit intentionally, push the existing PR
  branch, and post a concise PR comment with the fixes and verification evidence.

## Expected Files

| Area | Expected files |
|---|---|
| Resolver and creation lifecycle | `src/NetDid.Method.Ethr/DidEthrMethod.cs` |
| RPC wire validation | `src/NetDid.Method.Ethr/Rpc/DefaultEthereumRpcClient.cs` |
| ABI validation | `src/NetDid.Method.Ethr/Abi/AbiDecoder.cs` |
| Resolution metadata | Core resolution-result source located during implementation |
| Regression tests | Focused `NetDid.Method.Ethr.Tests` and core test files |
| Documentation | `NetDidPRD.md`, `README.md`, `CHANGELOG.md` |
| Process record | `tasks/lessons.md`, this file |

## Review

Implemented the four reported fixes as one fail-closed boundary pass and closed every
confirmed residual found by two independent adversarial reviewers.

### Fail-first evidence

- Initial closure matrix: 26 failed / 4 passed before implementation.
- First adversarial residuals added red coverage for incomplete same-block links,
  removed logs, canonical RPC metadata, malformed topics/ABI tails, and JSON envelope
  shapes.
- Final adversarial residuals added red coverage for malformed `changed(identity)`
  return words, non-increasing block timestamps, public RPC result types, exact ABI
  primitive lengths, and lowercase canonical wire syntax.
- Final focused negative/control set: 87/87 passed (81 `Pr104Round2_*` cases plus the
  six malformed-`changed` theory cases).

### Final behavior

- Registry history blocks are parsed and committed atomically.
- Canonical `logIndex`, `blockNumber`, `removed`, registry, identity, block, ABI, topic,
  and `previousChange` invariants are enforced.
- `changed(identity)` and block timestamps cannot silently truncate or reorder history.
- Invalid or mutually exclusive historical selectors return `invalidOptions` before RPC.
- Generated secp256k1 key material is deterministically disposed.

### Verification

- Release build: 0 warnings, 0 errors.
- Full solution: 1,332/1,332 tests passed:
  - Core 377
  - did:key 52
  - did:peer 48
  - did:webvh 411
  - did:ethr 193
  - dependency injection 18
  - W3C conformance 233
- W3C report timestamp-only churn restored.
- Samples passed: did:key, did:peer, did:webvh, did:ethr against live Sepolia, and
  dependency injection.
- Two independent final adversarial reviews returned clean verdicts.
- `git diff --check` passed.

Publishing target: existing branch `feat/did-ethr-resolver`, PR #104. No merge performed.
