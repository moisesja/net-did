# PR #132 Round-2 Fix — Aggregate Timestamp Wait Bound

## Context

PR #132 head `d5dddf0` closes the four round-1 findings, but
`DidWebVhMethod.GetNextVersionTimeAsync` bounds each UTC-derived delay independently rather than
bounding aggregate elapsed time. If UTC stalls or moves backward while timers continue firing,
the loop can exceed the documented two-second maximum indefinitely. This is a Medium availability
and contract defect. Documentation also describes the threshold as the log head's lead over the
clock, while the implementation actually bounds time until the next strictly increasing
whole-second timestamp.

The normative writer rule remains unchanged: the new `versionTime` must be strictly later than the
previous entry and no later than witness/resolver retrieval. The monotonic deadline is an
implementation resource bound; it must not alter timestamp selection.

## Plan

- [x] Add fail-first `Issue127_*` tests for a frozen UTC clock with advancing elapsed time, a
      backward UTC step, and caller cancellation during the new wait.
- [x] Prove the aggregate-bound regression fails quickly against `d5dddf0` using an external test
      timeout; avoid allowing the old infinite loop to wedge the suite.
- [x] Enforce one aggregate two-second budget using the injected `TimeProvider` monotonic timestamp
      across every loop iteration.
- [x] Update the deterministic clock fixtures so UTC and monotonic time can advance independently.
- [x] Reword code, README, PRD, CHANGELOG, PR body, and review records around whether the next
      authorable whole-second timestamp is reachable within the remaining aggregate budget.
- [x] Remove avoidable real-clock sleeps from WebVh test fixtures so the full unit suite does not
      retain the observed ~51-second timing tax.
- [x] Run focused tests, the full `net-did-verify` gate, and `git diff --check`.
- [x] Run independent adversarial review; fix and re-verify every confirmed finding.
- [x] Append the review evidence, commit, push the existing PR branch, update PR #132, and post a
      response to the round-2 review. Do not merge.

## Files touched

| File | Intended change |
|---|---|
| `src/NetDid.Method.WebVh/DidWebVhMethod.cs` | Aggregate monotonic wait deadline and accurate error contract |
| `tests/NetDid.Method.WebVh.Tests/AutoAdvanceTimeProvider.cs` | Independent UTC/elapsed-time test control |
| `tests/NetDid.Method.WebVh.Tests/LogChainValidatorTimestampTests.cs` | Frozen/backward/cancellation regression matrix |
| WebVh test fixtures/helpers as needed | Deterministic clocks instead of real one-second sleeps |
| `README.md`, `NetDidPRD.md`, `CHANGELOG.md` | Correct bounded-wait wording |
| `tasks/todo20260803-issue127.md` | Round-2 implementation/verification record |
| `tasks/todo20260803-pr132-revalidation.md` | Link the implemented resolution |

## Out of scope

- Issue #131 read-side future-skew enforcement remains separate; this change only bounds authoring
  waits after the supplied chain passes today's validation.
- Timestamp serialization, fractional imported-log reading, proof/hash generation, and other DID
  methods are unchanged.
- No public clock configuration is added; the existing internal seam remains test-only.

## Review (2026-08-03)

### Implementation

- `GetNextVersionTimeAsync` captures one injected monotonic start timestamp and carries the same
  two-second remaining budget through every retry. Frozen/backward UTC cannot reset it.
- Elapsed time is sampled before the eligible-success path. A timer that resumes after the
  deadline fails even if UTC reached the target during the oversleep; exact two-second eligibility
  still succeeds.
- Caller cancellation is checked before each clock sample and remains wired into the delay.
- The WebVh high-frequency test fixture shares an exact-second auto-advancing clock per xUnit test
  instance. Its 108 tests now take ~256 ms; the full WebVh suite fell from ~51 s to ~6 s.
- README, PRD, CHANGELOG, code comments, and error text describe reachability within the remaining
  aggregate budget, rather than the inaccurate head-lead threshold.

### Fail-first evidence

- Against the pre-fix loop, frozen UTC reached the third-timer guard instead of the promised
  `ArgumentException`, and a backward UTC step succeeded after 2.5 virtual seconds; caller
  cancellation already propagated.
- Against the first aggregate-deadline implementation, both Update and Deactivate overslept-timer
  tests failed because the operation returned success after 3 monotonic seconds. Moving the elapsed
  check before success made both green.

### Adversarial review

- Deadline lens: confirmed the Medium overslept-timer bypass above; frozen/backward UTC,
  cancellation, forward jumps, fractional heads, MaxValue, and negative elapsed otherwise held.
- Oracle/docs lens: confirmed inaccurate “more than 2 seconds away” wording and incomplete direct
  Deactivate loop coverage. Wording was corrected; frozen/backward and oversleep tests now exercise
  both Update and Deactivate.
- Final verdict: clean after fixes and full re-verification.

### Verification after adversarial fixes

- Release build: 0 warnings, 0 errors.
- Tests: Core 418; Key 52; Peer 48; WebVh 437; Ethr 490; DI 20; W3C 233/233;
  Ethr integration 11 passed / 7 expected real-EVM skips. Total: 1,709 passed.
- Samples: did:key, did:peer, did:webvh, did:ethr, and DI all exit 0; did:key was run outside
  the sandbox so macOS AppleCrypto could load its native provider.
- `git diff --check` clean; generated W3C timestamp churn restored.
