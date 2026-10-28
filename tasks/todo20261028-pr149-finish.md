# Finish PR #149 review fixes

## Context

The user explicitly requested implementation of both review findings, without another
review/fix handoff. Checkout and remote PR have advanced to 6f05f34290725829e338a29440e658253802ed11:
9f716ae implements relative DID URL handling, 3e70eb0 implements encoded-document authority
for peer Create, and subsequent commits add regressions and related corrections.
Preserve these existing changes; verify before adding any further implementation.

## Plan

- [x] Rebaseline branch, remote PR, existing fixes and tests.
- [x] Re-run the exact prior reproductions and verify new positive controls.
- [x] Inspect the completed fixes with an independent adversarial pass; fix confirmed gaps.
- [x] Run Release build, all tests, samples, conformance and EVM verification.
- [x] Record results and update PR with the concrete verified outcome.

No merge, version bump, or edits outside the affected fixes. Existing local re-review notes
are unrelated to the implementation and remain untouched.

## Review

Both implementation fixes were already committed and pushed before this turn began; no
additional production change was needed. Verification at 6f05f34:

- The original parser probe now reads/writes /keys/1, keys/1#k and ?versionId=1#key-1.
- Issue145_Numalgo2Create_ServicesReadTwoWays_ValidatesWhatItEncodes passes: the malformed
  enumerated service is rejected, and normal-list Create/Resolve equality controls pass.
- One independent adversarial pass over the completed fixes: clean; no confirmed residual.
- Release build: 0 warnings/errors. Default suite: 2,319 passed, 7 opt-in EVM cases skipped.
  Core 748, Key 54, Peer 114, WebVh 604, Ethr 529, DI 26, W3C 233, integration gate 11.
- Separate real-EVM run: 18/18. Five offline samples: exit 0.
- CI 40762475189 succeeded. Working-tree and full-PR whitespace checks clean.
- Remote refs unchanged throughout validation. W3C report timestamp churn restored.

The existing CHANGELOG and PRD describe these exact fixes and the associated compatibility
behavior. This turn adds verification evidence and the user-correction lesson only.

All four of my review threads are now resolved. Posted the verified outcome:
https://github.com/moisesja/net-did/pull/149#pullrequestreview-5689724719
PR remains unmerged.
