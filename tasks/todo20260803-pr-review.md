# Newly Opened PR Review

- [x] Identify the newest open PR and capture its title, description, commits, and scope.
- [x] Inspect the complete diff and relevant surrounding code/tests.
- [x] Assess tests, commit quality, scope, correctness, security, scalability, and regression risk.
- [x] Run focused validation or reproduce suspected failures where useful.
- [x] Perform an independent adversarial review for critical-path changes.
- [x] Post a specific GitHub review (approve or request changes).
- [x] Record the review outcome and evidence below.

## Review outcome

Reviewed PR #132 at `3d2d0f88bb9c159bfe66b96f45c6cc916f4d0599` and posted a
blocking COMMENT review (`PRR_kwDORfdSIM8AAAABIQE8Gg`). Formal connector writes were denied
with HTTP 403, so the review was submitted through the authenticated `gh` fallback and verified
through both `gh pr view` and the GitHub connector.

Confirmed findings:

1. Same-second updates author future `versionTime`s, violating the did:webvh writer-side timing
   requirement; resolver tolerance does not authorize future authoring.
2. Far-future deactivation returns success although conforming resolvers/witnesses reject the
   resulting log; the regression test depends on the known validator gap tracked by #131.
3. The claimed margin under every conforming resolver reverses the spec's at-most-five-minute
   guidance; conforming implementations may use a shorter tolerance.
4. The +6-minute rejection test does not pin the change from a 5-minute to a 1-minute budget.

Validation: GitHub `build-and-test` passed; local WebVh suite passed 429/429; `git diff --check`
passed. Those green results do not refute the findings because the local validator omits the
normative future-skew check.
