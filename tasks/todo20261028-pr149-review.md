# PR #149 review

- [x] Identify PR, read description, and match local HEAD/base to GitHub.
- [x] Inspect complete diff, commits, tests, compatibility, and critical paths.
- [x] Independently challenge webvh, ethr, and peer changes with adversarial agents.
- [x] Run verification gate and inspect CI.
- [x] Confirm findings and post a specific GitHub review comment.

Review only; no source implementation, commits, pushes, or merge. Reviewed head:
e20ec80a42443c630ff37e370535dce65d9ffc4e; base:
2f6e18352ec6d03badf4319dc5d1b5ad1719998e.

## Results

Verdict: changes requested in a COMMENT review; two confirmed P2 findings.

1. The new nested-serviceEndpoint-set read rejection has no matching production guard.
   Public did:peer:4 CreateAsync succeeds with a nested set, while ResolveAsync of the
   returned DID reports notFound and a null document. Reject at production too.
2. Writer UTF-16 guards do not cover raw JsonElement contents. A byte-parsed WTF-8 string
   or nested name in Core AdditionalProperties silently emits U+FFFD; public did:peer:2
   creation reproduces the same residual of the existing defect. Add raw element checks
   and byte-parsed writer regression tests.

Reproduction programs are outside the repository in /tmp/pr149-core-probe and
/tmp/netdid-pr149-ethr-peer-probe. No implementation changes made.

Verification at e20ec80:
- Release build: 0 warnings, 0 errors.
- Default suite: 2,015 passed, 7 opt-in EVM cases skipped. Core 533, Key 52, Peer 56,
  WebVh 598, Ethr 506, DI 26, W3C 233, integration gate 11.
- Separate real-EVM suite: 18/18 passed with NETDID_ETHR_INTEGRATION=1.
- Five offline samples exit 0. Tests/samples needed unsandboxed execution for VSTest
  loopback sockets and macOS crypto loading; initial sandbox test run aborted.
- GitHub CI run 40708797658 succeeded. Diff whitespace checks clean.
- W3C report timestamp churn restored; only this review record remains untracked.
- All remote refs unchanged after agent review; main and PR head match recorded SHAs.

Posted review with two inline comments:
https://github.com/moisesja/net-did/pull/149#pullrequestreview-5684631583
The connector returned a write-permission 403; authenticated gh posted the review.
No commits, pushes, merges, or source edits performed.
