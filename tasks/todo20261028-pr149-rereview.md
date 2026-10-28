# PR #149 re-review

Reviewed head: 0e8d8681c4d8f0d6aa15821fb1cc91445f7ec1a5.
Prior review: e20ec80a42443c630ff37e370535dce65d9ffc4e.

- [x] Match GitHub head and local checkout; read new commits and review replies.
- [x] Verify both prior findings and review all expanded production changes.
- [x] Independently challenge Core parser/dereferencing, ethr, peer/webvh changes.
- [x] Run full verification and targeted probes.
- [x] Post evidence-backed follow-up review.

Review only; no source changes, commits, pushes, or merge.

## Results

Both prior findings are closed, verified by rerunning public API probes. Two P2 concerns
remain in the expanded changes:

1. New identifier validation rejects conforming relative DID URLs with path/query components
   (DID Core section 3.2.2): read throws JsonException; write throws ArgumentException.
2. New peer:2 producer validation checks a second view of the caller's service list. A split
   enumerator/indexer list encodes an invalid endpoint but supplies a valid endpoint to the
   returned document and validator. Create succeeds; resolving its DID returns invalidDid.

Probes: /tmp/pr149-r2-parser and /tmp/pr149-r2-peer-probe. Original Core probe:
/tmp/pr149-core-probe. No additional actionable ethr/webvh issue found independently.

Validation at 0e8d868:
- Release build: 0 warnings/errors.
- Default suite: 2,261 passed, 7 opt-in EVM cases skipped. Core 706, Key 54, Peer 98,
  WebVh 604, Ethr 529, DI 26, W3C 233, integration gate 11.
- Separate real-EVM suite: 18/18. Five offline samples: exit 0.
- GitHub CI run 40754984649 succeeded.
- PR diff whitespace check found two added blank lines at EOF (Core Issue145 tests and
  DidKeyMethodTests); reported as minor hygiene, not a blocker.
- W3C report timestamp restored; remote refs unchanged after independent review.

Posted COMMENT review with two inline change requests, verified via connector:
https://github.com/moisesja/net-did/pull/149#pullrequestreview-5688590368
Used authenticated gh because the connector's review-write permission was unavailable.
