# PR #132 Fix Re-validation

- [x] Resolve the latest PR head and identify changes since reviewed commit `3d2d0f8`.
- [x] Re-check each prior blocking finding against code, tests, docs, and normative spec.
- [x] Run focused and full WebVh validation.
- [x] Perform independent adversarial re-review of the revised design.
- [x] Post a GitHub follow-up with the final verdict.
- [x] Record evidence and outcome below.

## Outcome

Revalidated PR #132 at `d5dddf0f9a56f65239bafb65fc61d8a50d65b5f1`; substantive
fix commit `2942278fd84e32858e8c2311400d6f81b5387486` closes all four original
findings. Posted follow-up COMMENT review `PRR_kwDORfdSIM8AAAABIQTBww`.

Remaining confirmed finding (Medium/blocking): `GetNextVersionTimeAsync` compares each
UTC-derived delay with the two-second maximum but never enforces an aggregate monotonic elapsed
budget. With frozen UTC and normally firing timers it repeats one-second delays until caller
cancellation; a temporary probe against the private helper confirmed cancellation after 2.5 s,
not enforcement of the claimed two-second bound. A backward UTC step creates the same class of
overrun. The fix should use a single monotonic deadline and add frozen/backward/cancellation tests.

Documentation also describes the wrong quantity: the code bounds distance to the next authorable
whole second, not the head's lead over the clock. Example: clock T/head T+2 s is rejected because
the next valid timestamp is T+3 s, although the head is not ahead by more than two seconds.

Validation: focused issue tests 9/9; full WebVh suite 430/430 in 51 s; GitHub build-and-test green;
`git diff --check` clean. Full-suite duration regression was noted as non-blocking cleanup.

## Implemented resolution

At the user's direction, the remaining blocker was fixed on the existing PR branch. One injected
monotonic deadline now bounds the complete authoring wait, including repeated timers, stalled or
backward UTC, and timer oversleep. Regression tests cover frozen/backward UTC and oversleep for
both Update and Deactivate plus caller cancellation. Documentation now describes reachability
within the remaining aggregate budget. The high-frequency test fixture uses virtual time, reducing
the full WebVh suite from ~51 seconds to ~6 seconds. See
`tasks/todo20260803-pr132-round2-fix.md` for fail-first, adversarial, and verification evidence.
