# Release 4.0.0

Requested by the user ("push version 4.0.0") after triage found no open issue blocking a release.

## Semver

**Major.** Issue #135 changes the did:webvh `did-witness.json` wire format: a witness file written by
NetDid 3.1.0 or earlier no longer validates, and its proofs must be re-collected. The release skill
treats a breaking wire-format change as major.

Public API since v3.1.0 (checked by diff): no removed members, no members added to public
interfaces, no new `abstract` or `required` members. The one signature change is `AbiDecoder`'s
tuple label `string` → `string?` (#145, already in the CHANGELOG).

## Steps

- [x] Preconditions: `main` clean at `6bb217d`, no open PRs, CI green, NuGet latest 3.1.0.
- [x] Branch `chore/release-4.0.0` (`--no-track`) from `origin/main`.
- [x] `Directory.Build.props`: `NetDidVersion` 3.2.0 → 4.0.0.
- [x] `CHANGELOG.md`: `[Unreleased]` → `[4.0.0] - 2026-10-28`, add an upgrade note (as 3.0.0 did),
      fresh empty `[Unreleased]`.
- [x] Release skill: it lists 5 packages; `NetDid.Method.Ethr` makes 6.
- [x] Verify (`net-did-verify`): 0-warning Release build, full suite, W3C conformance, samples,
      `dotnet pack` yields 6 `.nupkg` + `.snupkg`.
- [ ] Commit `chore(release): cut 4.0.0`, push, open the PR. Stop for the user's merge.
- [ ] After merge: tag `v4.0.0` on the merge commit, push the tag, watch `publish.yml`.
- [ ] Confirm all 6 packages list 4.0.0 on NuGet; comment on issues this release closes.

## Verification (branch `chore/release-4.0.0`, before the PR)

- Release build: 0 warnings, 0 errors.
- Tests: 2,319 passed, 7 skipped (opt-in real-EVM cases), 0 failed. Core 748, Key 54, Peer 114,
  WebVh 604, Ethr 529, DI 26, W3C conformance 233, Ethr integration gate 11.
- Samples: DidKey, DidPeer, DidWebVh, DidEthr, DependencyInjection all exit 0.
- `dotnet pack`: 6 `.nupkg` + 6 `.snupkg` at 4.0.0; inter-package dependencies pinned to 4.0.0.
- `w3c-conformance-report.md`: timestamp-only churn, restored. `git diff origin/main --check` clean.
