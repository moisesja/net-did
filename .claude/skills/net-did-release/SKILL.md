---
name: net-did-release
description: Cut a net-did release and publish all 5 NuGet packages — semver decision, chore/release branch, NetDidVersion bump, CHANGELOG stamp, verify, tag vX.Y.Z (triggers publish.yml), confirm on NuGet. Use when asked to release, cut a version, bump the version, publish to NuGet, or ship vX.Y.Z.
---

# net-did release / publish lifecycle

Mechanical and high-cost-of-error — follow exactly. Version bumps live ONLY here, never in feature work (memory: `feedback_version-bumps`).

## 1. Preconditions
- On `main`, clean tree, all feature PRs for this release already merged.
- `git fetch --tags`; note the latest `vX.Y.Z` tag and current `<NetDidVersion>` in `Directory.Build.props`.
- Confirm `CHANGELOG.md` `[Unreleased]` holds the entries to ship.

## 2. Semver decision
- **Major** — any breaking public-API change OR breaking wire-format/spec change (e.g. did:webvh #93/#95 changed every identifier ⇒ these were breaking; historically shipped as minors only because did:webvh had no production deployment — document that explicitly if you do the same).
- **Minor** — additive, backward-compatible (e.g. #91 added two `DidUpdateResult` members ⇒ 2.1.0 → 2.2.0).
- **Patch** — backward-compatible bug fix only.
- State the chosen bump and the reason.

## 3. Release branch
```
git switch -c chore/release-X.Y.Z
```
Mirror a prior release commit's shape (e.g. the 2.1.0/2.2.0 release commits) for consistency.

## 4. Version + changelog
- `Directory.Build.props`: `<NetDidVersion>` → `X.Y.Z`. (Bump a dependency version like NetCrypto only if this release actually upgrades it.)
- `CHANGELOG.md`: rename `## [Unreleased]` → `## [X.Y.Z] - YYYY-MM-DD` and add a fresh empty `## [Unreleased]` above it.
- Do not hand-edit `w3c-conformance-report.md` — it regenerates during verification.

## 5. Verify
Run the **`net-did-verify`** skill: 0-warning Release build, full test suite green, W3C conformance green, samples exit 0. This regenerates `w3c-conformance-report.md` legitimately for the release — keep any real content change, drop pure timestamp churn.
Optionally inspect the packages: `dotnet pack netdid.sln -c Release -o ./nupkgs` and confirm 5 `.nupkg` + `.snupkg` files.

## 6. Release PR
- Commit `chore(release): cut X.Y.Z`, push, open the PR.
- **Stop at the open PR.** The user reviews and merges (memory: `feedback_pr-merge-review`) — do not merge autonomously, even under standing autonomy.

## 7. Tag → publish (after the user merges)
```
git switch main && git pull
git tag vX.Y.Z <merge-commit>
git push origin vX.Y.Z
```
- The tag push triggers `.github/workflows/publish.yml`, which builds/tests/packs and `dotnet nuget push`es all packages with `-p:Version=X.Y.Z --skip-duplicate`.
- **Packages shipped (5):** `NetDid.Core`, `NetDid.Method.Key`, `NetDid.Method.Peer`, `NetDid.Method.WebVh`, `NetDid.Extensions.DependencyInjection`.
- Watch the workflow to completion (`gh run watch`).

## 8. Confirm
- Verify each package is queryable at the expected version on the NuGet API
  (`https://api.nuget.org/v3-flatcontainer/netdid.core/index.json` should list `X.Y.Z`).
- Comment on any issues the release closes with the shipped version.
- Append a `## Review` section to the plan file with the tag, workflow run URL, and confirmed package versions.

## Guardrails
- Tag only a merged commit on `main`; never tag a feature branch.
- Publishing is irreversible (a version can't be re-pushed with different content — hence `--skip-duplicate`). Double-check the version before pushing the tag.
