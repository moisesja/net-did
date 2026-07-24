---
name: net-did-verify
description: The net-did "done" gate — 0-warning Release build, full test suite with per-project counts, W3C conformance suite green, samples run end-to-end, clean git diff. Use before marking any net-did change complete, before opening a PR, or when asked to "verify", "prove it works", or "run the tests". This is the project-specific instance of the built-in /verify skill.
---

# net-did verification gate

CLAUDE.md: "Never mark a task complete without proving it works." This is the concrete checklist that recurs in ~every task file. Run it after implementing and after any adversarial fix. Report the evidence, not just "done."

## 1. Build — zero warnings, zero errors
```
dotnet build netdid.sln -c Release --no-restore --tl:off --disable-build-servers -m:1
```
- **0 warnings AND 0 errors** is the gate. Treat warnings as failures.
- Flags matter in the sandbox: `--tl:off` (no terminal logger), `--disable-build-servers` and `-m:1` avoid MSBuild IPC / named-pipe hangs seen repeatedly in this environment. If `dotnet restore` hangs, retry without the sandbox or restore per-project.

## 2. Full test suite — report per-project counts
```
dotnet test netdid.sln -c Release --no-build
```
Record the count **per project** as a regression ledger (it only ever goes up):
- `NetDid.Core.Tests`
- `NetDid.Method.Key.Tests`
- `NetDid.Method.Peer.Tests`
- `NetDid.Method.WebVh.Tests`
- `NetDid.Extensions.DependencyInjection.Tests`
- `NetDid.Tests.W3CConformance`

For a focused loop: `dotnet test tests/<Project>/<Project>.csproj --filter "FullyQualifiedName~<TestClass>"`.

## 3. W3C conformance is the parity oracle
- `NetDid.Tests.W3CConformance` **must stay 100% green.** It is the cross-method conformance proof; a regression here means a spec break, not a flaky test.
- Running it regenerates `w3c-conformance-report.md`. Only the `Generated:` timestamp / trailing-newline churn should change. **Restore that churn** (`git checkout w3c-conformance-report.md`) unless the report content genuinely changed — otherwise you commit noise.

## 4. Samples run end-to-end
Run each affected method sample and confirm exit 0 (they double as smoke tests):
```
dotnet run --project samples/NetDid.Samples.DidKey
dotnet run --project samples/NetDid.Samples.DidPeer
dotnet run --project samples/NetDid.Samples.DidWebVh
dotnet run --project samples/NetDid.Samples.DependencyInjection
```

## 5. Diff hygiene
- `git diff --check` — no whitespace errors / conflict markers.
- Leave unrelated untracked task files and other subsystems untouched. Only the timestamp line of `w3c-conformance-report.md` should be incidental.

## Report format
State: build result (warnings/errors), total + per-project test counts, W3C suite status, samples exit codes, diff-check result. If anything fails, show the output — CLAUDE.md: report outcomes faithfully.

## Notes
- CI (`.github/workflows/ci.yml`) runs restore/build/test in Release on push+PR to `main`; this gate front-runs it so PRs land green.
- `dotnet format` may time out on named pipes in the sandbox — don't block the gate on it.
