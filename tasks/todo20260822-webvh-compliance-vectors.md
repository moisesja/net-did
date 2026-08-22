# Issue #134 — Run did:webvh compliance test vectors

Reconnaissance pass: replay the DIF `didwebvh-test-suite` committed vectors through NetDid's
resolver offline and report divergences. Building the Docker harness that would register NetDid as
`implementations/dotnet/` is deliberately deferred until these findings are triaged.

Suite pinned at `f792ce4568c8c3efb3b6a055a1c2ba963dc00c35` (2026-07-30). Raw output:
[`tasks/webvh-vector-divergence.md`](webvh-vector-divergence.md), regenerable with
`dotnet run --project tools/NetDid.Tools.WebVhVectors`.

## Plan

- [x] Branch `feat/issue-134-webvh-compliance-vectors`
- [x] Clone suite to a gitignored path, pin HEAD SHA
- [x] Scaffold `tools/NetDid.Tools.WebVhVectors`, register in `netdid.sln`, `IsPackable=false`
- [x] Vector loader + `script.yaml` scanner + file-backed `IWebVhHttpClient` + structural differ
- [x] Replay happy-path (88 cases) and negative (21 cases) vectors
- [x] Triage every divergence: ours vs inter-implementation ambiguity vs already-tracked
- [x] File one issue per new finding; comment evidence on existing #35 / #123 / #131
- [x] CHANGELOG `[Unreleased]`, no version bump
- [x] Verify gate, open PR

## Results

88 happy-path replays (13 scenarios × 6 implementations, incl. historical versions), 21 negative.

| | Outcome |
|---|---|
| Happy-path logs accepted | 63 / 88 |
| Happy-path exact match | 0 / 63 |
| Negative vectors rejected | **21 / 21** |
| Negative error code matched | 1 / 21 |

### Method note

The comparison oracle is **the implementation that authored the log we resolved**, not an arbitrary
peer. Every implementation derives a different SCID for the same scenario, so diffing our output for
one implementation's log against another's expectations would have reported their disagreement with
each other as our defect. Peer results are used only to classify a genuine difference as universal
(ours) or contested (spec ambiguity). The first run got this wrong and produced ~238 phantom rows;
`JsonDiff.Compare` was rewritten around the authoring-implementation oracle.

Two further harness bugs were found and fixed before any finding was trusted:

- Resolving `portable-move` used the genesis `state.id`, but the resolver binds the requested DID to
  the **target** entry (`DidWebVhMethod.cs:267`) and a portable DID changes domain mid-log. Four
  rejections were the harness's fault, not NetDid's.
- Array paths were keyed by full `id`, so `#files` vs `did:webvh:…#files` split one service across
  two paths and hid a value difference behind a phantom presence difference. Now keyed by fragment.

The `script.yaml` scanner is hand-rolled (Central Package Management makes a YAML dependency a
solution-wide change). `Suite.SelfCheck` guards it: every negative scenario's parsed `expectError`
must equal the committed `ts/resolutionResult.json` error, or the tool throws rather than letting a
parser bug masquerade as a conformance finding.

## Findings

### Confirmed positive — hash, proof and canonicalization conformance

**Zero rejections were caused by a hash or signature mismatch.** All 25 rejections trace to the two
defects below. The 63 accepted replays each required recomputing the SCID from the genesis preimage,
recomputing every entry hash in the chain (`LogChainValidator.cs:136-145`, `:194`), and verifying
`eddsa-jcs-2022` Data Integrity proofs — against logs authored by `ts`, `rust`, `java`, `java-eecc`
and `dart`.

This is the first evidence that our wire format interoperates, and our self-generated tests
structurally could not have produced it. It settles issue **#35** and confirms the **#95** fix
in `WebVhHashEncoder.cs:18-22`.

### New issues filed

| # | Severity | Finding |
|---|---|---|
| #135 | Critical | `did-witness.json` read/written with `proofs`; spec and all 6 implementations use `proof` |
| #136 | High | Implicit `#files` / `#whois` services neither materialized nor resolvable |
| #137 | Medium | `didDocumentMetadata` omits `scid` and `versionNumber` |
| #138 | Medium | `didDocumentMetadata.updated` omitted at version 1 |
| #139 | Medium | Malformed/unsafe identifiers resolve as `notFound` instead of `invalidDid` |

**#135 is the #95 pattern repeating.** `WitnessValidator.cs:196` writes `"proofs"` and `:272` reads
`"proofs"`, so NetDid witness files round-trip against themselves and 970 green tests never noticed.
The spec is explicit — "`proof` is an array of Data Integrity proofs" — and all 14 committed witness
files across all 6 implementations use `proof`. Consequence: no witnessed did:webvh DID from any
conformant implementation resolves in NetDid, and no conformant resolver can validate a witnessed
NetDid DID. The blanket `catch { return null; }` at `:263-266` swallows the `KeyNotFoundException`,
which is *why* it stayed hidden — the failure surfaces as a bare `witnessValidationFailed`.

Aggravating: two negative vectors (`negative-cross-did-witness-replay`,
`negative-witness-update-threshold-not-met`) are recorded as correctly rejected but pass
**vacuously** — parsing fails before any witness security logic executes. Our witness replay and
threshold defences are effectively untested by this suite until #135 is fixed.

### Existing issues — evidence added, no duplicates filed

- **#35** (SCID vs DIF Universal Resolver): 63 foreign logs from 5 implementations accepted with no
  hash divergence. Recommended for closure.
- **#131** (versionTime future-skew): **the suite does not cover this.** The committed
  `negative-versiontime-future` log's tail is also non-monotonic, so our
  "strictly later than version N-1" rule (`LogChainValidator.cs:266`) rejects it before any
  future-skew bound would apply. The vector passes for the wrong reason; #131 stays open and
  unverified by this suite.
- **#123** (RFC 9457 error model): 20 of 21 negative vectors rejected with a non-matching code.

### Not a NetDid defect — upstream

All 15 `python` logs are rejected because their verification methods omit `controller`. Our
strictness is deliberate (issue **#121**) and backed by W3C DID Core §5.3.1, and 5 of 6
implementations do emit `controller` — `didwebvh-py` is the outlier. Worth reporting upstream; not
filed, as that is an outward-facing action on a third-party repository.

### Spec ambiguity — recorded, no issue

- Deactivation: we return `didDocument: null` (matching `ts`); `dart`, `java`, `java-eecc`, `python`,
  `rust` return the last document with `deactivated: true`.
- Empty relationship arrays, `watchers`/`witness` as `[]` vs `null` vs absent, absolute vs relative
  service `id`, VM `id` fragment convention (`#P5RDjVJG` vs full multibase), envelope `@context`.
  These are genuine inter-implementation disagreements and are Working Group material, which is the
  suite's stated purpose.

## Review

Scope held to reconnaissance: **no `src/` changes**, no test-count change, no version bump. The tool
is `IsPackable=false` and verified absent from `dotnet pack` output, so it cannot reach nuget.org via
`publish.yml`, which packs the whole solution.

The cloned suite is gitignored, so its own `CLAUDE.md` and `.claude/settings.json` cannot be picked
up as this repository's agent instructions. Its contents are treated as untrusted data — read as
bytes and fed to the resolver, never executed.

The report carries no generation timestamp, so re-running produces a byte-identical file (verified)
and does not create the commit churn documented for `w3c-conformance-report.md`.
