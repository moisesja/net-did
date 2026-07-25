# PR #104 Review-Follow-up Plan

## Context

The latest review of commit `f84dd10` contains one blocking compatibility defect,
four non-blocking follow-ups, and three unresolved inline suggestions. Each was
checked against the current implementation and, where applicable, authoritative
upstream sources.

This work stays on `feat/did-ethr-resolver`, updates PR #104 in place, and does not
merge the PR.

## Assessment

1. **Equal event-block timestamps rejected — valid, blocking.**
   Aurora supplies NEAR's nanosecond block timestamp to its engine but converts it
   to whole EVM seconds. Distinct ordered blocks can therefore have the same
   externally visible timestamp. The chronological safety invariant is
   non-decreasing timestamps; only a decrease proves that timestamp selection
   cannot describe a block-number prefix.
2. **Missing `removed` rejected — valid compatibility issue.**
   The canonical Ethereum execution API Log schema does not require `removed`.
   Omission should mean the log is not explicitly marked removed; explicit `true`
   must still fail closed and non-boolean/null values must remain malformed.
3. **`invalidOptions` provenance unclear — valid documentation note.**
   The value comes from the DID Resolution specification, not DID Core 1.0.
4. **`EthereumLogEntry.LogIndex` public required-member change undocumented —
   valid documentation note.** The method is unreleased, so no release migration is
   needed, but the API change should be explicit in the changelog.
5. **Attribute ABI pointer/length decoded twice — valid cleanup.**
   The method already proves the canonical pointer, length, exact frame, and
   padding; it should slice the validated payload directly instead of reparsing it.
6. **Serializer context literals should use key/value structure — valid
   maintainability suggestion.** Consolidate exact verification-method/context
   pairs into one ordered mapping while retaining the special secp256k1/security-v2
   rule.
7. **Named chain IDs hardcoded in `EthrIdentifier` — valid concern, but an external
   configuration file is the wrong fix.** `KnownNetworks` is already the Veramo-style
   deployment catalogue and consumer-supplied `EthereumNetworkConfig` remains the
   extension point. Remove the duplicate four-network dictionary and derive known
   name-to-chain-ID conversions from `KnownNetworks`, with coverage for every
   catalogue entry.
8. **Repeated `"0x"` literals in `Erc1056EventParser` — valid local cleanup.**
   Use one parser-local constant for the semantic Ethereum hex prefix.

## Plan

- [x] Add fail-first regression coverage:
  - equal `versionTime` block timestamps resolve successfully and include every
    event at that second;
  - decreasing timestamps still return `notFound`;
  - omitted `removed` succeeds, while explicit `true`, `null`, and non-boolean
    values fail;
  - every `KnownNetworks` name maps through `EthrIdentifier.ChainId` to the
    configured decimal chain ID.
- [x] Implement the timestamp and optional-`removed` compatibility fixes.
- [x] Remove the duplicate named-chain mapping in favor of `KnownNetworks`.
- [x] Apply the three bounded cleanups: ordered context mapping, parser hex-prefix
  constant, and direct slicing of the already-validated ABI payload.
- [x] Update `README.md`, `NetDidPRD.md`, and `CHANGELOG.md` to describe
  non-decreasing timestamps, optional `removed`, DID Resolution's
  `invalidOptions`, and the required `LogIndex` member.
- [x] Add the correction pattern to `tasks/lessons.md`.
- [x] Run focused tests, then the full `net-did-verify` gate.
- [x] Run the repository's `adversarial-review` workflow over the completed diff;
  validate and fix any confirmed residual before repeating affected verification.
- [x] Complete this file's review record, commit intentionally, push the existing
  branch, and report the disposition of all eight comments. Do not merge.

## Expected Files

| Area | Expected files |
|---|---|
| Timestamp selection | `src/NetDid.Method.Ethr/DidEthrMethod.cs` |
| RPC log decoding | `src/NetDid.Method.Ethr/Rpc/DefaultEthereumRpcClient.cs` |
| Chain catalogue reuse | `src/NetDid.Method.Ethr/Crypto/EthereumIdentifier.cs` |
| Bounded cleanups | Core serializer, ERC-1056 parser, ABI decoder |
| Regression tests | Core and did:ethr test projects |
| Documentation | `README.md`, `NetDidPRD.md`, `CHANGELOG.md` |
| Process record | `tasks/lessons.md`, this file |

## Review

### Adversarial pass

- **CONFIRMED — Medium:** the first catalogue refactor regressed the deprecated but documented
  `goerli` alias from numeric chain ID `5` to the literal name because deprecated deployments are
  intentionally absent from `KnownNetworks.All`. Fixed with a catalogue-owned deprecated-alias
  lookup and `Pr104Review_DeprecatedGoerliIdentifierRetainsNumericChainId`; Goerli remains absent
  from the active configuration list.
- Serializer ordering, ABI slicing bounds, hex-prefix cleanup, custom/hex network behavior, and
  optional-`removed` type handling were independently refuted as regression paths.

The post-fix re-attack returned a clean verdict. Active names/IDs, unknown hex IDs, arbitrary
custom names, case-insensitive lookup, public `KnownNetworks.Find` semantics, and initialization
order were checked in addition to the original review surface.

### Review round — 2026-07-25

All eight comments were addressed:

1. `versionTime` now accepts equal event-block timestamps and rejects only decreases.
2. Missing optional `removed` defaults to not explicitly removed; `true`, `null`, and non-Boolean
   values remain rejected.
3. README, PRD, and changelog identify `invalidOptions` as a DID Resolution error.
4. The required public `EthereumLogEntry.LogIndex` member is explicit in the changelog.
5. Attribute ABI payloads are sliced after the existing canonical validation instead of decoding
   their offset and length twice.
6. Exact verification-method/context pairs use one ordered mapping.
7. `EthrIdentifier` uses the `KnownNetworks` catalogue, with a catalogue-owned deprecated Goerli
   alias preserving the pre-fix numeric result.
8. `Erc1056EventParser` uses one local Ethereum hex-prefix constant.

### Fail-first evidence

Before source changes, the four-test `Pr104Review` set produced exactly three expected failures:
equal timestamps returned `notFound`, omitted `removed` threw, and the catalogue test returned
`"gno"` instead of `"100"`. The decreasing-timestamp rejection control passed. The Goerli
counterexample was found by the independent adversarial pass and pinned before final verification.

### Final verification

- Release build: 0 warnings, 0 errors.
- Full solution: 1,334/1,334 tests passed:
  - Core 377
  - did:key 52
  - did:peer 48
  - did:webvh 411
  - did:ethr 195
  - dependency injection 18
  - W3C conformance 233
- W3C report timestamp-only churn restored.
- Samples passed end-to-end: did:key, did:peer, did:webvh, dependency injection, and did:ethr
  against live Sepolia.
- Independent history/RPC audit: clean.
- Independent catalogue/serializer/ABI/parser audit: one Goerli regression found, fixed, and
  clean on re-audit.
- `git diff --check`: clean.

Publishing target: existing branch `feat/did-ethr-resolver`, PR #104. No merge performed.
