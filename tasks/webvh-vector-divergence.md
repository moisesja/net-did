# did:webvh compliance vector divergence report

- Suite: `decentralized-identity/didwebvh-test-suite` @ `f792ce4568c8c3efb3b6a055a1c2ba963dc00c35`
- Scenarios: 30 (13 happy-path, 17 negative)
- Harness: `tools/NetDid.Tools.WebVhVectors` — replays the suite's committed artifacts through `DidWebVhMethod` offline via a file-backed `IWebVhHttpClient`.

Resolution recomputes the SCID and every entry hash (`LogChainValidator.cs:136-145`, `:194`), so a successful resolve of a foreign log is direct evidence that our hash encoding interoperates with that implementation — something our self-generated tests cannot establish.

## Summary

| Check | Cases | Result |
|---|---:|---|
| Happy-path logs accepted | 88 | 73 accepted, 15 rejected |
| Happy-path exact match | 73 | 0 match, 73 diverge |
| Negative vectors rejected | 21 | 21 rejected, 0 **accepted** |
| Negative error code matches | 21 | 1 match, 20 differ |

## A. Hash / wire-format conformance

Whether our recomputation of each foreign log's SCID and entry-hash chain agrees with the implementation that authored it. A rejection here means our hash encoding does not interoperate.

| Implementation | Logs replayed | Accepted | Rejected |
|---|---:|---:|---:|
| `ts` | 15 | 15 | 0 |
| `python` | 15 | 0 | 15 |
| `rust` | 15 | 15 | 0 |
| `java` | 14 | 14 | 0 |
| `java-eecc` | 15 | 15 | 0 |
| `dart` | 14 | 14 | 0 |

Rejected logs:

| Scenario | Impl | Error | Resolver diagnostic |
|---|---|---|---|
| `basic-create` | `python` | `invalidDidLog` | `DID log contains invalid did:webvh data for did:webvh:QmXhVjFG6EBTosDastaaHMRypm2qSv4SMGctADsx878Yux:example.com :: FormatException: did:webvh log entry contains malformed content. :: JsonException: Verification method '…` |
| `basic-update` | `python` | `invalidDidLog` | `DID log contains invalid did:webvh data for did:webvh:QmXhVjFG6EBTosDastaaHMRypm2qSv4SMGctADsx878Yux:example.com :: FormatException: did:webvh log entry contains malformed content. :: JsonException: Verification method '…` |
| `deactivate` | `python` | `invalidDidLog` | `DID log contains invalid did:webvh data for did:webvh:QmXhVjFG6EBTosDastaaHMRypm2qSv4SMGctADsx878Yux:example.com :: FormatException: did:webvh log entry contains malformed content. :: JsonException: Verification method '…` |
| `key-rotation` | `python` | `invalidDidLog` | `DID log contains invalid did:webvh data for did:webvh:QmXhVjFG6EBTosDastaaHMRypm2qSv4SMGctADsx878Yux:example.com :: FormatException: did:webvh log entry contains malformed content. :: JsonException: Verification method '…` |
| `multi-update` | `python` | `invalidDidLog` | `DID log contains invalid did:webvh data for did:webvh:QmXhVjFG6EBTosDastaaHMRypm2qSv4SMGctADsx878Yux:example.com :: FormatException: did:webvh log entry contains malformed content. :: JsonException: Verification method '…` |
| `multi-update` | `python` | `invalidDidLog` | `DID log contains invalid did:webvh data for did:webvh:QmXhVjFG6EBTosDastaaHMRypm2qSv4SMGctADsx878Yux:example.com :: FormatException: did:webvh log entry contains malformed content. :: JsonException: Verification method '…` |
| `multi-update` | `python` | `invalidDidLog` | `DID log contains invalid did:webvh data for did:webvh:QmXhVjFG6EBTosDastaaHMRypm2qSv4SMGctADsx878Yux:example.com :: FormatException: did:webvh log entry contains malformed content. :: JsonException: Verification method '…` |
| `multiple-update-keys` | `python` | `invalidDidLog` | `DID log contains invalid did:webvh data for did:webvh:QmaSetYkGWKD3FF9VBazD9FRfg7RBbiQKum21NcryzTkM1:example.com :: FormatException: did:webvh log entry contains malformed content. :: JsonException: Verification method '…` |
| `portable` | `python` | `invalidDidLog` | `DID log contains invalid did:webvh data for did:webvh:QmZEmV4tPDCfzr5xb62SpKZWoJinQG81ZBaZXBQuEosD1C:example.com :: FormatException: did:webvh log entry contains malformed content. :: JsonException: Verification method '…` |
| `portable-move` | `python` | `invalidDidLog` | `DID log contains invalid did:webvh data for did:webvh:QmZEmV4tPDCfzr5xb62SpKZWoJinQG81ZBaZXBQuEosD1C:example.com :: FormatException: did:webvh log entry contains malformed content. :: JsonException: Verification method '…` |
| `pre-rotation` | `python` | `invalidDidLog` | `DID log contains invalid did:webvh data for did:webvh:QmcKnGa3dur9W5JbQ3CC7D95Aqy5g4tbp81U3QG8DG1wtv:example.com :: FormatException: did:webvh log entry contains malformed content. :: JsonException: Verification method '…` |
| `pre-rotation-consume` | `python` | `invalidDidLog` | `DID log contains invalid did:webvh data for did:webvh:QmcKnGa3dur9W5JbQ3CC7D95Aqy5g4tbp81U3QG8DG1wtv:example.com :: FormatException: did:webvh log entry contains malformed content. :: JsonException: Verification method '…` |
| `services` | `python` | `invalidDidLog` | `DID log contains invalid did:webvh data for did:webvh:QmZMMkNS4sL91SHsuCfDi2imHr1tfDtDN8j4xBncmjjNjC:example.com :: FormatException: did:webvh log entry contains malformed content. :: JsonException: Verification method '…` |
| `witness-threshold` | `python` | `invalidDidLog` | `DID log contains invalid did:webvh data for did:webvh:QmQvFgRe9yNYAT253FoGixHgRsZDCxeWQoU12varD5CDdJ:example.com :: FormatException: did:webvh log entry contains malformed content. :: JsonException: Verification method '…` |
| `witness-update` | `python` | `invalidDidLog` | `DID log contains invalid did:webvh data for did:webvh:QmVPXTZAumzuRFXb7Squ63ah8h7Tdi9SuP58wQ65Y5Baje:example.com :: FormatException: did:webvh log entry contains malformed content. :: JsonException: Verification method '…` |

## B. Resolution divergences, grouped by root cause

Each row is one root cause. `Cases` counts the (scenario × implementation) replays it affects.

| Path | Kind | Cases | Ours | Reference implementations |
|---|---|---:|---|---|
| `didDocument.service[].id` | impls disagree | 114 | `"#files"` | `"did:webvh:{SCID}:example.com#files"` — dart, java, python, rust, ts<br>`"#files"` — java-eecc |
| `didDocumentMetadata.scid` | missing from ours | 73 | *(absent)* | `"{SCID}"` — dart, java, java-eecc, python, rust, ts |
| `didDocumentMetadata.versionNumber` | impls disagree | 58 | *(absent)* | `1` — dart, java, java-eecc, python, rust<br>`(absent)` — ts |
| `didDocumentMetadata.portable` | impls disagree | 38 | *(absent)* | `false` — java, python, rust, ts<br>`(absent)` — dart, java-eecc |
| `didDocument.assertionMethod` | impls disagree | 32 | *(absent)* | `[]` — java-eecc, python, rust<br>`["did:webvh:{SCID}:example.com#z6MkjchhfUsD6mmvni8mCdXHw216X…` — dart, java<br>`(absent)` — ts |
| `didDocument.@context` | impls disagree | 30 | `["https://w3id.org/security/multikey/v1","https://www.w3.org…` | `["https://w3id.org/security/multikey/v1","https://www.w3.org…` — java-eecc, python, rust, ts<br>`"https://www.w3.org/ns/did/v1"` — dart, java |
| `didDocument.capabilityDelegation` | impls disagree | 30 | *(absent)* | `(absent)` — dart, java, ts<br>`[]` — java-eecc, python, rust |
| `didDocument.capabilityInvocation` | impls disagree | 30 | *(absent)* | `(absent)` — dart, java, ts<br>`[]` — java-eecc, python, rust |
| `didDocument.keyAgreement` | impls disagree | 30 | *(absent)* | `(absent)` — dart, java, ts<br>`[]` — java-eecc, python, rust |
| `didDocumentMetadata.watchers` | impls disagree | 30 | *(absent)* | `(absent)` — dart, java, java-eecc<br>`[]` — python, ts<br>`null` — rust |
| `didDocumentMetadata.deactivated` | impls disagree | 28 | *(absent)* | `false` — python, rust, ts<br>`(absent)` — dart, java, java-eecc |
| `didDocumentMetadata.witness` | impls disagree | 26 | *(absent)* | `(absent)` — dart, java, java-eecc<br>`{}` — python, ts<br>`null` — rust |
| `didDocumentMetadata.updated` | missing from ours | 25 | *(absent)* | `"2000-01-01T00:00:00Z"` — python, rust, ts<br>`"2026-07-29T18:17:37Z"` — java<br>`"2026-07-29T18:21:36Z"` — java-eecc |
| `didDocument.service[].serviceEndpoint` | impls disagree | 20 | `"https://example.com/"` | `"https://example.com/"` — dart, java, java-eecc, python, ts<br>`"https://example.com"` — rust |
| `didDocumentMetadata.nextKeyHashes` | impls disagree | 15 | *(absent)* | `(absent)` — dart, java, java-eecc, python, rust<br>`[]` — ts |
| `didDocumentMetadata.prerotation` | impls disagree | 15 | *(absent)* | `(absent)` — dart, java, java-eecc, python, rust<br>`false` — ts |
| `didDocumentMetadata.previousLogEntryHash` | impls disagree | 15 | *(absent)* | `(absent)` — dart, java, java-eecc, python, rust<br>`"{SCID}"` — ts |
| `didDocumentMetadata.updateKeys` | impls disagree | 15 | *(absent)* | `(absent)` — dart, java, java-eecc, python, rust<br>`["z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG"]` — ts |
| `didDocumentMetadata.versionTime` | impls disagree | 15 | `"2000-01-01T00:00:00Z"` | `"2000-01-01T00:00:00Z"` — python, rust<br>`(absent)` — ts<br>`"2026-07-29T18:17:37Z"` — java |
| `didDocumentMetadata.portable` | missing from ours | 10 | *(absent)* | `true` — dart, java, java-eecc, python, rust, ts |
| `didDocument.service[].type` | impls disagree | 6 | *(absent)* | `"relativeRef"` — dart, java-eecc, python, rust<br>`(absent)` — java, ts |
| `didDocumentMetadata.witness.witnesses[].id` | impls disagree | 5 | *(absent)* | `"did:key:z6Mkrv5Cm2XCLumMPTqooLTCw6YDf421d7VdTziwrZ8vNf4L"` — python, rust, ts<br>`(absent)` — dart, java, java-eecc |
| `didDocument` | impls disagree | 4 | `null` | `(absent)` — dart, java, java-eecc, python, rust<br>`null` — ts |
| `didDocument.authentication` | impls disagree | 4 | *(absent)* | `["did:webvh:{SCID}:example.com#P5RDjVJG"]` — java-eecc, python, rust<br>`["did:webvh:{SCID}:example.com#z6MkjchhfUsD6mmvni8mCdXHw216X…` — dart, java<br>`(absent)` — ts |
| `didDocument.controller` | impls disagree | 4 | *(absent)* | `"did:webvh:{SCID}:example.com"` — dart, java, java-eecc, python, rust<br>`(absent)` — ts |
| `didDocument.id` | impls disagree | 4 | *(absent)* | `"did:webvh:{SCID}:example.com"` — dart, java, java-eecc, python, rust<br>`(absent)` — ts |
| `didDocument.verificationMethod[].controller` | impls disagree | 4 | *(absent)* | `(absent)` — dart, java, python, ts<br>`"did:webvh:{SCID}:example.com"` — java-eecc, rust |
| `didDocument.verificationMethod[].id` | impls disagree | 4 | *(absent)* | `(absent)` — dart, java, ts<br>`"did:webvh:{SCID}:example.com#P5RDjVJG"` — java-eecc, python, rust |
| `didDocument.verificationMethod[].publicKeyMultibase` | impls disagree | 4 | *(absent)* | `(absent)` — dart, java, ts<br>`"z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG"` — java-eecc, python, rust |
| `didDocument.verificationMethod[].type` | impls disagree | 4 | *(absent)* | `(absent)` — dart, java, ts<br>`"Multikey"` — java-eecc, python, rust |
| `didDocumentMetadata.witness.threshold` | impls disagree | 4 | *(absent)* | `1` — python, rust, ts<br>`(absent)` — dart, java, java-eecc |
| `didDocument.service[].@context` | impls disagree | 3 | *(absent)* | `"https://identity.foundation/linked-vp/contexts/v1"` — dart, java-eecc, python, rust<br>`(absent)` — java, ts |
| `didDocumentMetadata.updated` | impls disagree | 1 | `"2000-01-02T00:00:00Z"` | `"2000-01-03T00:00:00Z"` — python, rust<br>`"2000-01-02T00:00:00Z"` — ts<br>`"2026-07-29T18:17:38Z"` — java |

## C. Negative vectors

Two independent axes. **Rejected** is the security-relevant question — did we refuse the malicious input at all. **Code** is the conformance question — did we refuse it with the error the suite specifies. Our resolver's vocabulary is `invalidDid` / `methodNotSupported` / `notFound` / `invalidDidLog` / `witnessValidationFailed`; the suite specifies `invalidDid` / `invalidProof` / `invalidParameters`.

| Scenario | Input | Expected | Actual | Rejected | Code |
|---|---|---|---|---|---|
| `negative-cross-did-witness-replay` | committed log | `invalidDid` | `witnessValidationFailed` | yes | differ |
| `negative-did-key-body-fragment-mismatch` | committed log | `invalidProof` | `invalidDidLog` | yes | differ |
| `negative-duplicate-witness-ids` | committed log | `invalidParameters` | `invalidDidLog` | yes | differ |
| `negative-fragment-leaks-into-domain` | `did:webvh:Qm0000000000000000000000000000000000000000…` | `invalidDid` | `invalidDid` | yes | match |
| `negative-lowercase-pct-port-ip` | `did:webvh:Qm0000000000000000000000000000000000000000…` | `invalidDid` | `notFound` | yes | differ |
| `negative-path-traversal-did` | `did:webvh:Qm0000000000000000000000000000000000000000…` | `invalidDid` | `notFound` | yes | differ |
| `negative-pct-encoded-ip-host` | `did:webvh:Qm0000000000000000000000000000000000000000…` | `invalidDid` | `notFound` | yes | differ |
| `negative-pct-encoded-ip-host` | `did:webvh:Qm0000000000000000000000000000000000000000…` | `invalidDid` | `notFound` | yes | differ |
| `negative-pct-encoded-ip-host` | `did:webvh:Qm0000000000000000000000000000000000000000…` | `invalidDid` | `notFound` | yes | differ |
| `negative-pct-encoded-traversal` | `did:webvh:Qm0000000000000000000000000000000000000000…` | `invalidDid` | `notFound` | yes | differ |
| `negative-pct-encoded-traversal` | `did:webvh:Qm0000000000000000000000000000000000000000…` | `invalidDid` | `notFound` | yes | differ |
| `negative-pct-encoded-traversal` | `did:webvh:Qm0000000000000000000000000000000000000000…` | `invalidDid` | `notFound` | yes | differ |
| `negative-portable-scid-swap` | committed log | `invalidDid` | `invalidDidLog` | yes | differ |
| `negative-pre-rotation-omit-updatekeys` | committed log | `invalidParameters` | `invalidDidLog` | yes | differ |
| `negative-scid-mismatch-genesis` | committed log | `invalidDid` | `invalidDidLog` | yes | differ |
| `negative-unknown-method-version` | committed log | `invalidDid` | `invalidDidLog` | yes | differ |
| `negative-versiontime-future` | committed log | `invalidDid` | `invalidDidLog` | yes | differ |
| `negative-versiontime-non-monotonic` | committed log | `invalidDid` | `invalidDidLog` | yes | differ |
| `negative-witness-update-threshold-not-met` | committed log | `invalidDid` | `witnessValidationFailed` | yes | differ |
| `negative-wrong-cryptosuite` | committed log | `invalidProof` | `invalidDidLog` | yes | differ |
| `negative-zero-witness-threshold` | committed log | `invalidParameters` | `invalidDidLog` | yes | differ |

### Rejected, but with a different error code (20)

| Scenario | Expected | Ours | Resolver diagnostic |
|---|---|---|---|
| `negative-cross-did-witness-replay` | `invalidDid` | `witnessValidationFailed` | `Resolving did:webvh:QmU9s4GUNrt8SM9CCCTejsbZj583dXQWUduG1QnWaHbrzS:example.com from https://example.com/.well-known/did.jsonl` |
| `negative-did-key-body-fragment-mismatch` | `invalidProof` | `invalidDidLog` | `DID log contains invalid did:webvh data for did:webvh:Qmdxt11AjZewCNXX69bpEDobgjySeZ7eFwjf4tgpF6p2Dg:example.com :: FormatException: did:webvh log entry contains malformed content. :: JsonException: Verification method '…` |
| `negative-duplicate-witness-ids` | `invalidParameters` | `invalidDidLog` | `DID log contains invalid did:webvh data for did:webvh:QmRYjUsnhRqEyLAdZhWGf48Qzfwc1o3nrTkJeGXGMhrEXf:example.com :: FormatException: did:webvh log entry contains malformed content. :: JsonException: Verification method '…` |
| `negative-lowercase-pct-port-ip` | `invalidDid` | `notFound` | `Resolution failed for did:webvh:Qm0000000000000000000000000000000000000000000000:127.0.0.1%3a8080 :: ArgumentException: Invalid did:webvh domain — non-public host '127.0.0.1': did:webvh:Qm00000000000000000000000000000000…` |
| `negative-path-traversal-did` | `invalidDid` | `notFound` | `Resolution failed for did:webvh:Qm0000000000000000000000000000000000000000000000:example.com:..:..:admin :: ArgumentException: Invalid did:webvh — traversal path segment '..': did:webvh:Qm00000000000000000000000000000000…` |
| `negative-pct-encoded-ip-host` | `invalidDid` | `notFound` | `Resolution failed for did:webvh:Qm0000000000000000000000000000000000000000000000:127%2E0%2E0%2E1 :: ArgumentException: Invalid did:webvh domain — non-public host '127.0.0.1': did:webvh:Qm000000000000000000000000000000000…` |
| `negative-pct-encoded-ip-host` | `invalidDid` | `notFound` | `Resolution failed for did:webvh:Qm0000000000000000000000000000000000000000000000:127%2e0%2e0%2e1 :: ArgumentException: Invalid did:webvh domain — non-public host '127.0.0.1': did:webvh:Qm000000000000000000000000000000000…` |
| `negative-pct-encoded-ip-host` | `invalidDid` | `notFound` | `Resolution failed for did:webvh:Qm0000000000000000000000000000000000000000000000:169%2E254%2E169%2E254 :: ArgumentException: Invalid did:webvh domain — non-public host '169.254.169.254': did:webvh:Qm000000000000000000000…` |
| `negative-pct-encoded-traversal` | `invalidDid` | `notFound` | `Resolution failed for did:webvh:Qm0000000000000000000000000000000000000000000000:example.com:%2E%2E:admin :: ArgumentException: Invalid did:webvh — traversal path segment '..': did:webvh:Qm0000000000000000000000000000000…` |
| `negative-pct-encoded-traversal` | `invalidDid` | `notFound` | `Resolution failed for did:webvh:Qm0000000000000000000000000000000000000000000000:example.com:%2e%2e:admin :: ArgumentException: Invalid did:webvh — traversal path segment '..': did:webvh:Qm0000000000000000000000000000000…` |
| `negative-pct-encoded-traversal` | `invalidDid` | `notFound` | `Resolution failed for did:webvh:Qm0000000000000000000000000000000000000000000000:example.com:a%2Fb :: ArgumentException: Invalid did:webvh — unsafe path segment character '/': did:webvh:Qm00000000000000000000000000000000…` |
| `negative-portable-scid-swap` | `invalidDid` | `invalidDidLog` | `Chain validation failed for did:webvh:QmAttackerChosenAfterPortabilityMove:newdomain.example.com :: LogChainValidationException: Entry 2 state.id SCID does not match the log's SCID.` |
| `negative-pre-rotation-omit-updatekeys` | `invalidParameters` | `invalidDidLog` | `Chain validation failed for did:webvh:QmXpqXh9uM1rN2uBuHQB4qdGUMfJsEouwz8Yn8RaaTXgKq:example.com :: LogChainValidationException: Pre-rotation is active but version 2 does not explicitly define at least one updateKey.` |
| `negative-scid-mismatch-genesis` | `invalidDid` | `invalidDidLog` | `Chain validation failed for did:webvh:QmAttackerControlledScidThatDoesNotHashToAnything:example.com :: LogChainValidationException: Genesis SCID does not match computed hash (SCID verification failed).` |
| `negative-unknown-method-version` | `invalidDid` | `invalidDidLog` | `Chain validation failed for did:webvh:QmV2V5CSzH5w9UF4rHHAdktXL93ounugmgV2LXVCx9s2i9:example.com :: LogChainValidationException: Unsupported did:webvh method version 'did:webvh:99.0'.` |
| `negative-versiontime-future` | `invalidDid` | `invalidDidLog` | `Chain validation failed for did:webvh:QmV2V5CSzH5w9UF4rHHAdktXL93ounugmgV2LXVCx9s2i9:example.com :: LogChainValidationException: versionTime at version 3 must be strictly later than version 2.` |
| `negative-versiontime-non-monotonic` | `invalidDid` | `invalidDidLog` | `Chain validation failed for did:webvh:QmXW57zansv15fXV2p48bUiXABPFUzXabrAoYphUGwjqiq:example.com :: LogChainValidationException: versionTime at version 2 must be strictly later than version 1.` |
| `negative-witness-update-threshold-not-met` | `invalidDid` | `witnessValidationFailed` | `Resolving did:webvh:QmbKWDWzoZZpiDQbDCD1tAVxWhsadoAdgKQuSfuM8pKQqv:example.com from https://example.com/.well-known/did.jsonl` |
| `negative-wrong-cryptosuite` | `invalidProof` | `invalidDidLog` | `Chain validation failed for did:webvh:QmV2V5CSzH5w9UF4rHHAdktXL93ounugmgV2LXVCx9s2i9:example.com :: LogChainValidationException: Proof validation failed at version 1: The proof type or cryptosuite is not supported.` |
| `negative-zero-witness-threshold` | `invalidParameters` | `invalidDidLog` | `DID log contains invalid did:webvh data for did:webvh:QmZSzYU6pmRAZUKRPoF9nHUvTtzLwTmFVyfSqecZ9ZACbv:example.com :: FormatException: did:webvh log entry contains malformed content. :: JsonException: Verification method '…` |

## D. Full happy-path matrix

`MATCH` — identical after normalising each implementation's SCID. `DIFF` — resolved, output differs. `REJECTED` — we refused a valid log.

| Scenario | Target | `ts` | `python` | `rust` | `java` | `java-eecc` | `dart` |
|---|---|---|---|---|---|---|---|
| `basic-create` | `resolutionResult.json` | DIFF (13) | **REJECTED**<br>`invalidDidLog` | DIFF (14) | DIFF (7) | DIFF (7) | DIFF (6) |
| `basic-update` | `resolutionResult.json` | DIFF (12) | **REJECTED**<br>`invalidDidLog` | DIFF (13) | DIFF (6) | DIFF (6) | DIFF (5) |
| `deactivate` | `resolutionResult.json` | DIFF (9) | **REJECTED**<br>`invalidDidLog` | DIFF (25) | DIFF (13) | DIFF (22) | DIFF (19) |
| `key-rotation` | `resolutionResult.json` | DIFF (12) | **REJECTED**<br>`invalidDidLog` | DIFF (13) | DIFF (6) | DIFF (6) | DIFF (5) |
| `multi-update` | `resolutionResult.1.json` | DIFF (13) | **REJECTED**<br>`invalidDidLog` | DIFF (14) | DIFF (7) | DIFF (7) | DIFF (6) |
| `multi-update` | `resolutionResult.2.json` | DIFF (12) | **REJECTED**<br>`invalidDidLog` | DIFF (14) | DIFF (6) | DIFF (6) | DIFF (5) |
| `multi-update` | `resolutionResult.json` | DIFF (12) | **REJECTED**<br>`invalidDidLog` | DIFF (13) | DIFF (6) | DIFF (6) | DIFF (5) |
| `multiple-update-keys` | `resolutionResult.json` | DIFF (12) | **REJECTED**<br>`invalidDidLog` | DIFF (13) | — | DIFF (6) | — |
| `portable` | `resolutionResult.json` | DIFF (13) | **REJECTED**<br>`invalidDidLog` | DIFF (14) | DIFF (7) | DIFF (8) | DIFF (7) |
| `portable-move` | `resolutionResult.json` | DIFF (12) | **REJECTED**<br>`invalidDidLog` | DIFF (13) | DIFF (6) | DIFF (7) | DIFF (6) |
| `pre-rotation` | `resolutionResult.json` | DIFF (13) | **REJECTED**<br>`invalidDidLog` | DIFF (14) | DIFF (7) | DIFF (7) | DIFF (6) |
| `pre-rotation-consume` | `resolutionResult.json` | DIFF (12) | **REJECTED**<br>`invalidDidLog` | DIFF (13) | DIFF (6) | DIFF (6) | DIFF (5) |
| `services` | `resolutionResult.json` | DIFF (12) | **REJECTED**<br>`invalidDidLog` | DIFF (13) | DIFF (6) | DIFF (6) | DIFF (5) |
| `witness-threshold` | `resolutionResult.json` | DIFF (14) | **REJECTED**<br>`invalidDidLog` | DIFF (15) | DIFF (7) | DIFF (7) | DIFF (6) |
| `witness-update` | `resolutionResult.json` | DIFF (13) | **REJECTED**<br>`invalidDidLog` | DIFF (15) | DIFF (6) | DIFF (6) | DIFF (5) |

## E. Full diagnostics for rejected logs

**7 rejection(s)** — `basic-create`/`python`, `basic-update`/`python`, `deactivate`/`python`, `key-rotation`/`python`, `multi-update`/`python`

```
DID log contains invalid did:webvh data for did:webvh:QmXhVjFG6EBTosDastaaHMRypm2qSv4SMGctADsx878Yux:example.com :: FormatException: did:webvh log entry contains malformed content. :: JsonException: Verification method 'did:webvh:QmXhVjFG6EBTosDastaaHMRypm2qSv4SMGctADsx878Yux:example.com#P5RDjVJG' is missing the required 'controller' property (W3C DID Core §5.2). A verification method's controller MUST be stated explicitly; it does not default to the DID subject.
```

**2 rejection(s)** — `portable`/`python`, `portable-move`/`python`

```
DID log contains invalid did:webvh data for did:webvh:QmZEmV4tPDCfzr5xb62SpKZWoJinQG81ZBaZXBQuEosD1C:example.com :: FormatException: did:webvh log entry contains malformed content. :: JsonException: Verification method 'did:webvh:QmZEmV4tPDCfzr5xb62SpKZWoJinQG81ZBaZXBQuEosD1C:example.com#P5RDjVJG' is missing the required 'controller' property (W3C DID Core §5.2). A verification method's controller MUST be stated explicitly; it does not default to the DID subject.
```

**2 rejection(s)** — `pre-rotation`/`python`, `pre-rotation-consume`/`python`

```
DID log contains invalid did:webvh data for did:webvh:QmcKnGa3dur9W5JbQ3CC7D95Aqy5g4tbp81U3QG8DG1wtv:example.com :: FormatException: did:webvh log entry contains malformed content. :: JsonException: Verification method 'did:webvh:QmcKnGa3dur9W5JbQ3CC7D95Aqy5g4tbp81U3QG8DG1wtv:example.com#P5RDjVJG' is missing the required 'controller' property (W3C DID Core §5.2). A verification method's controller MUST be stated explicitly; it does not default to the DID subject.
```

**1 rejection(s)** — `multiple-update-keys`/`python`

```
DID log contains invalid did:webvh data for did:webvh:QmaSetYkGWKD3FF9VBazD9FRfg7RBbiQKum21NcryzTkM1:example.com :: FormatException: did:webvh log entry contains malformed content. :: JsonException: Verification method 'did:webvh:QmaSetYkGWKD3FF9VBazD9FRfg7RBbiQKum21NcryzTkM1:example.com#P5RDjVJG' is missing the required 'controller' property (W3C DID Core §5.2). A verification method's controller MUST be stated explicitly; it does not default to the DID subject.
```

**1 rejection(s)** — `services`/`python`

```
DID log contains invalid did:webvh data for did:webvh:QmZMMkNS4sL91SHsuCfDi2imHr1tfDtDN8j4xBncmjjNjC:example.com :: FormatException: did:webvh log entry contains malformed content. :: JsonException: Verification method 'did:webvh:QmZMMkNS4sL91SHsuCfDi2imHr1tfDtDN8j4xBncmjjNjC:example.com#P5RDjVJG' is missing the required 'controller' property (W3C DID Core §5.2). A verification method's controller MUST be stated explicitly; it does not default to the DID subject.
```

**1 rejection(s)** — `witness-threshold`/`python`

```
DID log contains invalid did:webvh data for did:webvh:QmQvFgRe9yNYAT253FoGixHgRsZDCxeWQoU12varD5CDdJ:example.com :: FormatException: did:webvh log entry contains malformed content. :: JsonException: Verification method 'did:webvh:QmQvFgRe9yNYAT253FoGixHgRsZDCxeWQoU12varD5CDdJ:example.com#P5RDjVJG' is missing the required 'controller' property (W3C DID Core §5.2). A verification method's controller MUST be stated explicitly; it does not default to the DID subject.
```

**1 rejection(s)** — `witness-update`/`python`

```
DID log contains invalid did:webvh data for did:webvh:QmVPXTZAumzuRFXb7Squ63ah8h7Tdi9SuP58wQ65Y5Baje:example.com :: FormatException: did:webvh log entry contains malformed content. :: JsonException: Verification method 'did:webvh:QmVPXTZAumzuRFXb7Squ63ah8h7Tdi9SuP58wQ65Y5Baje:example.com#P5RDjVJG' is missing the required 'controller' property (W3C DID Core §5.2). A verification method's controller MUST be stated explicitly; it does not default to the DID subject.
```

