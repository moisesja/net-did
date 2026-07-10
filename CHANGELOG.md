# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- **did:webvh resolution now binds the DID's self-certifying SCID to the genesis entry** (#82). Resolution previously
  anchored identity only on the latest entry's `state.id` — an attacker-controllable document field — and validated the
  genesis SCID for internal self-consistency only. It never compared the SCID embedded in the requested DID string
  (`did:webvh:<SCID>:<domain>`) against the genesis entry's actual SCID. An attacker able to serve `did.jsonl` at the
  victim's URL (subdomain/host takeover, malicious CDN, or on-path MITM) could therefore serve a self-consistent genesis
  signed by *their own* key, with `state.id` set to the victim's literal DID, and the resolver would return the
  attacker's document with attacker keys as the authoritative resolution of the victim's unchanged DID. This defeated
  the self-certifying property that is did:webvh's entire security gain over did:web. `ResolveCoreAsync` now rejects
  (`invalidDidLog`) any log whose genesis SCID differs from the SCID in the requested DID, and the same binding is
  enforced on the write path (see below), so the writer cannot emit a log the resolver rejects on DID/SCID identity
  grounds (other resolution checks, e.g. witness thresholds, remain orthogonal). Discovered by an adversarial audit
  while fixing the Update/Deactivate binding below.

### Fixed

- **did:webvh Update/Deactivate now bind their inputs to the target DID** (#82). `DidWebVhMethod.UpdateCoreAsync`
  and `DeactivateCoreAsync` previously validated the caller-supplied `CurrentLogContent` chain and authorized the
  `SigningKey` against *that log's* `updateKeys` without checking that the log actually belonged to the `did` being
  operated on, and Update accepted a `NewDocument` without checking `NewDocument.Id == did`. An "update of A" could
  therefore be driven entirely by B's log + B's key (returning a document claiming `Id = A`), and the driver could
  emit an appended log that its own resolver rejects (resolution enforces `state.id == did`) — publishing it would
  brick the identity. Both operations now reject, with `ArgumentException`, a log whose latest entry's `state.id`
  differs from `did`, a log whose **genesis SCID** differs from the SCID in `did` (the self-certification binding
  above, applied writer-side so an attacker-owned log cannot authorize an update of the victim DID merely by claiming
  its id), a log that is already deactivated, and (Update) a `NewDocument` whose `Id` differs from `did`. This makes
  the write path match the read path's invariants.

### Added

- **`DidUpdateResult.AuthorizationChange`** (#82) — a method-agnostic signal of whether an update changed the
  method's authorization material, typed as the new **`AuthorizationChangeStatus`** enum (`Unknown` / `Unchanged` /
  `Changed`). did:webvh keeps update authority (`updateKeys` and related parameters) in the log parameters rather
  than the DID Document, so a caller reading back `DidUpdateResult.DidDocument` could not otherwise tell a
  document-only edit apart from a (possibly smuggled) key rotation. The did:webvh driver reports `Changed` /
  `Unchanged` by comparing the effective `updateKeys` / `nextKeyHashes` / `prerotation` / `witness` configuration
  before and after the update (`ttl` is excluded as a non-authority caching hint; the `witness` comparison is
  order-sensitive because enforcement resolves a witness by first-id match). The default is **`Unknown` so absence
  of evidence fails closed** — a method that does not evaluate change evidence (including any third-party
  `IDidMethod`) leaves the value at `Unknown`, and a consumer enforcing a document-only postcondition must require
  `Unchanged` explicitly rather than treat "not reported" as "confirmed unchanged."

## [2.0.1] - 2026-06-14

### Changed

- **Bumped `NetCrypto` `1.0.0` → `1.1.0`.** A backward-compatible (additive + hardening) refresh of
  the cryptography provider; net-did's own public API is unchanged. NetCrypto 1.1.0 adds
  `IKeyStore.DeriveSharedSecretAsync` (HSM-friendly ECDH), a `Base64Url` codec, and unified AEAD
  size metadata, and tightens EC public-key validation (wrong-length NIST EC keys now throw a
  parameter-named `ArgumentException` rather than an opaque `CryptographicException`). Consumers
  using NetCrypto types transitively pick these up automatically. `DataProofsDotnet.Core`
  `0.1.0-preview.1` (pinned to NetCrypto `>= 1.0.0`) resolves cleanly to 1.1.0 — the full suite,
  including did:webvh Data Integrity and all 182 W3C conformance assertions, passes against it.

## [2.0.0] - 2026-06-13

The crypto/proof externalization refactor. net-did now carries **only DID-method logic** — every
cryptographic primitive comes from [**NetCrypto**](https://www.nuget.org/packages/NetCrypto) (#75),
and did:webvh Data Integrity proofs come from
[**DataProofsDotnet**](https://www.nuget.org/packages/DataProofsDotnet.Core) (#76). JCS
canonicalization is owned by **NetCid**. No crypto primitive, signer, key model, JWK converter,
JCS canonicalizer, or Data Integrity engine remains in net-did source.

### Changed (BREAKING)

- **did:webvh Data Integrity now uses the conformant `eddsa-jcs-2022` cryptosuite from
  DataProofsDotnet** (#76). net-did previously signed `JCS(document-only)` — a non-conformant
  input. did:webvh log/witness proofs are now created and verified via
  `DataProofsDotnet.DataIntegrity.EddsaJcs2022Cryptosuite`, which signs the spec-correct
  `hashData = SHA-256(JCS(proofConfig)) ‖ SHA-256(JCS(document))`. **This changes the signed
  bytes: did:webvh logs and witness proofs produced by net-did before 2.0.0 will not verify
  under 2.0.0, and vice-versa.** net-did regenerates proofs deterministically, so there are no
  shipped golden proof fixtures to migrate. The `eddsa-jcs-2022` cryptosuite identifier and the
  did:webvh log wire shape are unchanged (the proof carries the same `type`/`cryptosuite`/
  `verificationMethod`/`created`/`proofPurpose`/`proofValue` fields) — only the `proofValue`
  bytes change — so the did:webvh method version is **not** bumped. One consequence of the
  conformant algorithm: the `verificationMethod` is now part of the signed proof configuration,
  so it can no longer be altered (e.g. adding/removing the `#fragment`) after signing without
  re-signing.
- **`DidWebVhMethod` no longer takes an `ICryptoProvider`** (#76). Its constructor is now
  `DidWebVhMethod(IWebVhHttpClient httpClient, ILogger<DidWebVhMethod>? logger = null)` — the
  cryptosuite is self-contained. `services.AddNetDid(...).AddDidWebVh()` is unaffected.
- **Cryptographic primitives moved to NetCrypto** (#75): The crypto primitive, key-type,
  signer, keystore, JWK, and KDF surface that previously lived under `NetDid.Core` is now
  provided by NetCrypto. The affected public types **changed namespace** from
  `NetDid.Core` / `NetDid.Core.Crypto` / `NetDid.Core.KeyStore` / `NetDid.Core.Jwk` to
  **`NetCrypto`**: `ICryptoProvider`, `IBbsCryptoProvider`, `ISigner`, `IKeyGenerator`,
  `IKeyStore`, `DefaultCryptoProvider`, `DefaultBbsCryptoProvider`, `DefaultKeyGenerator`,
  `KeyType`, `KeyTypeExtensions`, `EcPointValidator`, `EcdsaSignatureFormat`, `KeyPair`,
  `KeyPairSigner`, `KeyStoreSigner`, `StoredKeyInfo`, `PublicKeyReference`, `InMemoryKeyStore`,
  `JwkConverter`, and `ConcatKdf`. Consumers must replace `using NetDid.Core.Crypto;` (and the
  `.KeyStore` / `.Jwk` / `.Crypto.Kdf` namespaces) with `using NetCrypto;`. The method,
  property, and enum-ordinal signatures are otherwise unchanged, so behavior is identical — the
  W3C conformance suite (`did:key` / `did:peer` vectors, multibase + JWK round-trips) is
  byte-for-byte green across the swap.
- **`KeyTypeExtensions.ToKeyType(ulong)` renamed to `FromMulticodec(ulong)`** (#75): clearer
  name for "map a multicodec code to a `KeyType`". Call sites updated.
- **`AddNetDid(...)` now registers crypto services via `NetCrypto.AddNetCrypto()`** (#75):
  the DI container resolves `ICryptoProvider`, `IBbsCryptoProvider`, and `IKeyGenerator` from
  NetCrypto (still `TryAddSingleton`, `IKeyStore` still not auto-registered — unchanged
  behavior). The BBS-absent path now surfaces as `NetCrypto.BbsUnavailableException`
  (a `CryptographicException`) rather than `PlatformNotSupportedException`.

### Removed

- **In-repo crypto sources** (#75): deleted the `NetDid.Core/Crypto/` primitive cluster
  (`DefaultCryptoProvider`, `KeyType`, `KeyTypeExtensions`, `EcPointValidator`,
  `EcdsaSignatureFormat`, `KeyPair`, `KeyPairSigner`, `KeyStoreSigner`, `DefaultKeyGenerator`,
  `StoredKeyInfo`, `PublicKeyReference`, `DefaultBbsCryptoProvider`, `Native/ZkryptiumNative`,
  `Kdf/ConcatKdf`), the `I*` crypto interfaces, `KeyStore/InMemoryKeyStore`, and
  `Jwk/JwkConverter`.
- **Self-hosted zkryptium native FFI** (#75): removed the `native/zkryptium-ffi/` Rust crate,
  the bundled `runtimes/**` BBS dylib, the `runtimes` pack directive, and
  `<AllowUnsafeBlocks>` from `NetDid.Core.csproj`. The BBS native payload now flows
  transitively from the NetCrypto NuGet package (all 5 RIDs).
- **In-repo Data Integrity engine and JCS canonicalizer** (#76): deleted
  `NetDid.Core/Crypto/DataIntegrity/` (`DataIntegrityProofEngine`, the net-did `DataIntegrityProof`
  model) and `NetDid.Core/Crypto/Jcs/JsonCanonicalization`. did:webvh proofs come from
  DataProofsDotnet; SCID/entryHash JCS canonicalization comes from `NetCid.JcsCanonicalizer`. The
  security-critical `did:key` proof-signer parser (the DID==fragment anti-spoof check, with no
  upstream home) was relocated into an internal `NetDid.Method.WebVh` helper. `NetDid.Core` no
  longer contains a `Crypto/` directory.

### Dependencies

- Added `NetCrypto` `1.0.0` (#75) and `DataProofsDotnet.Core` `0.1.0-preview.1` (#76, referenced
  by `NetDid.Method.WebVh`). Bumped `NetCid` `1.5.0` → `1.6.0`. Dropped the direct
  `NSec.Cryptography`, `NBitcoin.Secp256k1`, and `Nethermind.Crypto.Bls` references — they are
  now transitive via NetCrypto. `Microsoft.IdentityModel.Tokens` is retained
  (`VerificationMethod.PublicKeyJwk` + JWK round-trips).

> **Preview dependency (conscious call).** `NetDid.Method.WebVh` `2.0.0` takes a **transitive
> dependency on `DataProofsDotnet.Core 0.1.0-preview.1`**, a prerelease package. Consumers that
> otherwise pin only stable packages will pull in this preview when they use `did:webvh`. The
> contract net-did relies on (`EddsaJcs2022Cryptosuite` / `DataIntegrityProof` /
> `PublicKeyMaterial` / `ProofVerificationResult`) is API-frozen, so the risk is the release
> channel, not the surface. net-did will move to the stable `DataProofsDotnet.Core 1.0.0` (and
> publish a corresponding net-did patch) as soon as it ships. `did:key` and `did:peer` have no
> preview dependencies. If a fully-stable dependency tree is required before adopting `did:webvh`,
> pin `NetDid.Method.WebVh` to the `1.x` line until then.

## [1.3.1] - 2026-06-03

### Added

- **Verification-relationship authorization primitive** (#71): New `IVerificationRelationshipResolver` (in `NetDid.Core.Resolution`) answers the W3C DID Core §5.3 question "does the controller's DID document authorize this verification method for this relationship?" Replaces the `bareDid(verificationMethod) == controller` string heuristic, which is sound only for `did:key` and breaks on cross-DID references and per-purpose key separation (hot key under `capabilityInvocation`, cold key under `capabilityDelegation`). Returns a tri-state `VerificationRelationshipAuthorizationResult` (`Authorized` / `NotAuthorized` / `ControllerNotResolvable`) so verifiers can fail closed while still surfacing the underlying resolution error code. Registered as a singleton by `services.AddNetDid(...)`; unblocks `zcap-dotnet#65` controller-authorization soundness for non-`did:key` methods. The relationship-list selector formerly private to `DefaultDidUrlDereferencer` is promoted to `DidDocument.GetRelationshipEntries(VerificationRelationship)` for reuse. Full rationale in PRD §10.5.

- **`DidWebVhArtifacts` constants for artifact dictionary keys** (#37 follow-up): New `public static class NetDid.Method.WebVh.DidWebVhArtifacts` exposes `DidJsonl`, `DidJson`, `DidWitnessJson`, and `LogEntries` as `public const string`. Internal Create/Update/Deactivate/Resolve sites and the test suite now bind to these symbols instead of duplicating the string literals (`"did.jsonl"`, etc.), so a typo in an external consumer like `net-wallet-mcp`'s `wallet.export_did_log` is a compile error instead of a runtime `KeyNotFoundException`. The string values themselves are unchanged; existing consumers that still pass the literal continue to work.

- **Expose the parsed did:webvh log on `DidResolutionResult`** (#37): `DidResolutionOptions` gains `IncludeLog` (default `false`); when set, `DidWebVhMethod.ResolveCoreAsync` surfaces the log that it already fetches, parses, and validates internally via a new `DidResolutionResult.Artifacts` dictionary — `Artifacts["did.jsonl"]` (UTF-8 `string`, matching the `did.jsonl` artifact already emitted by `CreateAsync` / `UpdateAsync` / `DeactivateAsync`) and `Artifacts["log.entries"]` (`IReadOnlyList<LogEntry>`, the parsed chain). Unblocks `net-wallet-mcp`'s `wallet.export_did_log` (FR-006, P7) without adding a separate `GetLogAsync` round-trip. Methods without history (`did:key`, `did:peer`) ignore the flag and leave `Artifacts` null; callers can branch on the new `DidMethodCapabilities.History` flag (declared by `did:webvh`, not by `did:key` / `did:peer`). `GetCacheDiscriminator()` now mixes in `IncludeLog` so a no-log cached result cannot shadow a fresh request that wants the log. The `Artifacts` value is `IReadOnlyDictionary<string, object>?`, matching the existing pattern on `DidCreateResult` / `DidUpdateResult` / `DidDeactivateResult`.

### Changed

- **Defensive read-only container for the parsed log chain** (#37 follow-up): `LogEntrySerializer.ParseJsonLines` now returns the result via `List<LogEntry>.AsReadOnly()` (`System.Collections.ObjectModel.ReadOnlyCollection<LogEntry>`) instead of handing out the concrete backing `List<LogEntry>` typed as `IReadOnlyList<LogEntry>`. Consumers that receive `Artifacts[DidWebVhArtifacts.LogEntries]` can no longer downcast to `List<LogEntry>` and `Add`/`Remove`/`Clear` the container — the `LogEntry` records were already immutable from the original PR, so the chain is now fully tamper-proof at both element and container level. Internal callers (`new List<LogEntry>(entries) { newEntry }` in Update/Deactivate, indexing in `ResolveCoreAsync`, `ValidateAllWitnesses(IReadOnlyList<LogEntry>)`) are source-compatible since `ReadOnlyCollection<T>` satisfies every signature the previous `List<T>` did.

- **`LogEntry` is now an immutable record** (#37): `NetDid.Method.WebVh.Model.LogEntry` was a `sealed class` with `set`-accessible `VersionId` and `Proof`; both internal flows (post-hash version-id assignment, post-sign proof attachment, validator save-mutate-restore) and one path in `LogChainValidator` mutated entries in place. It is now a `sealed record` whose `VersionId` and `Proof` are `init`-only; all internal mutation sites were refactored to `with` expressions. Two consequences for callers: (1) entries handed out via the new `IncludeLog` surface cannot be tampered with after resolution, and (2) `LogEntry` now uses structural equality — which is a behavior change for anyone who was comparing entries by reference. Internal grep showed no such comparisons; external code that wraps `LogEntry` should review.

- **NuGet dependency refresh**: Updated all centrally managed package versions to the latest stable releases on nuget.org. Crypto: `NSec.Cryptography` 24.4.0 → 26.4.0, `NBitcoin.Secp256k1` 3.1.5 → 4.0.0. Microsoft.Extensions.\* (`Caching.Memory`, `Logging.Abstractions`, `DependencyInjection`, `DependencyInjection.Abstractions`, `Http`) moved off the 10.0.0-preview channel onto stable `10.0.8`. `Microsoft.IdentityModel.Tokens` 8.3.0 → 8.19.1, `Microsoft.SourceLink.GitHub` 8.0.0 → 10.0.300. Testing: `Microsoft.NET.Test.Sdk` 17.12.0 → 18.6.0, `xunit.runner.visualstudio` 2.8.2 → 3.1.5 (still compatible with xunit v2), `coverlet.collector` 6.0.3 → 10.0.1. `FluentAssertions` intentionally held at 7.0.0 — v8 introduced a paid commercial license (Xceed) that is unsuitable for this open-source library. `Nethermind.Crypto.Bls`, `NetCid`, `xunit`, and `NSubstitute` were already on the latest stable versions and were not changed. All 775 tests across the 6 test projects pass on the new dependency set with no build warnings.

## [1.3.0] - 2026-05-22

### Security

- **Invalid-curve attack defense at the JWK boundary** (#63): `JwkConverter.ExtractPublicKey` now validates that the `(x, y)` coordinates of any `"EC"` JWK actually lie on the stated curve before returning. Without this check, a malicious peer could send a JWK whose coordinates do not satisfy `y² ≡ x³ + a·x + b (mod p)` and trick a downstream `DeriveSharedSecret` call into the invalid-curve attack (Antipa et al., PKC 2003; Jager–Schwenk–Somorovsky 2015 for the JOSE variant), recovering the victim's static private key bit-by-bit. RFC 7518 §6.2.2 mandates this check for JWE/JWS implementations. The new `NetDid.Core.Crypto.EcPointValidator.EnsureOnCurve(KeyType, x, y)` helper centralizes the validation logic — three BigInteger operations using the standard NIST curve parameters (`a = p − 3`) for P-256/P-384/P-521 and (`a = 0, b = 7, p = 2^256 − 2^32 − 977`) for secp256k1. The check is also wired into `DefaultCryptoProvider.ImportEcPublicKey` (uncompressed-point branch) and `DefaultCryptoProvider.DecompressEcPoint` (defense-in-depth — guards against a math bug in modular sqrt producing an off-curve point). Negative test coverage: off-curve points, point-at-infinity `(0, 0)`, and out-of-range `x = p` all throw `CryptographicException` from `ExtractPublicKey` for every NIST curve and secp256k1.

### Added

- **Concat KDF (RFC 7518 §4.6 / NIST SP 800-56A §5.8.1)** (#64): Added `NetDid.Core.Crypto.Kdf.ConcatKdf.DeriveKey(sharedSecret, algorithmId, partyUInfo, partyVInfo, suppPubInfo, suppPrivInfo, keyDataLen)` — the canonical NIST-spec-blessed KDF used by JOSE ECDH-ES (RFC 7518 §4.6) and ECDH-1PU (draft-madden-jose-ecdh-1pu §2). Combined with `ICryptoProvider.DeriveSharedSecret`, this completes the "compute the agreed content encryption key for a DID-secured channel" toolkit so consumers don't have to re-implement the subtle OtherInfo length-prefixing rules. Implementation handles counter mode (any `keyDataLen > 32` exercises it), non-block-aligned output truncation, empty `apu`/`apv`, and arbitrary `suppPubInfo` pass-through (for the ECDH-1PU AEAD tag binding). Validated against the RFC 7518 Appendix C worked example (note: the RFC's byte-list quote at position 15 is a known typo; we assert the cryptographically correct value, matching every other JOSE library).
- **IEEE P1363 ECDSA signature format** (#62): NIST-curve ECDSA signatures (P-256, P-384, P-521) can now be produced and verified in either ASN.1 DER (the back-compat default, expected by X.509 / CMS / generic DID proofs) or IEEE P1363 fixed-width R‖S concatenation (required by JOSE/JWS RFC 7515 §3.4, JWE, COSE, and WebAuthn). New `EcdsaSignatureFormat` enum (`Der = 0`, `IeeeP1363 = 1`) and additive `Sign(KeyType, priv, data, format)` / `Verify(KeyType, pub, data, sig, format)` overloads on `ICryptoProvider`. The existing 3-arg/4-arg overloads continue to default to DER, so no existing consumer breaks. Mismatched-format verify returns `false` rather than throwing, matching the JOSE convention for malformed signatures. P1363 signatures are exactly 64 (P-256), 96 (P-384), or 132 (P-521) bytes — fixed and not subject to ASN.1 length encoding. EdDSA / BLS keys ignore the format parameter; secp256k1's 64-byte compact output already matches P1363.
- **P-521 (secp521r1) support** (#61): Added `KeyType.P521` as a first-class key type across the full crypto surface: key generation/restore (`DefaultKeyGenerator`), ECDSA sign/verify with SHA-512 (JOSE alg `ES512`), ECDH dispatch in `DeriveSharedSecret`, JWK conversion (`crv: "P-521"` per RFC 7518 §6.2.1.1), JWK extraction, compressed SEC1 point decompression (66-byte X coord), and the W3C multikey multicodec mapping (`0x1202`). Both `DidKeyMethod` and `DidPeerMethod` now declare P-521 in `SupportedKeyTypes`, so `did:key:zP521…` can be created and resolved end-to-end. P-521 uses the same `a = p − 3`, `p ≡ 3 mod 4` curve-arithmetic path as P-256/P-384 — no new BigInteger paths needed. Validated by sign/verify round-trip, restored-key round-trip, JWK round-trip, ECDH key agreement (66-byte raw Z), and did:key create-resolve round-trip.
- **Raw ECDH key agreement** (#60): New `ICryptoProvider.DeriveSharedSecret(KeyType, privateKey, publicKey)` method returns the unprocessed shared secret "Z" for X25519, P-256, P-384, and P-521, with no KDF, no truncation, and no normalization applied. The 32-byte (X25519, P-256), 48-byte (P-384), or 66-byte (P-521) output is the canonical input to JOSE ECDH-ES Concat KDF (RFC 7518 §4.6), ECDH-1PU `Z = Ze ‖ Zs`, and other protocol-specific derivation flows. The existing `KeyAgreement(privateKey, publicKey)` method retains its X25519+HKDF-SHA256 behavior for back-compat. NIST P-curve agreement uses the cross-platform `ECDiffieHellman.DeriveRawSecretAgreement` API; X25519 uses NSec's `SharedSecretBlobFormat.RawSharedSecret` export. Non-ECDH key types (Ed25519, secp256k1, BLS12-381) throw `ArgumentException`. Validated against the RFC 7748 §6.1 X25519 and RFC 5903 §8.1/§8.2 P-256/P-384 ECDH known-answer test vectors.

## [1.2.0] - 2026-05-21

### Security

- **did:webvh HTTP fetches lack explicit resource limits** (#51): `DefaultWebVhHttpClient` previously called `HttpClient.GetAsync` and then `ReadAsByteArrayAsync` for both `did.jsonl` and `did-witness.json`, with no size limit, no streaming, and no `ResponseHeadersRead`. A hostile did:webvh host could push an unbounded body into the resolver's memory. The default client now accepts a `WebVhHttpClientOptions` with `MaxDidLogBytes` (default 5 MiB) and `MaxWitnessFileBytes` (default 1 MiB), uses `HttpCompletionOption.ResponseHeadersRead`, rejects responses whose declared `Content-Length` exceeds the limit, and aborts streaming reads once the bounded buffer is exceeded.

### Documentation

- **W3C conformance report scope clarified** (#48): The generated `w3c-conformance-report.md` now opens with a "Scope and limitations" section that distinguishes local DID Core 1.0 coverage from official method conformance certification, and links to the per-method test classes that cover the recent audit findings (`LogChainValidatorAuthorizationTests` for #50, `Issue49_*` for #49, `DefaultWebVhHttpClientTests` for #51, `Issue52_*` for #52). The audit findings themselves were addressed by PRs #54, #55, #56, #57, and this PR.

### Security

- **Native Rust FFI dependency cleanup** (#47): Upgraded `zkryptium` 0.2.2 → 0.6.1 in `native/zkryptium-ffi`, which prunes the cargo-license / clap / dotenv / ansi_term / atty / proc-macro-error transitives that triggered RustSec maintenance and unsoundness warnings (RUSTSEC-2021-0139, 2024-0375, 2021-0141, 2024-0370, 2021-0145). Crate dependency count fell from 103 → 51. Only RUSTSEC-2026-0097 (`rand 0.8.5`) remains; its unsoundness requires "a custom logger using `rand::rng()`", which is not reachable from the FFI shim or `zkryptium`. Added a `cargo audit` job to CI under `native/zkryptium-ffi` that ignores only that one advisory; any other warning now fails the build. Reachability analysis documented in `native/zkryptium-ffi/README.md`.

- **did:webvh URL mapping accepts unsafe host/path encodings** (#49): `DidUrlMapper.MapToLogUrl` / `MapToWitnessUrl` previously percent-decoded the domain chunk with `Uri.UnescapeDataString` and string-interpolated it into an HTTPS URL via `new Uri($"https://{host}/...")`. A crafted DID could therefore smuggle `%40` (`@`, userinfo/host pivot — e.g. `trusted.example%40evil.example` fetches `evil.example`), `%2F` / `%5C` (path injection), control characters, or path-traversal segments (`..`, `%2E%2E`) through resolution. The mapper now validates the decoded authority (no `@`, `/`, `\`, `?`, `#`, control chars; `Uri.CheckHostName` must succeed; port in [1, 65535]), validates each path segment (rejects `.`, `..`, encoded equivalents, and separator characters), and builds the URI with `UriBuilder` instead of string interpolation. `DidWebVhMethod.CreateAsync` applies the same validation, so unsafe `Domain`/`Path` inputs are rejected before any artifact is produced.
- **did:peer numalgo 2 accepts malformed key segments** (#52): `Numalgo2Handler.DecodeKeySegment` previously copied each `V`/`A`/`E`/`I`/`D` segment tail directly into `VerificationMethod.PublicKeyMultibase` with no decoding or validation, so a hostile `did:peer:2.V<garbage>` resolved into a DID Document containing impossible key material (invalid base58, unknown multicodec, wrong key length, off-curve EC point). Numalgo 2 now applies the same validation as `did:key` and numalgo 0 — decode multibase, decode multicodec, map to `KeyType`, length-check, and `IsValidEcPoint` — returning `invalidDid` on any failure.

### Security

- **did:webvh proof authorization bypass** (#50): `LogChainValidator.ValidateProof` previously authorized proofs using `proof.VerificationMethod.Contains(authorizedKey)` (substring match) while verifying signatures against the key extracted from the DID part only. An attacker could craft `verificationMethod = did:key:<attacker>#<authorized>`, sign with their own key, and have the proof accepted as authorized — allowing unauthorized log updates or deactivation. Authorization now requires exact equality between the signer's multibase key and an entry in `updateKeys`. A new `DataIntegrityProofEngine.ExtractDidKeyMultibase` helper parses `did:key` verification methods and rejects DID/fragment mismatches, path segments, and query strings before authorization is considered.

### Added

- **Method discovery surface on `IDidMethod`** (#36): Three additive, non-breaking properties let wallets and tooling introspect a registered method without constructing options:
    - `SupportedKeyTypes : IReadOnlyList<KeyType>` — the `KeyType` values the method accepts as input keys (`did:key` and `did:peer` declare every enum member; `did:webvh` declares `[Ed25519]`).
    - `SupportsRecovery : bool` — whether the method exposes a recovery surface. Defaults to `false`; concrete recovery API per category lands with ND-E9 (#44).
    - `RecoveryMaterialSpec : RecoveryMaterialSpec?` — `(Kind, SchemaVersion, Encoding)` introspection shape; non-null iff `SupportsRecovery == true`.
- **`NetDid.Core.Recovery.RecoveryMaterialSpec`**: New record describing the envelope shape of recovery material a method emits at bootstrap and consumes during recovery.
- **`DidManager` registration invariant** (#36): Construction now fails fast with `InvalidOperationException` when any registered method declares `SupportsRecovery=true` without a non-null `RecoveryMaterialSpec`.
- **Vulnerability and conformance audit report**: Added `tasks/vulnerability-conformance-audit-20260521.md` with NuGet, RustSec, full test-suite, W3C conformance, and manual security/conformance review results.

### Changed

- **`DidMethodBase.SupportedKeyTypes`** is **abstract** — every driver inheriting from `DidMethodBase` must declare its accepted set. The `IDidMethod` interface itself still defaults to an empty list via a default interface implementation, so out-of-tree implementers that bypass the base class are not broken.

## [1.1.2] - 2026-03-19

### Fixed

- **did:webvh artifact type mismatch** (#33): `DidWebVhMethod.CreateAsync`, `UpdateAsync`, and `DeactivateAsync` now return artifact values as `string` instead of `byte[]`. Consumers using `as string` or `(string)` casts on `Artifacts["did.jsonl"]` and `Artifacts["did.json"]` now receive the expected text content instead of `null`.

## [1.1.1] - 2026-03-15

### Fixed

- **Service dereferencing: unsupported Accept** (#29): Unsupported `Accept` media types (e.g. `text/plain`) now return `representationNotSupported` instead of incorrectly returning a DID Document. Only `application/did+ld+json`, `application/did+json`, and `text/uri-list` are accepted.
- **Service dereferencing: ID normalization** (#29): Service ID matching now normalizes relative and absolute URIs before comparison. A service with `id: "#svc"` correctly matches a query `?service=did:example:123%23svc`, and vice versa.
- **Service dereferencing: serviceType URI list** (#29): `?serviceType=<type>` with `Accept: text/uri-list` now returns URLs from all matching services, not just the first one.
- **Service dereferencing: fragment guard** (#29): `ConstructServiceUrl` no longer appends a DID URL fragment when the service endpoint URI already contains its own fragment.

## [1.1.0] - 2026-03-15

### Added

- **`IDidManager`** + **`DidManager`**: Unified DID lifecycle manager that routes Create, Resolve, Update, and Deactivate operations across registered methods. Inspired by Veramo's `IDIDManager` pattern.
- **`DidDocumentBuilder`**: Fluent API for constructing `DidDocument` instances with auto-set controller, verification methods, relationships, and services. Includes `VerificationMethodBuilder` and `ServiceBuilder`.
- **`NetDid.Extensions.DependencyInjection`**: Microsoft DI integration package with `services.AddNetDid(builder => {...})` composition pattern. Supports `AddDidKey()`, `AddDidPeer()`, `AddDidWebVh()`, and `AddCaching()`.
- **Logging support**: Optional `ILogger<T>` integration in `CompositeDidResolver`, `CachingDidResolver`, and `DidWebVhMethod` via `Microsoft.Extensions.Logging.Abstractions`.
- **Witness artifact production** (#17): `DidWebVhCreateOptions`, `DidWebVhUpdateOptions`, and `DidWebVhDeactivateOptions` now accept `WitnessProofs` to emit `did-witness.json` artifacts during CRUD operations. Includes `WitnessValidator.SerializeWitnessFile` and `MergeWitnessProofs` for round-trip serialization and incremental merging.
- **`serviceType` query parameter** (#29): `DefaultDidUrlDereferencer` supports `?serviceType=<type>` to filter services by type per W3C §7.2.
- **`VerificationRelationship` dereferencing option** (#29): `DidUrlDereferencingOptions.VerificationRelationship` restricts fragment dereferencing to a specific relationship array (e.g., `authentication`, `assertionMethod`).

### Changed

- **`IDidManager.CreateAsync`**: Method is now inferred from the options type via `DidCreateOptions.MethodName` instead of a separate `string method` parameter. Callers write `manager.CreateAsync(new DidKeyCreateOptions { ... })` instead of `manager.CreateAsync("key", new DidKeyCreateOptions { ... })`.
- **Samples split into per-method projects**: `NetDid.Samples.DidKey`, `NetDid.Samples.DidPeer`, `NetDid.Samples.DidWebVh`, and `NetDid.Samples.DependencyInjection` replace the monolithic `NetDid.Samples` project.

### Fixed

- **Invalid DID misclassification** (#26): `DidManager` and `CompositeDidResolver` now return `invalidDid` for syntactically invalid DIDs instead of incorrectly returning `methodNotSupported`. Validation via `DidParser.IsValid` runs before method extraction.
- **Service dereferencing algorithm** (#29): `DefaultDidUrlDereferencer` now returns a DID Document wrapper for service queries when `Accept` is a DID document content type (previously returned the raw `Service` object). Unsupported `Accept` values return `representationNotSupported`. Service ID matching normalizes relative and absolute URIs before comparison (e.g. `#svc` matches `did:example:123#svc`). Endpoint sets (`ServiceEndpointValue.IsSet`) are handled for `text/uri-list` responses. URL construction uses `System.Uri` for RFC 3986 compliance.
- **Witness validation spec compliance** (#15): Witness validation now checks all witnessed versions in the log chain, not just the final entry. Cumulative coverage rule implemented: a witness proof at version N satisfies all versions ≤ N, with deduplication by witness ID. Legacy single-object `did-witness.json` format is now rejected (only spec-compliant JSON array format accepted). Missing or malformed witness files correctly fail resolution when witness threshold > 0.
- **did:peer:4 long-form encoding** (#25): Encoding now follows the current peer-DID spec — contextualizes the input document, prepends JSON multicodec, multibase-encodes the result, and computes the short-form hash from the encoded document.
- **EC key encodings** (#27): `did:key` and `did:peer:0` now use compressed point encoding for P-256, P-384, and secp256k1 keys per the `did:key` specification. Malformed multicodec payloads are rejected during resolution instead of producing unusable verification methods.
- **did:peer:2 identifiers** (#28): Verification methods now use spec-defined relative IDs (`#key-1`, `#key-2`) instead of absolute IDs. Service entries use the spec-defined `#service` / `#service-1` naming pattern. Explicit `service.id` values are preserved through round-trip.

### Removed

- **`NetDid.Samples`**: Monolithic samples project replaced by per-method sample projects.

## [0.4.0] - Unreleased

### Added

- **did:webvh method** (`NetDid.Method.WebVh`): Full CRUD implementation of the DIF did:webvh v1.0 specification (did:web + Verifiable History). Supports:
    - **Create**: Genesis log entry generation with SCID (Self-Certifying Identifier) via two-pass algorithm (JCS → SHA-256 → multihash → base58btc multibase)
    - **Resolve**: Fetch `did.jsonl`, validate hash chain and Data Integrity Proofs, return DID Document
    - **Update**: Append log entries with cryptographic chaining to previous entry's `versionId`
    - **Deactivate**: Append deactivation entry with minimal document
    - **Pre-rotation**: Commit to future update keys via SHA-256 hash commitments (`nextKeyHashes`). Every update under pre-rotation must rotate keys.
    - **Witness validation**: Configurable witness threshold with weighted witness proofs via `did-witness.json`
    - **did:web backwards compatibility**: Automatic `did.json` generation alongside `did.jsonl`
    - **Versioned resolution**: Resolve by `versionId` or `versionTime` with partial chain validation
- **Data Integrity Proof engine** (`eddsa-jcs-2022`): JCS canonicalization → Ed25519 signing → multibase encoding. Reusable across DID methods.
- **`IWebVhHttpClient`** interface with `MockWebVhHttpClient` for testing
- **`DidUrlMapper`**: Maps `did:webvh:<SCID>:<domain>` → `https://<domain>/.well-known/did.jsonl`
- **`PreRotationManager`**: Key commitment computation and validation
- **`WitnessValidator`**: Witness proof validation with configurable thresholds and weights
- **`LogChainValidator`**: Full chain validation with partial validation support for versioned queries
- **`VersionTime` metadata**: `DidDocumentMetadata.VersionTime` property for did:webvh resolution output
- **W3C conformance tests** for did:webvh (57/57 DID Core checks passing)
- **Web server setup documentation**: ASP.NET Core, NGINX, Apache, Caddy, and cloud hosting configurations
- **Samples**: 7 did:webvh usage examples (create, artifacts, resolve, update, key rotation with pre-rotation, deactivate, dual-identity pattern)

### Fixed

- **Entry hash chaining** (#14): Log entry hashes now include the previous entry's full `versionId` per the did:webvh spec, preventing history rewriting attacks.
- **Witness validation security** (#15): Missing or malformed `did-witness.json` now correctly fails resolution when witness threshold > 0.
- **DID binding during resolution** (#16): Resolver now verifies that the resolved document's `id` matches the requested DID, preventing wrong-SCID resolution attacks.
- **Versioned resolution** (#20): Returns `notFound` when a requested `versionId` or `versionTime` doesn't match any entry (previously fell back to latest). Earlier valid versions can now be resolved even if later entries are corrupt via partial chain validation.
- **Pre-rotation bypass** (#21): Updates under active pre-rotation now require `updateKeys` to be provided. Both the API and chain validator reject entries that omit key rotation when pre-rotation is enabled.
- **Documentation staleness** (#18): README updated to reflect did:webvh as implemented. Installation instructions include `NetDid.Method.WebVh`. Roadmap Phase III marked as Complete.

## [0.3.0] - Unreleased

### Changed

- **did:peer purpose codes**: Aligned with the current DIF peer-DID spec. `KeyAgreement` now uses prefix `E` (was `A`). Added three new `PeerPurpose` members: `Assertion` (prefix `A`), `CapabilityInvocation` (prefix `I`), and `CapabilityDelegation` (prefix `D`). All five W3C DID Core verification relationships are now supported in numalgo 2.

### Fixed

- **DID parser validation**: `DidParser.IsValid` now enforces W3C DID Core ABNF — rejects DID URLs (fragments, queries, paths, parameters), spaces, and other illegal characters. The `Did` value object now truly guarantees syntactic validity.
- **DID URL parameter parsing**: `DidParser.ParseDidUrl` now correctly parses DID parameters (`;param=value`), modeled via new `DidUrl.Parameters` property.
- **Private JWK key leak**: `DidDocumentSerializer` no longer emits private key member `d` from `publicKeyJwk`. Only public JWK members (`kty`, `crv`, `x`, `y`) are serialized.
- **JSON-LD context objects**: Object-valued `@context` entries now round-trip correctly through serialization and deserialization. Previously they were dropped or caused `JsonException`.
- **Embedded VM dereferencing**: `DefaultDidUrlDereferencer` now finds embedded verification methods inside all relationship arrays (`authentication`, `assertionMethod`, `keyAgreement`, `capabilityInvocation`, `capabilityDelegation`) when resolving by fragment.
- **Documentation alignment**: Aligned `CLAUDE.md`, `AGENTS.md`, and `NetDidPRD.md` with actual implementation status. Only `did:key` and `did:peer` are implemented; `did:webvh` and `did:ethr` are marked as planned. W3C Test Suite conformance claims downgraded to planned.
- **did:peer numalgo 4 resolution fidelity**: `BuildResolvedDocument` now rewrites controller values matching the placeholder DID, rewrites embedded verification methods in relationship arrays, and preserves `@context` and `AdditionalProperties`. Input document now serialized as JSON-LD so `@context` survives round-trip.

## [0.2.0] - 2026-03-08

### Added

- **did:key method** (`NetDid.Method.Key`): Deterministic, self-certifying DID method. Create and resolve for all 7 key types. Ed25519 auto-derives X25519 key agreement key. Supports `Multikey` and `JsonWebKey2020` verification method representations. BLS12-381 keys use assertion-only relationships.
- **did:peer method** (`NetDid.Method.Peer`): Peer-to-peer DID method with three numalgo variants:
    - Numalgo 0: Inception key (functionally identical to did:key)
    - Numalgo 2: Inline keys and services with DIF spec purpose codes and service abbreviation encoding
    - Numalgo 4: Hash-based short/long form with SHA-256 integrity verification
- **Ed25519 to X25519 public key derivation**: Birational map for resolve-path public-key-only conversion (`IKeyGenerator.DeriveX25519PublicKeyFromEd25519`)
- **JWK from raw bytes**: `JwkConverter.ToPublicJwk(KeyType, byte[])` overload for resolve-path usage
- **Samples**: Console app demonstrating did:key and did:peer usage across all variants

## [0.1.0] - 2026-03-08

### Added

- **DID Document Model**: Full W3C DID Core 1.0 compliant data model including `DidDocument`, `VerificationMethod`, `Service`, `ServiceEndpointValue` (URI/map/set), and `VerificationRelationshipEntry` (reference/embedded)
- **DID Parsing**: W3C DID syntax validation, method extraction, and DID URL parsing (path, query, fragment)
- **Cryptographic Primitives**:
    - Key generation for Ed25519, X25519, P-256, P-384, secp256k1, BLS12-381 G1, and BLS12-381 G2
    - Sign/verify for Ed25519, P-256, P-384, secp256k1, BLS12-381 G1, and BLS12-381 G2
    - X25519 key agreement (ECDH)
    - Ed25519 to X25519 key derivation
- **BBS+ Signatures** (IETF draft-irtf-cfrg-bbs-signatures-10, BLS12-381-SHA-256 ciphersuite):
    - Multi-message signing and verification
    - Selective disclosure proof generation and verification
    - Native implementation via Rust FFI shim wrapping [zkryptium](https://github.com/Cybersecurity-LINKS/zkryptium)
- **Encoding Utilities**: Multibase (Base58Btc, Base64Url, Base32Lower), multicodec (7 key types), Base58Btc, Base64Url-no-padding
- **JWK Conversion**: Round-trip between raw key bytes and JSON Web Keys for all supported key types
- **Serialization**: DID Document serializer supporting both `application/did+ld+json` (JSON-LD with auto-computed `@context`) and `application/did+json` (plain JSON)
- **Resolver Infrastructure**: `CompositeDidResolver` (method routing), `CachingDidResolver` (TTL-based caching), `DefaultDidUrlDereferencer` (W3C section 7.2 algorithm)
- **Key Management**: `IKeyStore` interface for pluggable key storage, `InMemoryKeyStore` reference implementation, `ISigner` abstraction supporting both in-memory and HSM-backed signing
- **JSON Canonicalization**: RFC 8785 implementation for Data Integrity Proofs
- **Exception Hierarchy**: 8 domain-specific exception types
- **Result Types**: Strongly-typed results for create, resolve, update, deactivate, and dereference operations
