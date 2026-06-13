# net-did Refactor Plan — Adopt NetCrypto + DataProofsDotnet (+ NetCid)

_Generated 20260613-100115 by a 22-agent survey→map→verify→synthesize workflow. Companion upstream issues: `upstream-gaps-20260613-100115.md`._

## Executive Summary

net-did can shed essentially its entire crypto/proof implementation. Eighteen source files under src/NetDid.Core/Crypto/ (plus the self-hosted Rust zkryptium-ffi crate, the osx-arm64 dylib, and the runtimes pack directive) are verbatim or near-verbatim ancestors of shipped NetCrypto twins and can be deleted: ICryptoProvider/IBbsCryptoProvider, DefaultCryptoProvider, DefaultBbsCryptoProvider+ZkryptiumNative, KeyType/KeyTypeExtensions/EcPointValidator/EcdsaSignatureFormat, ConcatKdf, ISigner/IKeyGenerator/IKeyStore, KeyPair/KeyPairSigner/KeyStoreSigner/DefaultKeyGenerator/StoredKeyInfo/PublicKeyReference/InMemoryKeyStore, and JwkConverter. JCS canonicalization moves to NetCid.JcsCanonicalizer (bump NetCid 1.5.0->1.6.0). The crypto-primitive, key-type, signer/keystore, KDF, JWK, and BBS subsystems map cleanly — the public API signatures all exist in NetCrypto's frozen PublicAPI.Shipped.txt and the only deltas are non-regressing hardening. The dominant correctness caveat is type identity, not behavior: swapping to NetCrypto.KeyType/ISigner rewrites kept DID-method PUBLIC APIs across ~29 files, so the whole Crypto/ folder must migrate in one pass rather than file-by-file, and every test project (not just src/samples) must be rewired in the same commit or the suite stops compiling. The real risk is concentrated in one subsystem: Data Integrity / eddsa-jcs-2022 for did:webvh. net-did currently signs JCS(document-only) while the conformant DataProofsDotnet EddsaJcs2022Cryptosuite signs SHA-256(proofConfig)‖SHA-256(document) — a hard wire-format break that invalidates every existing did:webvh log/witness fixture (BLOCKER). Two upstream gaps block the migration outright: (1) DataProofsDotnet is not published to NuGet anywhere (version 0.1.0-preview.1, "being finalized"; no .nupkg in cache or repo), so the entire Data Integrity phase cannot even reference it yet; and (2) the wire-format conformance decision for did:webvh must be made and fixtures regenerated. Lower-severity gaps: NetCrypto exposes no public raw BBS keygen (the one net-did BBS test that P/Invokes ZkryptiumNative.bbs_keygen must be deleted, not ported), the did:key verificationMethod parser (ExtractDidKeyMultibase, security-critical anti-spoof) has no upstream home and must be relocated into net-did's did:key method, and CPM bookkeeping (add NetCrypto + DataProofsDotnet.Core PackageVersions, bump NetCid to 1.6.0) must precede everything. The non-Data-Integrity crypto migration (NetCrypto + NetCid only) is unblocked today and should proceed first; the did:webvh Data Integrity phase is gated on DataProofsDotnet being published and the wire-format decision being ratified.


---

## Goal: net-did consumes NetCrypto + DataProofsDotnet + NetCid; carries ZERO crypto/proof code

### Target end-state architecture

- **net-did keeps ONLY DID-method logic**: the DID document model, parsing, resolution, dereferencing, verification-relationship authorization, and the three method implementations (`did:key`, `did:peer`, `did:webvh`). No crypto primitive, signer, key model, keystore, JWK converter, JCS canonicalizer, or Data Integrity engine survives in net-did source.
- **NetCrypto (crypto-dotnet)** supplies every cryptographic primitive: `ICryptoProvider`/`DefaultCryptoProvider`, `IBbsCryptoProvider`/`DefaultBbsCryptoProvider` (+ native BBS payload transitively via the NuGet `runtimes/`), `KeyType`/`KeyTypeExtensions`/`EcPointValidator`/`EcdsaSignatureFormat`, `ConcatKdf`/`Hkdf`, `ISigner`/`IKeyGenerator`/`IKeyStore`, `KeyPair`/`KeyPairSigner`/`KeyStoreSigner`/`DefaultKeyGenerator`/`StoredKeyInfo`/`PublicKeyReference`/`InMemoryKeyStore`, and `JwkConverter`.
- **DataProofsDotnet (DataProofsDotnet.Core)** supplies Data Integrity / `eddsa-jcs-2022` (`EddsaJcs2022Cryptosuite`, `DataIntegrityProof`, `PublicKeyMaterial`, `ProofVerificationResult`) for did:webvh log/witness signing and verification.
- **NetCid** supplies multiformats (`Multibase`/`Multicodec`/`Multihash`/`Multikey`) and `JcsCanonicalizer` (RFC 8785) for SCID/entryHash.
- **net-did retains** only DID-method-specific glue: the `did:key` verificationMethod parser/anti-spoof helper, the `DataIntegrityProofValue` wire DTO that controls the exact did:webvh log JSON shape, and its allow-list (`updateKeys`) authorization model.

### Repo rules

- Do **NOT** bump `NetDidVersion`. Record all changes under `CHANGELOG.md` `[Unreleased]` only (currently absent — add the section above `[1.3.1]`).
- Write/track this plan in `tasks/todo{timestamp}.md`; capture corrections in `tasks/lessons.md`.

---

## Phase 0 — Packaging & central package management (do FIRST; unblocks everything)

- [ ] Add to `/Users/moises/Projects/net-did/Directory.Packages.props`: `<PackageVersion Include="NetCrypto" Version="1.0.0-preview.1" />` (verified present in `~/.nuget/packages/netcrypto/1.0.0-preview.1` with all 5 RID native dylibs). A bare `PackageReference` fails under CPM without this.
- [ ] Bump `<PackageVersion Include="NetCid" ... />` from `1.5.0` to `1.6.0` in `Directory.Packages.props` (NetCrypto 1.0.0-preview.1 nuspec depends on NetCid 1.6.0; JcsCanonicalizer hardening also lands in 1.6.0). NetCid 1.6.0 confirmed in cache.
- [ ] **BLOCKED (upstream gap DP-1):** add `<PackageVersion Include="DataProofsDotnet.Core" Version="0.1.0-preview.1" />`. DataProofsDotnet is NOT published to NuGet (no `.nupkg` in cache or repo; version `0.1.0-preview.1`, "being finalized"). Do not start Phase 6 until the package exists on a feed net-did's CI can restore from. Interim option for local dev only: a `ProjectReference` to `/Users/moises/Projects/dataproofs-dotnet/src/DataProofsDotnet.Core` — but the migration is not "done" until it is a real package reference.
- [ ] Add `<PackageReference Include="NetCrypto" />` to `src/NetDid.Core/NetDid.Core.csproj`. Keep `NSec.Cryptography`/`NBitcoin.Secp256k1`/`Nethermind.Crypto.Bls` references for now (still consumed by the not-yet-deleted `DefaultCryptoProvider`/`KeyTypeExtensions`). They are dropped at the END of Phase 2.
- [ ] Verify `dotnet restore` succeeds with the new prerelease pin (may require `--prerelease` / a `nuget.config` that allows preview). Confirm no NetCid downgrade warning under CPM.

## Phase 1 — KDF (lowest-risk warm-up, validates the package wiring)

- [ ] Delete `src/NetDid.Core/Crypto/Kdf/ConcatKdf.cs` (only file under `Crypto/Kdf/`); replace with `NetCrypto.ConcatKdf` (identical `DeriveKey` signature; NetCrypto adds a harmless overflow guard).
- [ ] Rewire `samples/NetDid.Samples.DidPeer/Program.cs:5` (`using NetDid.Core.Crypto.Kdf;` -> `using NetCrypto;`); call at `:185` is body-unchanged.
- [ ] Delete or rewire `tests/NetDid.Core.Tests/Crypto/Kdf/ConcatKdfTests.cs` (`using` swap to `NetCrypto`; or delete — coverage duplicated upstream).
- [ ] Build + run `NetDid.Core.Tests` and the DidPeer sample to confirm the package reference is wired correctly before larger phases.

## Phase 2 — Crypto primitives, key types, signers/keystore, JWK (migrate as ONE atomic pass)

> These cannot be split: `NetCrypto.KeyType`/`ISigner` flow through kept DID-method PUBLIC APIs (~29 files), and `EcPointValidator`/`KeyTypeExtensions`/`JwkConverter` reach into `DefaultCryptoProvider` internals via `InternalsVisibleTo`. Delete the whole `Crypto/` cluster + the two interface files together, then rewire all consumers (src + samples + **tests**) in the same commit.

### 2a. Delete net-did crypto sources (replace with NetCrypto twins)

- [ ] `src/NetDid.Core/ICryptoProvider.cs` (both `ICryptoProvider` + `IBbsCryptoProvider`) -> `NetCrypto.ICryptoProvider` / `NetCrypto.IBbsCryptoProvider`.
- [ ] `src/NetDid.Core/Crypto/DefaultCryptoProvider.cs` (incl. internal `ImportEc*`/`Decompress*`/`GetCurveParams`) -> `NetCrypto.DefaultCryptoProvider`.
- [ ] `src/NetDid.Core/Crypto/KeyType.cs` -> `NetCrypto.KeyType` (enum ordinals verified identical, `P521=7` last).
- [ ] `src/NetDid.Core/Crypto/KeyTypeExtensions.cs` -> `NetCrypto.KeyTypeExtensions` (**rename `ToKeyType(ulong)` -> `FromMulticodec(ulong)`** at all call sites).
- [ ] `src/NetDid.Core/Crypto/EcPointValidator.cs` -> `NetCrypto.EcPointValidator`.
- [ ] `src/NetDid.Core/Crypto/EcdsaSignatureFormat.cs` -> `NetCrypto.EcdsaSignatureFormat`.
- [ ] `src/NetDid.Core/ISigner.cs` / `IKeyGenerator.cs` / `IKeyStore.cs` -> `NetCrypto.ISigner` / `IKeyGenerator` / `IKeyStore`.
- [ ] `src/NetDid.Core/Crypto/KeyPair.cs`, `KeyPairSigner.cs`, `KeyStoreSigner.cs`, `DefaultKeyGenerator.cs`, `StoredKeyInfo.cs`, `PublicKeyReference.cs` -> corresponding `NetCrypto.*` types.
- [ ] `src/NetDid.Core/KeyStore/InMemoryKeyStore.cs` -> `NetCrypto.InMemoryKeyStore` (namespace flattens `NetDid.Core.KeyStore` -> `NetCrypto`).
- [ ] `src/NetDid.Core/Jwk/JwkConverter.cs` -> `NetCrypto.JwkConverter` (`ToPublicJwk`/`ToPrivateJwk`/`ExtractPublicKey`; `VerificationMethod.PublicKeyJwk` stays `Microsoft.IdentityModel.Tokens.JsonWebKey?` — no model change).

### 2b. Rewire DI (NetDidBuilder)

- [ ] `src/NetDid.Extensions.DependencyInjection/NetDidBuilder.cs:4` `using NetDid.Core.Crypto;` -> `using NetCrypto;`.
- [ ] Replace the ctor registrations at `:26-27` (`TryAddSingleton<IKeyGenerator,DefaultKeyGenerator>()` + `TryAddSingleton<ICryptoProvider,DefaultCryptoProvider>()`) with a single `services.AddNetCrypto();` (registers `ICryptoProvider`+`IBbsCryptoProvider`+`IKeyGenerator` via `TryAddSingleton`; intentionally does NOT register `IKeyStore`, matching net-did today).
- [ ] `:56` `sp.GetRequiredService<ICryptoProvider>()` now resolves `NetCrypto.ICryptoProvider` (passed to `DidWebVhMethod`).

### 2c. Rewire kept DID-method public surface (using-swap `NetDid.Core.Crypto` -> `NetCrypto`; `ToKeyType` -> `FromMulticodec`)

- [ ] `src/NetDid.Method.Peer/Numalgo0Handler.cs` (`:13,:15` field/ctor `IKeyGenerator`; `:57` `ToKeyType`->`FromMulticodec`; `:31,:59,:62,:138` `NormalizeToCompressed`/`IsValidKeyLength`/`IsValidEcPoint`/`GetMulticodec`; `:36,:110` `Generate`/`DeriveX25519PublicKeyFromEd25519`).
- [ ] `src/NetDid.Method.Peer/Numalgo2Handler.cs` (`:148` `ToKeyType`->`FromMulticodec`; `:150,:154` using-swap).
- [ ] `src/NetDid.Method.Peer/DidPeerMethod.cs:17` ctor `IKeyGenerator`; `src/NetDid.Method.Peer/PeerKeyPurpose.cs:9` `ISigner Key`.
- [ ] `src/NetDid.Method.Key/DidKeyMethod.cs` (`:4` using; `:17,:19` ctor/field `IKeyGenerator`; `:87` `ToKeyType`->`FromMulticodec`; `:53,:89,:92,:206` using-swap; `:198` `JwkConverter.ToPublicJwk` -> `NetCrypto.JwkConverter`).
- [ ] `src/NetDid.Core/Resolution/DefaultVerificationMethodResolver.cs` (`:32` `ToKeyType`->`FromMulticodec`; `:39` `JwkConverter.ExtractPublicKey` -> `NetCrypto.JwkConverter`).
- [ ] `src/NetDid.Method.WebVh/DidWebVhMethod.cs:5,:19,:27,:30` field/ctor `ICryptoProvider` -> `NetCrypto.ICryptoProvider`.
- [ ] `src/NetDid.Method.WebVh/DidWebVhCreateOptions.cs:22`, `DidWebVhUpdateOptions.cs:16`, `DidWebVhDeactivateOptions.cs:16` `required ISigner` properties -> `NetCrypto.ISigner` (these are the real `ISigner` declarations; `DidWebVhMethod.cs` only accesses `.MultibasePublicKey`/`.KeyType`).

### 2d. Rewire samples

- [ ] `samples/NetDid.Samples.DidKey/Program.cs` (`:11` `new DefaultKeyGenerator()`, `:12` `new DefaultCryptoProvider()`, `:48` `new KeyPairSigner(...)`, `:119-125` `EcdsaSignatureFormat`/`KeyType.P256`) -> `NetCrypto` via `using NetCrypto;`.
- [ ] `samples/NetDid.Samples.DidPeer/Program.cs` (`:13,:14` generators/provider; `:49-51/:136-137/:149-150` `KeyPairSigner`; `:163,:170` `DeriveSharedSecret(KeyType.X25519,...)`) -> `NetCrypto`.
- [ ] `samples/NetDid.Samples.DidWebVh/Program.cs` (`:12,:13` `DefaultKeyGenerator`/`DefaultCryptoProvider`; `:25/:123/:193` `KeyPairSigner`) -> `NetCrypto`.

### 2e. Rewire ALL test projects (mandatory — suite will not compile otherwise)

- [ ] `tests/NetDid.Core.Tests/Crypto/EcPointValidatorTests.cs` — `using NetDid.Core.Crypto;` -> `using NetCrypto;`. NOTE: it calls the internal `DefaultCryptoProvider.DecompressEcPoint`/`DecompressSecp256k1Point` (`:207,:225`), which are internal in NetCrypto with `InternalsVisibleTo` only for `NetCrypto.Tests` — **these specific cases must be rewritten against a public NetCrypto API or deleted** (see gap CD-3). Public `EcPointValidator.EnsureOnCurve` cases pass unchanged.
- [ ] `tests/NetDid.Core.Tests/Crypto/DefaultCryptoProviderTests.cs` (`EcdsaSignatureFormat.Der/IeeeP1363` + `KeyType` at ~20 sites) — using-swap.
- [ ] `tests/NetDid.Core.Tests/Crypto/DefaultKeyGeneratorTests.cs` (`new DefaultKeyGenerator()`, `Generate`, `FromPublicKey` at `:85`) — using-swap; the `FromPublicKey` case passes (valid key) but note NetCrypto now throws `ArgumentException` on bad length/off-curve.
- [ ] `tests/NetDid.Core.Tests/Crypto/KeyPairSignerTests.cs`, `tests/NetDid.Core.Tests/Jwk/JwkConverterTests.cs` (round-trip + unsupported-kty `ArgumentException` cases pass unchanged — just `using NetDid.Core.Jwk;`->`using NetCrypto;` and `DefaultKeyGenerator`->`NetCrypto.DefaultKeyGenerator`), `tests/NetDid.Core.Tests/KeyStore/InMemoryKeyStoreTests.cs` (`using NetDid.Core.KeyStore;`->`using NetCrypto;`).
- [ ] `tests/NetDid.Tests.W3CConformance/Infrastructure/TestDidFactory.cs` (`KeyPairSigner` x3, `DefaultKeyGenerator`), `tests/NetDid.Method.Key.Tests/*`, `tests/NetDid.Method.Peer.Tests/DidPeerMethodTests.cs`, `tests/NetDid.Method.WebVh.Tests/*` (incl. `DidWebVhMethodTests.cs:885` which fully-qualifies `Core.Crypto.KeyType.Ed25519` — must change to `NetCrypto.KeyType.Ed25519`).

### 2f. Drop the three managed native packages (only AFTER 2a-2e compile)

- [ ] Remove `NSec.Cryptography`, `NBitcoin.Secp256k1`, `Nethermind.Crypto.Bls` `PackageReference`s from `src/NetDid.Core/NetDid.Core.csproj` (now transitive via NetCrypto). Keep `Microsoft.IdentityModel.Tokens` (still required by `VerificationMethod.PublicKeyJwk` and JWK round-trip).
- [ ] Remove the now-unused `InternalsVisibleTo Include="NetDid.Core.Tests"` only if no remaining net-did internals are tested (verify first; the DI/resolution code may still use it).

## Phase 3 — BBS provider + zkryptium native FFI relocation

- [ ] Delete `src/NetDid.Core/Crypto/DefaultBbsCryptoProvider.cs` -> `NetCrypto.DefaultBbsCryptoProvider` (ctor `new DefaultBbsCryptoProvider()` still compiles; availability now via `IsAvailable`, BBS-absent throws `NetCrypto.BbsUnavailableException` not `PlatformNotSupportedException`).
- [ ] Delete `src/NetDid.Core/Crypto/Native/ZkryptiumNative.cs` (and the empty `Crypto/Native/` folder) -> `NetCrypto.Native.ZkryptiumNative` (internal, transitive).
- [ ] Delete the entire `native/zkryptium-ffi/` Rust crate (`Cargo.toml`, `Cargo.lock`, `src/lib.rs`, `build-all.sh`, `README.md`, `target/`) — owned by `/Users/moises/Projects/crypto-dotnet/native/zkryptium-ffi`.
- [ ] Delete `src/NetDid.Core/runtimes/osx-arm64/native/libzkryptium_ffi.dylib` and the whole `runtimes/` tree; native payload now flows transitively from the NetCrypto NuGet (verified: `~/.nuget/packages/netcrypto/1.0.0-preview.1/runtimes/` carries osx-arm64/osx-x64/linux-x64/linux-arm64/win-x64).
- [ ] Remove the `<None Include="runtimes\**\native\*" .../>` pack ItemGroup from `NetDid.Core.csproj` (lines 25-28).
- [ ] Remove `<AllowUnsafeBlocks>true</AllowUnsafeBlocks>` from `NetDid.Core.csproj` (only `ZkryptiumNative`'s `LibraryImport` needed it; confirmed no other `unsafe` in net-did src — `stackalloc` users do not require it).
- [ ] **Delete** `tests/NetDid.Core.Tests/Crypto/DefaultBbsCryptoProviderTests.cs` — do NOT port. It P/Invokes the internal `ZkryptiumNative.bbs_keygen` (`:4,:24`), which has no public NetCrypto path for `NetDid.Core.Tests` (no `InternalsVisibleTo`). BBS round-trip coverage already lives in `NetCrypto.Tests` (gap CD-2). The `Sign_WithNethermindGeneratedKey_*` cases use the public `DefaultKeyGenerator.Generate(KeyType.Bls12381G2)` path but the file as a whole cannot compile without the FFI, so delete it wholesale.

## Phase 4 — JCS canonicalization -> NetCid (gated on Phase 6 ordering for one file)

- [ ] Delete `src/NetDid.Core/Crypto/Jcs/JsonCanonicalization.cs` -> `NetCid.JcsCanonicalizer` (parse string to `JsonElement` first: `JcsCanonicalizer.Canonicalize(JsonDocument.Parse(json).RootElement)`).
- [ ] Rewire `src/NetDid.Method.WebVh/ScidGenerator.cs:3` (drop `using NetDid.Core.Crypto.Jcs;`; `using NetCid;` already present); `:36` and `:57` `JsonCanonicalization.CanonicalizeToUtf8(s)` -> `JcsCanonicalizer.Canonicalize(JsonDocument.Parse(s).RootElement)`.
- [ ] Rewire `tests/NetDid.Method.WebVh.Tests/LogChainValidatorAuthorizationTests.cs:7,:68` (same swap).
- [ ] Delete `tests/NetDid.Core.Tests/Crypto/JsonCanonicalizationTests.cs` — its `FormatEs6Number` assertions (`:164/:171/:178`) target net-did's internal helper; NetCid's ES6 formatter is internal with no public target. RFC 8785 coverage is duplicated by NetCid's own suite. (Behavioral fix: net-did `-0.0`->"-0" vs NetCid "0" per spec.)
- [ ] **ORDERING PREREQUISITE:** `src/NetDid.Core/Crypto/DataIntegrity/DataIntegrityProofEngine.cs:2,43,91` also consumes `JsonCanonicalization`. Do NOT delete `JsonCanonicalization.cs` until Phase 6 has removed `DataIntegrityProofEngine.cs`, or the build breaks. Sequence: Phase 6 first (or concurrently), then delete the JCS file.

## Phase 5 — Retain & relocate DID-method-specific helpers (no upstream home)

- [ ] Move `ExtractDidKeyMultibase(string)` and `ExtractPublicKeyFromDidKey(string)` out of the to-be-deleted `DataIntegrityProofEngine.cs` into net-did's `did:key` method (e.g. `DidKeyMethod` static helpers, or a small `NetDid.Method.Key` internal helper). PRESERVE the exact-ordinal `StringComparer.Ordinal` DID==fragment anti-spoof check (defends `did:key:<attacker>#<authorized>`). For the bytes step, decode the extracted multibase via `NetCid.Multicodec.Decode` + `Multicodec.Ed25519Pub` check (existing logic), or feed the multibase into `DataProofsDotnet.PublicKeyMaterial.FromMultikey` at the verify boundary (gap DP-3 keeps the parser in net-did).
- [ ] **KEEP** `src/NetDid.Method.WebVh/Model/DataIntegrityProofValue.cs` as the did:webvh wire DTO (controls exact log/witness JSON). Bridge it to the upstream `DataIntegrityProof` (string `Created`) at the sign/verify boundary in Phase 6.

## Phase 6 — Data Integrity / eddsa-jcs-2022 -> DataProofsDotnet (RISKIEST; BLOCKED on DP-1 + DP-Blocker)

> **BLOCKED** until: (a) DataProofsDotnet.Core is published (gap DP-1), and (b) the wire-format/conformance decision is ratified (gap DP-Blocker). Phase 2 (NetCrypto `ISigner`/`KeyType`) is a hard prerequisite — DataProofs APIs take `NetCrypto.ISigner`/`KeyType`.

### 6a. Decide & document wire format (gap DP-Blocker)

- [ ] Confirm whether did:webvh mandates conformant Data Integrity `hashData = SHA-256(proofConfig)‖SHA-256(document)` (DataProofs) vs net-did's current `JCS(document-only)`. Adopt the conformant suite (spec-correct, interops with other did:webvh impls). Document a did:webvh log version bump and regenerate all golden `.jsonl`/witness fixtures.

### 6b. Delete net-did Data Integrity sources

- [ ] Delete `src/NetDid.Core/Crypto/DataIntegrity/DataIntegrityProofEngine.cs` -> `DataProofsDotnet.DataIntegrity.EddsaJcs2022Cryptosuite` (`CreateProofAsync(JsonElement, DataIntegrityProof, NetCrypto.ISigner, ct)` / `VerifyProof(JsonElement, DataIntegrityProof, PublicKeyMaterial) -> ProofVerificationResult`). Call the suite directly, NOT the high-level `DataIntegrityProofPipeline` (which embeds proof under `document.proof`; did:webvh serializes proof separately).
- [ ] Delete `src/NetDid.Core/Crypto/DataIntegrity/DataIntegrityProof.cs` -> `DataProofsDotnet.DataIntegrity.DataIntegrityProof` (richer; `Created` is a verbatim string — feed net-did's existing `"yyyy-MM-ddTHH:mm:ssZ"` string straight through; verified it passes the suite's `XmlDateTimeStamp` validation).

### 6c. Rewire did:webvh consumers

- [ ] `src/NetDid.Method.WebVh/DidWebVhMethod.cs` (`:6` using; `:20,:31` `new DataIntegrityProofEngine(crypto)` -> `EddsaJcs2022Cryptosuite`; `:103,:356,:448` `CreateProofAsync(string,...)` -> `suite.CreateProofAsync(JsonElement, proofOptions, signer, ct)` and **supply `proofOptions.VerificationMethod = did:key:{mb}#{mb}`** (upstream REQUIRES it; net-did used to auto-derive it) + `Created` as verbatim string; `:111-119/:364-372/:456-464` map returned `DataIntegrityProof` into `DataIntegrityProofValue` with string `Created` directly, no `DateTimeOffset` reformat; `:27` reassess whether the `ICryptoProvider` ctor param is still needed for proofs).
- [ ] `src/NetDid.Method.WebVh/LogChainValidator.cs` (`:1` using; `:12,:14` field/ctor -> `EddsaJcs2022Cryptosuite`; `:160-167` build upstream `DataIntegrityProof` with string `Created`; `:170` resolve VM via the relocated did:key helper -> `PublicKeyMaterial.FromMultikey(mb)` -> `suite.VerifyProof(JsonDocument.Parse(entryJsonWithoutProof).RootElement, proof, pkm).Verified`; `:180` `ExtractDidKeyMultibase` -> relocated helper; PRESERVE the `StringComparer.Ordinal` `updateKeys` allow-list check at `:183`; REMOVE the `DateTimeOffset.Parse` at `:164`).
- [ ] `src/NetDid.Method.WebVh/WitnessValidator.cs` (`:3` using; `:13,:15` field/ctor -> `EddsaJcs2022Cryptosuite`; `:54-61/:132-139` build upstream proof; `:63,:141` `VerifyProof` -> resolve VM + `suite.VerifyProof(...).Verified`; remove `DateTimeOffset.Parse` at `:58,:136`).
- [ ] Map `ProofVerificationResult.Verified` (bool) back into the existing "try next proof / accept first valid authorized" loop. Do NOT route through the pipeline's `DocumentVerificationResult` (all-proofs-must-verify aggregate) — wrong semantics for did:webvh.

### 6d. Rewrite/delete Data Integrity tests

- [ ] `tests/NetDid.Core.Tests/Crypto/DataIntegrity/DataIntegrityProofEngineTests.cs` — delete or rewrite against the conformant suite (golden proof bytes change due to hash-concat).
- [ ] `tests/NetDid.Method.WebVh.Tests/DidWebVhMethodTests.cs` — regenerate golden vectors / round-trip expectations (conformant hash-concat changes SCID-adjacent proof bytes; SCID itself unchanged if JCS bytes match).
- [ ] `tests/NetDid.Method.WebVh.Tests/LogChainValidatorAuthorizationTests.cs` — repoint `ExtractDidKeyMultibase` calls to the relocated helper.

## Verification

- [ ] `dotnet build` the full solution clean (after each phase; Phase 2 must compile before 2f drops the native packages).
- [ ] `dotnet test tests/NetDid.Core.Tests` — KDF, key-types, signers, JWK, EC validation.
- [ ] `dotnet test tests/NetDid.Method.Key.Tests` + `tests/NetDid.Method.Peer.Tests` — did:key/did:peer creation/resolution.
- [ ] `dotnet test tests/NetDid.Tests.W3CConformance` — **W3C conformance must stay green** (proves multibase/JWK round-trips and `did:key`/`did:peer` vectors are byte-identical post-swap).
- [ ] `dotnet test tests/NetDid.Method.WebVh.Tests` — did:webvh; after Phase 6, with regenerated fixtures.
- [ ] `dotnet test tests/NetDid.Extensions.DependencyInjection.Tests` — confirm `AddNetCrypto()` wiring resolves `ICryptoProvider`/`IKeyGenerator` and methods construct.
- [ ] Run all three samples (DidKey, DidPeer, DidWebVh) end-to-end.
- **Behavioral parity checks:**
  - [ ] EC compression: confirm `NormalizeToCompressed` still emits 33/49/67-byte compressed SEC1 and identical multibase strings for did:key/did:peer vectors.
  - [ ] On-curve / invalid-curve defense: confirm `IsValidEcPoint`/`EnsureOnCurve` reject off-curve points; confirm ECDSA verify of an off-curve attacker key returns `false` (not throws) in JWS-style loops (NetCrypto moved import inside the verify `try`).
  - [ ] X25519-from-Ed25519: confirm `Numalgo0Handler`/`DidKeyMethod` derivation produces identical X25519 keys (NetCrypto adds a `y==1` reject that never fires for valid keys).
  - [ ] DeriveSharedSecret vs KeyAgreement: confirm DidPeer `ConcatKdf` path still gets raw Z from `DeriveSharedSecret` (not HKDF-wrapped).
  - [ ] BBS draft alignment: confirm `IBbsCryptoProvider.IsAvailable` is true on osx-arm64 via the transitive NetCrypto native payload (before relying on it); round-trip a BBS sign/verify via the public `DefaultKeyGenerator.Generate(KeyType.Bls12381G2)` path.
  - [ ] **eddsa-jcs proof bytes (Phase 6):** the dominant risk — verify regenerated did:webvh logs/witness files verify under the conformant suite AND old fixtures are explicitly retired; confirm `Created` string is passed verbatim (no `DateTimeOffset` round-trip) and proof config omits `@context` (LogEntry has none) consistently.
  - [ ] SCID/entryHash parity: run SCID golden tests after the NetCid JCS swap; the `{SCID}`/placeholder two-pass must produce byte-identical SCIDs. (Note: `ScidGenerator` still uses `Multicodec.Prefix(0x12,...)` — a pre-existing, separately-tracked multihash concern, out of scope here.)
- [ ] Update `CHANGELOG.md` `[Unreleased]`: document removal of in-repo crypto/BBS/JCS/Data-Integrity code, adoption of NetCrypto + DataProofsDotnet.Core, NetCid 1.6.0 bump, did:webvh log wire-format change. Do NOT bump `NetDidVersion`.
- [ ] Add a `tasks/lessons.md` note: the migration is a project-wide public-API type swap (`NetCrypto.KeyType`/`ISigner`), not a folder delete — keep src + samples + tests in lockstep.

## Blocked-step summary (see gap report)

- **Phase 0 DataProofsDotnet PackageVersion** and **all of Phase 6** — BLOCKED on **DP-1** (DataProofsDotnet not published) and **DP-Blocker** (wire-format conformance decision).
- **Phase 3 BBS test** — resolved by deletion (gap **CD-2**, no upstream change strictly needed).
- **Phase 2e EcPointValidatorTests internal-decompress cases** — BLOCKED on **CD-3** (no public NetCrypto decompress API) unless rewritten/deleted.
- **Phase 5 did:key parser** — resolved in net-did (gap **DP-3**, no upstream change).

---

## Review — Issue #75 (cryptographic half) — ✅ DONE (2026-06-13, branch `feat/issue-75-netcrypto-migration`)

**Outcome:** full solution builds clean; **800 tests pass** across all 6 test projects (Core 400, W3CConformance 175, WebVh 130, Key 44, Peer 40, DI 11); all 4 samples (DidKey, DidPeer, DidWebVh, DependencyInjection) run end-to-end (exit 0). W3C conformance green is the key parity proof — the swap is type-identity, not behavior.

**Deviations from the original plan (all improvements):**
- Used **NetCrypto `1.0.0` GA** (in the cache) instead of `1.0.0-preview.1` → resolves gap **CD-1** (no prerelease pin needed).
- **Bumped `NetDidVersion` 1.3.1 → 2.0.0** at the user's explicit instruction (overrides the usual no-bump rule; justified by the breaking `KeyType`/`ISigner` namespace move). CHANGELOG `[2.0.0]` added.
- **Deferred ALL of Phase 4 (JCS) to #76** (user decision). #75 does not touch `ScidGenerator`/`JsonCanonicalization.cs`. Recorded as a comment on issue #76, which now owns the full JCS migration (not just the file deletion).
- **CD-3 EcPointValidator + DefaultCryptoProvider decompress tests:** rather than delete, re-expressed against the public `JwkConverter.ToPublicJwk` → `Base64UrlEncoder.DecodeBytes(X/Y)` path (keeps the on-curve / uncompressed-input coverage). Only `DecompressEcPoint_AcceptsRealKey` (which directly probed the internal primitive) and the BBS keygen test were deleted.

**Execution note:** Phase 1 (ConcatKdf) could not be isolated — see `tasks/lessons.md` (namespace ambiguity forces the whole crypto swap to be one atomic pass: delete sources first, then rewire).

**What still lives in net-did for #76 (data-proof half):** `Crypto/DataIntegrity/DataIntegrityProofEngine.cs` (+ the `did:key` proof-signer parser), `Crypto/DataIntegrity/DataIntegrityProof.cs`, `Crypto/Jcs/JsonCanonicalization.cs` — each given a `using NetCrypto;` swap so they consume the moved `ICryptoProvider`/`ISigner`/`KeyType` types.
