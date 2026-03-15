# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.0] - Unreleased

### Added

- **`IDidManager`** + **`DidManager`**: Unified DID lifecycle manager that routes Create, Resolve, Update, and Deactivate operations across registered methods. Inspired by Veramo's `IDIDManager` pattern.
- **`DidDocumentBuilder`**: Fluent API for constructing `DidDocument` instances with auto-set controller, verification methods, relationships, and services. Includes `VerificationMethodBuilder` and `ServiceBuilder`.
- **`NetDid.Extensions.DependencyInjection`**: Microsoft DI integration package with `services.AddNetDid(builder => {...})` composition pattern. Supports `AddDidKey()`, `AddDidPeer()`, `AddDidWebVh()`, and `AddCaching()`.
- **Logging support**: Optional `ILogger<T>` integration in `CompositeDidResolver`, `CachingDidResolver`, and `DidWebVhMethod` via `Microsoft.Extensions.Logging.Abstractions`.

### Changed

- **Samples split into per-method projects**: `NetDid.Samples.DidKey`, `NetDid.Samples.DidPeer`, `NetDid.Samples.DidWebVh`, and `NetDid.Samples.DependencyInjection` replace the monolithic `NetDid.Samples` project.

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
- **Witness validation security** (#15): Missing or malformed `did-witness.json` now correctly fails resolution when witness threshold > 0. Parser handles spec-compliant JSON array format and legacy single-object format.
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
