# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
