# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - Unreleased

### Added

- **DID Document Model**: Full W3C DID Core 1.0 compliant data model including `DidDocument`, `VerificationMethod`, `Service`, `ServiceEndpointValue` (URI/map/set), and `VerificationRelationshipEntry` (reference/embedded)
- **DID Parsing**: W3C DID syntax validation, method extraction, and DID URL parsing (path, query, fragment)
- **Cryptographic Primitives**:
  - Key generation for Ed25519, X25519, P-256, P-384, and secp256k1
  - Sign/verify for Ed25519, P-256, P-384, and secp256k1
  - X25519 key agreement (ECDH)
  - Ed25519 to X25519 key derivation
- **Encoding Utilities**: Multibase (Base58Btc, Base64Url, Base32Lower), multicodec (7 key types), Base58Btc, Base64Url-no-padding
- **JWK Conversion**: Round-trip between raw key bytes and JSON Web Keys for all supported key types
- **Serialization**: DID Document serializer supporting both `application/did+ld+json` (JSON-LD with auto-computed `@context`) and `application/did+json` (plain JSON)
- **Resolver Infrastructure**: `CompositeDidResolver` (method routing), `CachingDidResolver` (TTL-based caching), `DefaultDidUrlDereferencer` (W3C section 7.2 algorithm)
- **Key Management**: `IKeyStore` interface for pluggable key storage, `InMemoryKeyStore` reference implementation, `ISigner` abstraction supporting both in-memory and HSM-backed signing
- **JSON Canonicalization**: RFC 8785 implementation for Data Integrity Proofs
- **Exception Hierarchy**: 8 domain-specific exception types
- **Result Types**: Strongly-typed results for create, resolve, update, deactivate, and dereference operations
