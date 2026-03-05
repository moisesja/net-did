# NetDid — Multi-Method DID Library for .NET

## Product Requirements Definition

**Version**: 1.0
**Date**: March 2026
**License**: Apache 2.0
**Target Runtime**: .NET 10
**Repository**: github.com/moisesja/netdid
**Status**: Implementation-Ready Specification

---

## Table of Contents

1. [Vision & Goals](#1-vision--goals)
2. [Scope & DID Methods](#2-scope--did-methods)
3. [Architecture Overview](#3-architecture-overview)
4. [Cryptographic Key Management](#4-cryptographic-key-management)
5. [DID Method: did:key](#5-did-method-didkey)
6. [DID Method: did:peer](#6-did-method-didpeer)
7. [DID Method: did:webvh](#7-did-method-didwebvh)
8. [DID Method: did:dht](#8-did-method-diddht)
9. [DID Method: did:ethr](#9-did-method-didethr)
10. [DID Document Model](#10-did-document-model)
11. [Resolver Architecture](#11-resolver-architecture)
12. [Pluggable Key Management](#12-pluggable-key-management)
13. [W3C DID Test Suite Conformance](#13-w3c-did-test-suite-conformance)
14. [Integration with zcap-dotnet](#14-integration-with-zcap-dotnet)
15. [Monorepo Structure](#15-monorepo-structure)
16. [Testing Strategy](#16-testing-strategy)
17. [Implementation Phases](#17-implementation-phases)
18. [Appendix A: Dual-Identity Design Pattern](#appendix-a-dual-identity-design-pattern)
19. [Appendix B: Specification References](#appendix-b-specification-references)
20. [Appendix C: Glossary](#appendix-c-glossary)

---

## 1. Vision & Goals

### 1.1 Purpose

NetDid is an open-source .NET 10 library that provides a unified, specification-compliant interface for creating, resolving, updating, and deactivating Decentralized Identifiers across five DID methods: `did:key`, `did:peer`, `did:webvh`, `did:dht`, and `did:ethr`.

The library generates cryptographic keys using well-tested elliptic curve algorithms but delegates key storage and lifecycle management to the consuming application through a pluggable `IKeyStore` interface. This separation ensures that NetDid remains focused on DID operations while allowing developers to integrate their own HSM, vault, or file-based key management solution.

Conformance is validated against the W3C DID Test Suite (https://w3c.github.io/did-test-suite/), ensuring that every DID Document produced by NetDid passes all applicable normative assertion tests defined by the W3C DID Working Group.

### 1.2 Design Goals

| Goal                            | Description                                                                                                                                                                                                  |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Spec Compliance**             | 100% compliant with W3C DID Core 1.0 and each method's published specification. No shortcuts, no partial implementations.                                                                                    |
| **W3C Test Suite Pass**         | Every DID method implementation MUST pass the W3C DID Test Suite across all five conformance categories: `did-identifier`, `did-core-properties`, `did-production`, `did-consumption`, and `did-resolution`. |
| **Key Generation, Not Storage** | Generate and restore keys across Ed25519, secp256k1, P-256, P-384, X25519, and BLS12-381 (G1/G2). Storage is the caller's responsibility via `IKeyStore`.                                                    |
| **Pluggable Everything**        | Key stores, HTTP clients, Ethereum RPC providers, Pkarr gateways — all injectable.                                                                                                                           |
| **Zero Opinions on Frameworks** | No dependency on ASP.NET, no DI container requirement. Pure library with optional DI extensions.                                                                                                             |
| **Test-Driven**                 | Every public API surface covered by unit tests. Integration tests against real networks (testnets, public gateways). W3C conformance tests run in CI.                                                        |
| **zcap-dotnet Compatible**      | Designed to be consumed directly by the zcap-dotnet library for ZCAP-LD signing and verification using DID-resolved keys.                                                                                    |

### 1.3 Non-Goals

- **Key vault implementation**: NetDid does NOT ship a production key store. It ships an `InMemoryKeyStore` for testing and development only.
- **Verifiable Credentials**: VC issuance/verification is out of scope. NetDid provides the identity layer that VC libraries build on.
- **DID method registration**: NetDid does not run a DID registrar service. It provides the programmatic building blocks.
- **Wallet UI**: No UI components.

---

## 2. Scope & DID Methods

### 2.1 Supported Methods Summary

| Method        | Spec Status            | Create | Resolve | Update         | Deactivate     | Service Endpoints | Key Types                                     |
| ------------- | ---------------------- | ------ | ------- | -------------- | -------------- | ----------------- | --------------------------------------------- |
| **did:key**   | W3C CCG Final          | ✅     | ✅      | ❌ (immutable) | ❌ (immutable) | ❌                | Ed25519, P-256, P-384, secp256k1, X25519, BLS12-381 G2 |
| **did:peer**  | DIF v2 (numalgo 0,2,4) | ✅     | ✅      | ❌ (static)    | ❌             | ✅ (numalgo 2,4)  | Ed25519, X25519                               |
| **did:webvh** | DIF v1.0               | ✅     | ✅      | ✅             | ✅             | ✅                | Ed25519 (required), P-256 (optional)          |
| **did:dht**   | TBD/DIF Spec           | ✅     | ✅      | ✅             | ✅             | ✅                | Ed25519 (identity key required), + additional (secp256k1, P-256, BLS12-381) |
| **did:ethr**  | ERC-1056 / DIF         | ✅     | ✅      | ✅             | ✅             | ✅                | secp256k1 (primary), Ed25519 (delegate)       |

### 2.2 CRUD Operations Per Method

Each method implements the standard DID CRUD lifecycle, but the mechanics differ significantly:

**did:key** — Create-only. The DID _is_ the key. No network interaction. Resolution is purely algorithmic: decode the multicodec-prefixed key from the DID string, expand into a DID Document deterministically. The DID Document is always derived, never stored.

**did:peer** — Create and resolve locally. Numalgo 0 is equivalent to did:key. Numalgo 2 encodes verification methods and services directly in the DID string using purpose-prefixed multibase keys and JSON-encoded service blocks. Numalgo 4 hashes a full input document into a short-form DID with a long-form for initial exchange. No network interaction for any numalgo.

**did:webvh** — Full CRUD. "did:web + Verifiable History." Each update appends to a JSON Lines log file (`did.jsonl`) hosted at a web URL. The log is a cryptographically chained sequence of DID Document versions, anchored by a Self-Certifying Identifier (SCID) derived from the initial state. Resolution fetches the log and validates the entire chain. The DID can also be consumed as a plain `did:web` by legacy resolvers (backwards compatible). Supports pre-rotation keys, witnesses (did:key DIDs that co-sign updates), and watchers. Every version links back to its predecessor via a hash chain. Update authorization keys MUST rotate on every version when pre-rotation is active.

**did:dht** — Full CRUD. The DID suffix is a z-base-32 encoded Ed25519 public key called the "Identity Key." The DID Document is encoded as DNS TXT resource records following RFC 1035 packet format, signed with the Identity Key per BEP44 (BitTorrent mutable items), and published to the Mainline DHT via Pkarr HTTP relay gateways. Records are ephemeral (approximately 2 hour TTL on the DHT) and must be republished periodically. Deactivation is accomplished by publishing a DNS packet with an empty record set. The did:dht spec defines a type indexing system for discoverability.

**did:ethr** — Full CRUD. Based on the ERC-1056 `EthereumDIDRegistry` smart contract deployed at a well-known address. Any Ethereum address is automatically a valid DID with no registration needed (identity creation is free). Updates are recorded as on-chain events: `changeOwner` for ownership transfer, `setAttribute` for adding service endpoints and additional keys, `addDelegate`/`revokeDelegate` for time-limited delegate keys. Resolution replays contract events (via `eth_getLogs`) to reconstruct the DID Document. Supports meta-transactions (signed by the identity key, submitted by a third-party relayer). The network identifier is part of the DID: `did:ethr:0x1:0xabc...` for mainnet, `did:ethr:sepolia:0xabc...` for testnet. Pluggable RPC endpoint means any EVM chain works.

---

## 3. Architecture Overview

### 3.1 Layer Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                    Consumer Applications                     │
│         (zcap-dotnet, TurtleShell PDS, custom apps)         │
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│                      NetDid.Core                             │
│                                                              │
│  ┌────────────┐  ┌──────────────┐  ┌─────────────────────┐  │
│  │ IDidMethod │  │ IDidResolver │  │ IKeyGenerator       │  │
│  │            │  │              │  │                     │  │
│  │ + Create() │  │ + Resolve()  │  │ + Generate()        │  │
│  │ + Update() │  │              │  │ + FromPrivateKey()   │  │
│  │ + Deact()  │  │              │  │ + FromPublicKey()    │  │
│  └─────┬──────┘  └──────┬───────┘  └──────────┬──────────┘  │
│        │                │                      │             │
│  ┌─────▼────────────────▼──────────────────────▼──────────┐  │
│  │              DID Document Model                         │  │
│  │  DidDocument, VerificationMethod, Service,              │  │
│  │  VerificationRelationship, Did (value object)           │  │
│  └─────────────────────────────────────────────────────────┘  │
│                                                              │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │              Cryptographic Primitives                    │  │
│  │  Ed25519, X25519, P-256, P-384, secp256k1, BLS12-381   │  │
│  │  BBS+ Signatures, Multicodec, Multibase                 │  │
│  └─────────────────────────────────────────────────────────┘  │
│                                                              │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │              Key Management Abstraction                  │  │
│  │  IKeyStore (pluggable), KeyPair, KeyType enum            │  │
│  └─────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│                   Method Implementations                      │
│                                                               │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌─────────────┐  │
│  │ NetDid.   │ │ NetDid.   │ │ NetDid.   │ │ NetDid.     │  │
│  │ Method.   │ │ Method.   │ │ Method.   │ │ Method.     │  │
│  │ Key       │ │ Peer      │ │ WebVH     │ │ Dht         │  │
│  └───────────┘ └───────────┘ └───────────┘ └─────────────┘  │
│                                                               │
│  ┌─────────────┐ ┌──────────────────────────────────────┐    │
│  │ NetDid.     │ │ NetDid.Extensions.DependencyInjection│    │
│  │ Method.     │ │ (optional Microsoft.Extensions.DI)   │    │
│  │ Ethr        │ └──────────────────────────────────────┘    │
│  └─────────────┘                                              │
│                                                               │
│  ┌──────────────────────────────────────────────────────┐    │
│  │ NetDid.TestSuite.W3C                                  │    │
│  │ (W3C DID Test Suite conformance harness & fixtures)   │    │
│  └──────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────┘
```

### 3.2 Core Interfaces

```csharp
/// The unified interface every DID method implements.
public interface IDidMethod
{
    /// Method name (e.g., "key", "peer", "webvh", "dht", "ethr")
    string MethodName { get; }

    /// Which CRUD operations this method supports.
    DidMethodCapabilities Capabilities { get; }

    /// Create a new DID and return the DID Document + any artifacts (log entries, DNS packets, etc.)
    Task<DidCreateResult> CreateAsync(DidCreateOptions options, CancellationToken ct = default);

    /// Resolve a DID to its DID Document.
    Task<DidResolutionResult> ResolveAsync(string did, DidResolutionOptions? options = null, CancellationToken ct = default);

    /// Update an existing DID's document (throws NotSupportedException for immutable methods).
    Task<DidUpdateResult> UpdateAsync(string did, DidUpdateOptions options, CancellationToken ct = default);

    /// Deactivate a DID (throws NotSupportedException for immutable methods).
    Task<DidDeactivateResult> DeactivateAsync(string did, DidDeactivateOptions options, CancellationToken ct = default);
}

[Flags]
public enum DidMethodCapabilities
{
    None = 0,
    Create = 1,
    Resolve = 2,
    Update = 4,
    Deactivate = 8,
    ServiceEndpoints = 16
}

/// Standalone resolver interface for consumers who only need to resolve, not create.
public interface IDidResolver
{
    Task<DidResolutionResult> ResolveAsync(string did, DidResolutionOptions? options = null, CancellationToken ct = default);
    bool CanResolve(string did);
}
```

### 3.3 Result Types

```csharp
public sealed record DidCreateResult
{
    public required DidDocument DidDocument { get; init; }
    public required string Did { get; init; }
    public DidDocumentMetadata? Metadata { get; init; }

    /// Method-specific artifacts (e.g., did.jsonl content for webvh, DNS packet for dht)
    public IReadOnlyDictionary<string, object>? Artifacts { get; init; }
}

public sealed record DidResolutionResult
{
    public required DidDocument? DidDocument { get; init; }
    public required DidResolutionMetadata ResolutionMetadata { get; init; }
    public DidDocumentMetadata? DocumentMetadata { get; init; }
}

public sealed record DidResolutionMetadata
{
    public string? Error { get; init; }  // "notFound", "invalidDid", "methodNotSupported", etc.
    public string? ContentType { get; init; }
    public DateTimeOffset? Retrieved { get; init; }
    public IReadOnlyDictionary<string, object>? AdditionalProperties { get; init; }
}

public sealed record DidDocumentMetadata
{
    public DateTimeOffset? Created { get; init; }
    public DateTimeOffset? Updated { get; init; }
    public bool? Deactivated { get; init; }
    public string? VersionId { get; init; }
    public string? NextVersionId { get; init; }
    public string? NextUpdate { get; init; }
    public IReadOnlyList<string>? EquivalentId { get; init; }
    public string? CanonicalId { get; init; }
}

public sealed record DidUpdateResult
{
    public required DidDocument DidDocument { get; init; }
    public IReadOnlyDictionary<string, object>? Artifacts { get; init; }
}

public sealed record DidDeactivateResult
{
    public required bool Success { get; init; }
    public IReadOnlyDictionary<string, object>? Artifacts { get; init; }
}
```

### 3.4 Architectural Patterns

| Pattern             | Usage                                                                                                                        |
| ------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| **Strategy**        | Each DID method is an `IDidMethod` strategy. The `DidMethodRegistry` selects the correct one based on the DID string prefix. |
| **Factory**         | `IKeyGenerator` implementations are factories for key pairs per curve type.                                                  |
| **Adapter**         | External dependencies (HTTP for Pkarr gateways, Ethereum JSON-RPC) are wrapped behind interfaces for testability.            |
| **Decorator**       | Caching DID resolver wraps any `IDidResolver` with LRU + TTL cache.                                                          |
| **Composite**       | `CompositeDidResolver` aggregates multiple method-specific resolvers into a single `IDidResolver`.                           |
| **Template Method** | Base class `DidMethodBase` provides shared validation logic; each method overrides the method-specific steps.                |

### 3.5 Error Handling Strategy

NetDid defines a hierarchy of exception types for programmatic error handling. All NetDid exceptions derive from a common base:

```csharp
/// Base exception for all NetDid errors.
public class NetDidException : Exception
{
    public NetDidException(string message, Exception? inner = null) : base(message, inner) { }
}

/// The DID string is syntactically invalid (malformed, wrong prefix, bad encoding).
public class InvalidDidException : NetDidException
{
    public string Did { get; }
    public InvalidDidException(string did, string message) : base(message) => Did = did;
}

/// The DID method is not registered or supported by this resolver/method registry.
public class MethodNotSupportedException : NetDidException
{
    public string MethodName { get; }
    public MethodNotSupportedException(string method)
        : base($"DID method '{method}' is not supported.") => MethodName = method;
}

/// The requested CRUD operation is not supported by this DID method
/// (e.g., Update on did:key).
public class OperationNotSupportedException : NetDidException
{
    public string MethodName { get; }
    public string Operation { get; }
    public OperationNotSupportedException(string method, string operation)
        : base($"Method '{method}' does not support '{operation}'.") =>
        (MethodName, Operation) = (method, operation);
}

/// A resolution attempt failed (network error, malformed response, DID not found).
public class DidResolutionException : NetDidException
{
    public string Did { get; }
    public string ErrorCode { get; } // "notFound", "invalidDid", "deactivated", etc.
    public DidResolutionException(string did, string errorCode, string message, Exception? inner = null)
        : base(message, inner) => (Did, ErrorCode) = (did, errorCode);
}

/// Cryptographic verification failed (invalid signature, broken hash chain, etc.).
public class CryptoVerificationException : NetDidException
{
    public CryptoVerificationException(string message, Exception? inner = null) : base(message, inner) { }
}

/// A DID log chain is invalid (did:webvh hash chain break, unauthorized update key, etc.).
public class LogChainValidationException : CryptoVerificationException
{
    public int FailedAtVersion { get; }
    public LogChainValidationException(int version, string message)
        : base(message) => FailedAtVersion = version;
}

/// An Ethereum RPC or contract interaction failed (did:ethr).
public class EthereumInteractionException : NetDidException
{
    public EthereumInteractionException(string message, Exception? inner = null) : base(message, inner) { }
}
```

Method implementations return error codes via `DidResolutionMetadata.Error` for non-exceptional resolution failures (e.g., `"notFound"`, `"deactivated"`), following the W3C DID Core resolution contract. Exceptions are reserved for infrastructure failures, invalid inputs, and programming errors.

### 3.6 DidMethodBase

```csharp
/// Base class providing shared validation and routing for DID method implementations.
/// Each method overrides the abstract methods for method-specific logic.
public abstract class DidMethodBase : IDidMethod, IDidResolver
{
    public abstract string MethodName { get; }
    public abstract DidMethodCapabilities Capabilities { get; }

    public async Task<DidCreateResult> CreateAsync(DidCreateOptions options, CancellationToken ct = default)
    {
        if (!Capabilities.HasFlag(DidMethodCapabilities.Create))
            throw new OperationNotSupportedException(MethodName, "Create");
        return await CreateCoreAsync(options, ct);
    }

    public async Task<DidResolutionResult> ResolveAsync(string did, DidResolutionOptions? options = null, CancellationToken ct = default)
    {
        if (!DidParser.IsValid(did))
            return DidResolutionResult.InvalidDid(did);
        var method = DidParser.ExtractMethod(did);
        if (method != MethodName)
            return DidResolutionResult.MethodNotSupported(did);
        return await ResolveCoreAsync(did, options, ct);
    }

    public async Task<DidUpdateResult> UpdateAsync(string did, DidUpdateOptions options, CancellationToken ct = default)
    {
        if (!Capabilities.HasFlag(DidMethodCapabilities.Update))
            throw new OperationNotSupportedException(MethodName, "Update");
        return await UpdateCoreAsync(did, options, ct);
    }

    public async Task<DidDeactivateResult> DeactivateAsync(string did, DidDeactivateOptions options, CancellationToken ct = default)
    {
        if (!Capabilities.HasFlag(DidMethodCapabilities.Deactivate))
            throw new OperationNotSupportedException(MethodName, "Deactivate");
        return await DeactivateCoreAsync(did, options, ct);
    }

    public bool CanResolve(string did) => DidParser.ExtractMethod(did) == MethodName;

    protected abstract Task<DidCreateResult> CreateCoreAsync(DidCreateOptions options, CancellationToken ct);
    protected abstract Task<DidResolutionResult> ResolveCoreAsync(string did, DidResolutionOptions? options, CancellationToken ct);
    protected virtual Task<DidUpdateResult> UpdateCoreAsync(string did, DidUpdateOptions options, CancellationToken ct)
        => throw new OperationNotSupportedException(MethodName, "Update");
    protected virtual Task<DidDeactivateResult> DeactivateCoreAsync(string did, DidDeactivateOptions options, CancellationToken ct)
        => throw new OperationNotSupportedException(MethodName, "Deactivate");
}
```

---

## 4. Cryptographic Key Management

### 4.1 Supported Key Types

| Key Type          | Algorithm       | Multicodec Prefix                   | Usage                                                               |
| ----------------- | --------------- | ----------------------------------- | ------------------------------------------------------------------- |
| **Ed25519**       | EdDSA           | `0xed` (public), `0x8026` (private) | Signing, verification. Required by did:dht, did:webvh.              |
| **X25519**        | ECDH            | `0xec` (public)                     | Key agreement only. Used in did:peer and did:key.                   |
| **P-256**         | ECDSA (ES256)   | `0x8024` (public)                   | Signing, verification. Optional in did:webvh, supported in did:key. |
| **P-384**         | ECDSA (ES384)   | `0x8124` (public)                   | Signing, verification. Supported in did:key. Common in government/enterprise contexts. |
| **secp256k1**     | ECDSA (ES256K)  | `0xe7` (public)                     | Signing, verification. Required by did:ethr.                        |
| **BLS12-381 G1**  | BBS (BLS)       | `0xea` (public)                     | BBS+ signature verification (short signatures). Used in did:key.    |
| **BLS12-381 G2**  | BBS (BLS)       | `0xeb` (public)                     | BBS+ signing, selective disclosure, ZKPs. Primary curve for BBS+ credentials. Used in did:key and did:dht. |

### 4.2 Key Generator Interface

```csharp
public interface IKeyGenerator
{
    /// Generate a new random key pair for the given key type.
    KeyPair Generate(KeyType keyType);

    /// Restore a key pair from an existing private key.
    KeyPair FromPrivateKey(KeyType keyType, ReadOnlySpan<byte> privateKey);

    /// Create a public-only key reference from a public key.
    PublicKeyReference FromPublicKey(KeyType keyType, ReadOnlySpan<byte> publicKey);

    /// Derive an X25519 key agreement key from an Ed25519 key pair.
    KeyPair DeriveX25519FromEd25519(KeyPair ed25519KeyPair);
}

public sealed class KeyPair
{
    public required KeyType KeyType { get; init; }
    public required byte[] PublicKey { get; init; }
    public required byte[] PrivateKey { get; init; }

    /// The multicodec-prefixed, multibase-encoded public key (e.g., "z6Mkf...")
    public string MultibasePublicKey => MultibaseEncoder.Encode(MulticodecEncoder.Prefix(KeyType, PublicKey));

    /// JWK representation of the public key
    public JsonWebKey ToPublicJwk() => JwkConverter.ToPublicJwk(this);

    /// JWK representation of the key pair (includes private key material)
    public JsonWebKey ToPrivateJwk() => JwkConverter.ToPrivateJwk(this);
}

public enum KeyType
{
    Ed25519,
    X25519,
    P256,
    P384,
    Secp256k1,
    Bls12381G1,
    Bls12381G2
}
```

### 4.3 Cryptographic Signing Interface

```csharp
public interface ICryptoProvider
{
    // --- Standard single-message signing (EdDSA, ECDSA) ---
    byte[] Sign(KeyType keyType, ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> data);
    bool Verify(KeyType keyType, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature);

    // --- Key Agreement (X25519 ECDH) ---
    byte[] KeyAgreement(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> publicKey);
}

/// BBS+ signature operations (multi-message, selective disclosure, ZKPs).
/// Separated from ICryptoProvider because BBS+ has a fundamentally different
/// signing model: it operates over an ordered set of messages rather than
/// a single byte span, and supports proof derivation for selective disclosure.
public interface IBbsCryptoProvider
{
    /// Sign an ordered set of messages using a BLS12-381 G2 private key.
    /// Returns a BBS+ signature over all messages.
    byte[] Sign(ReadOnlySpan<byte> privateKey, IReadOnlyList<byte[]> messages);

    /// Verify a BBS+ signature against the full set of messages.
    bool Verify(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> signature, IReadOnlyList<byte[]> messages);

    /// Derive a zero-knowledge proof that selectively discloses only the messages
    /// at the specified indices, without revealing the original signature.
    /// The nonce prevents proof replay.
    byte[] DeriveProof(
        ReadOnlySpan<byte> publicKey,
        byte[] signature,
        IReadOnlyList<byte[]> messages,
        IReadOnlyList<int> revealedIndices,
        ReadOnlySpan<byte> nonce);

    /// Verify a derived proof against the revealed messages.
    /// totalMessageCount is needed because the proof hides unrevealed messages.
    bool VerifyProof(
        ReadOnlySpan<byte> publicKey,
        byte[] proof,
        IReadOnlyList<byte[]> revealedMessages,
        IReadOnlyList<int> revealedIndices,
        int totalMessageCount,
        ReadOnlySpan<byte> nonce);
}
```

### 4.4 Implementation Notes

- **Ed25519**: Use `System.Security.Cryptography` (.NET 10 has native Ed25519 support) or `NSec.Cryptography` as fallback for older targets.
- **X25519**: Same as Ed25519 — native in .NET 10 via `ECDiffieHellman` with `Curve25519`, or `NSec`.
- **P-256**: `System.Security.Cryptography.ECDsa` with `ECCurve.NamedCurves.nistP256`.
- **P-384**: `System.Security.Cryptography.ECDsa` with `ECCurve.NamedCurves.nistP384`. Native .NET support, no third-party dependency needed.
- **secp256k1**: `System.Security.Cryptography.ECDsa` with explicit curve parameters (secp256k1 is not a named curve in .NET), or `NBitcoin.Secp256k1` for a battle-tested implementation with Ethereum-compatible signing (recoverable signatures with v, r, s).
- **BLS12-381 (G1/G2)**: No native .NET support. Use `Nethermind.Crypto.Bls` (C# wrapper around the Supranational `blst` library) or `BLS.NET`. The `blst` library is the most widely deployed and audited BLS12-381 implementation (used by Ethereum 2.0 consensus clients). BBS+ signature operations (multi-message sign, derive proof, verify proof) should be implemented on top of the BLS12-381 primitives following the IETF BBS Signature Scheme draft (draft-irtf-cfrg-bbs-signatures).
- **JCS (JSON Canonicalization Scheme)**: Required for `eddsa-jcs-2022` Data Integrity Proofs used by did:webvh. Implements RFC 8785 deterministic JSON serialization. Use a custom implementation or port — no widely-adopted .NET library exists. The canonicalization must handle Unicode normalization, number serialization (IEEE 754 double), and property ordering as specified by RFC 8785.

### 4.5 Multicodec & Multibase

The library includes encoding/decoding utilities compliant with the Multiformats specifications:

```csharp
public static class MulticodecEncoder
{
    /// Prefix raw public key bytes with the multicodec varint for the given key type.
    public static byte[] Prefix(KeyType keyType, ReadOnlySpan<byte> rawKey);

    /// Decode: strip the multicodec prefix and return (KeyType, rawKeyBytes).
    public static (KeyType KeyType, byte[] RawKey) Decode(ReadOnlySpan<byte> prefixedKey);
}

public static class MultibaseEncoder
{
    /// Encode bytes as a multibase string (default: base58btc, prefix 'z').
    public static string Encode(ReadOnlySpan<byte> data, MultibaseEncoding encoding = MultibaseEncoding.Base58Btc);

    /// Decode a multibase string back to raw bytes.
    public static byte[] Decode(string multibaseString);
}

public enum MultibaseEncoding
{
    Base58Btc,  // prefix 'z'
    Base64Url,  // prefix 'u'
    Base32Lower // prefix 'b'
}
```

---

## 5. DID Method: did:key

### 5.1 Specification

W3C CCG did:key Method — https://w3c-ccg.github.io/did-method-key/

### 5.2 DID Format

```
did:key:<multibase-encoded-multicodec-prefixed-public-key>
```

Example: `did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK`

### 5.3 Create

1. Generate (or accept) a key pair of the requested `KeyType`.
2. Multicodec-prefix the public key bytes.
3. Multibase-encode with base58btc (`z` prefix).
4. The DID is `did:key:` + the multibase string.
5. Derive the DID Document algorithmically (see Resolution).

### 5.4 Resolve

Resolution is entirely deterministic — no network, no state:

1. Parse the DID, extract the multibase-encoded portion.
2. Multibase-decode, then multicodec-decode to get `(KeyType, rawPublicKey)`.
3. Build the DID Document:
   - `id`: the DID
   - `verificationMethod[0]`: the key, with `id` = `{did}#{multibase}`, type based on key type
   - `authentication`, `assertionMethod`, `capabilityDelegation`, `capabilityInvocation`: all reference `verificationMethod[0]`
   - If Ed25519: also derive X25519 key agreement key and add it to `keyAgreement`
4. Return the DID Document.

### 5.5 Key Type → Verification Method Type Mapping

| KeyType       | VM Type (Multikey) | VM Type (JWK)    | Curve        |
| ------------- | ------------------ | ---------------- | ------------ |
| Ed25519       | `Multikey`         | `JsonWebKey2020` | Ed25519      |
| X25519        | `Multikey`         | `JsonWebKey2020` | X25519       |
| P-256         | `Multikey`         | `JsonWebKey2020` | P-256        |
| P-384         | `Multikey`         | `JsonWebKey2020` | P-384        |
| secp256k1     | `Multikey`         | `JsonWebKey2020` | secp256k1    |
| BLS12-381 G1  | `Multikey`         | `JsonWebKey2020` | BLS12-381 G1 |
| BLS12-381 G2  | `Multikey`         | `JsonWebKey2020` | BLS12-381 G2 |

### 5.6 BBS+ Key Usage in did:key

When creating a `did:key` with a BLS12-381 G2 key, the resulting DID Document advertises the key for `assertionMethod` (credential issuance with selective disclosure) and `capabilityInvocation`. The key is NOT added to `authentication` because BBS+ signatures are not suitable for challenge-response authentication (they are designed for credential signing and proof derivation).

Example DID: `did:key:zUC7DerdEmfZ8GgSqnmUZjJiKJGYmVzRR7YXVP5eq3jtyLMtnDq...`

The multicodec prefix `0xeb` identifies the key as a BLS12-381 G2 public key (96 bytes).

### 5.7 Configuration

```csharp
public sealed record DidKeyCreateOptions : DidCreateOptions
{
    public required KeyType KeyType { get; init; }
    public bool EnableEncryptionKeyDerivation { get; init; } = true; // Derive X25519 from Ed25519
    public VerificationMethodRepresentation Representation { get; init; } = VerificationMethodRepresentation.Multikey;
}

public enum VerificationMethodRepresentation
{
    Multikey,       // "publicKeyMultibase" property
    JsonWebKey2020  // "publicKeyJwk" property
}
```

---

## 6. DID Method: did:peer

### 6.1 Specification

DIF Peer DID Method Specification — https://identity.foundation/peer-did-method-spec/

### 6.2 Supported Numalgo Variants

**Numalgo 0** — Inception key only. Functionally identical to did:key. Format: `did:peer:0<multibase-multicodec-public-key>`.

**Numalgo 2** — Inline keys and services. Each key is purpose-prefixed per the DIF spec:

- `A` = key agreement (X25519)
- `V` = verification / authentication (Ed25519) — used for authentication and assertion relationships
- `S` = service block (JSON encoded, then base64url-encoded)

Format: `did:peer:2.<purpose><multibase-key>.<purpose><multibase-key>.<purpose><encoded-service>`

**Numalgo 4** — Short-form + long-form. The "input document" (a DID Document without `id`) is serialized, hashed (SHA-256), and multibase-encoded to form the short-form DID. The long-form appends the full encoded input document for initial exchange. After first exchange, only the short-form is used.

Format:

- Short: `did:peer:4<short-form-hash>`
- Long: `did:peer:4<short-form-hash>:<long-form-encoded-document>`

### 6.3 Create

```csharp
public sealed record DidPeerCreateOptions : DidCreateOptions
{
    public required PeerNumalgo Numalgo { get; init; }

    // Numalgo 0: single key
    public KeyType? InceptionKeyType { get; init; }

    // Numalgo 2: explicit keys and services
    public IReadOnlyList<PeerKeyPurpose>? Keys { get; init; }
    public IReadOnlyList<Service>? Services { get; init; }

    // Numalgo 4: full input document
    public DidDocument? InputDocument { get; init; }
}

public sealed record PeerKeyPurpose(KeyPair KeyPair, PeerPurpose Purpose);

public enum PeerPurpose { Authentication, KeyAgreement }
public enum PeerNumalgo { Zero = 0, Two = 2, Four = 4 }
```

### 6.4 Resolve

Numalgo 0: Same algorithm as did:key — decode the key, build the document.

Numalgo 2: Parse the DID string, extract each purpose-prefixed segment, decode keys and service blocks, assemble the DID Document with appropriate verification relationships.

Numalgo 4 long-form: Decode the appended input document, verify the short-form hash matches the SHA-256 of the encoded document, populate the DID Document (inserting the DID as `id` and prefixing all relative references).

Numalgo 4 short-form: The resolver MUST already possess the long-form (received during initial exchange). If the long-form is not available, resolution fails with `notFound`.

### 6.5 Service Encoding (Numalgo 2)

Services in numalgo 2 are encoded per the spec's abbreviation rules:

| Full Property      | Abbreviated |
| ------------------ | ----------- |
| `type`             | `t`         |
| `serviceEndpoint`  | `s`         |
| `routingKeys`      | `r`         |
| `accept`           | `a`         |
| `DIDCommMessaging` | `dm`        |

The service JSON is serialized, base64url-encoded (no padding), and appended with an `S` purpose prefix.

---

## 7. DID Method: did:webvh

### 7.1 Specification

DIF did:webvh v1.0 — https://identity.foundation/didwebvh/

### 7.2 DID Format

```
did:webvh:<SCID>:<domain>:<optional-path-segments>
```

Example: `did:webvh:QmRwq46VkGuCEx4dyYxxexmig7Fwbqbm9AB73iKUAHjMZH:example.com`

The SCID (Self-Certifying Identifier) is derived from the initial DID log entry, making the DID self-certifying — the SCID cryptographically binds to the genesis state.

### 7.3 Backwards Compatibility with did:web

Any `did:webvh` can be deterministically converted to an equivalent `did:web` by removing `vh` from the method name and dropping the SCID segment:

```
did:webvh:QmRwq46V...:example.com  →  did:web:example.com
```

Legacy resolvers that only understand did:web can consume the `did.json` file at the web endpoint. The `alsoKnownAs` property in the DID Document links back to the did:webvh identifier.

### 7.4 DID Log Structure

The DID history is stored as a JSON Lines file (`did.jsonl`), where each line is a log entry:

```json
{
  "versionId": "1-QmRwq46V...",
  "versionTime": "2026-03-01T00:00:00Z",
  "parameters": {
    "method": "did:webvh:0.4",
    "scid": "QmRwq46V...",
    "updateKeys": ["z6Mkf..."],
    "prerotation": false,
    "witness": [],
    "deactivated": false
  },
  "state": {
    /* full DID Document */
  },
  "proof": [
    {
      "type": "DataIntegrityProof",
      "cryptosuite": "eddsa-jcs-2022",
      "verificationMethod": "did:key:z6Mkf...#z6Mkf...",
      "proofPurpose": "authentication",
      "proofValue": "z5d..."
    }
  ]
}
```

Each entry's `versionId` has the format `<version-number>-<entry-hash>`, where the entry hash chains to the previous entry.

### 7.5 Create

1. Generate an Ed25519 key pair (the "update key").
2. Build the initial DID Document with desired verification methods and services.
3. Set parameters: SCID (derived from genesis entry hash), updateKeys, optional pre-rotation commitment, optional witnesses.
4. Sign the genesis log entry with the update key using Data Integrity Proof (eddsa-jcs-2022).
5. Compute the SCID from the signed genesis entry.
6. Return: the DID string, the DID Document, the `did.jsonl` content (single line), and a `did.json` file for did:web compatibility.
7. The caller is responsible for publishing `did.jsonl` and `did.json` at the correct web URL.

### 7.6 Resolve

1. Transform the DID to an HTTPS URL: `did:webvh:<SCID>:<domain>` → `https://<domain>/.well-known/did.jsonl` (or path-based for non-root DIDs).
2. Fetch `did.jsonl` via HTTP.
3. Parse each JSON Lines entry sequentially.
4. Validate the genesis entry: verify the SCID matches the entry hash.
5. For each subsequent entry: verify the proof signature against an authorized update key, verify the hash chain links to the previous entry, verify parameter constraints (pre-rotation key commitments, witness thresholds).
6. If witnesses are configured, fetch `did-witness.json` and validate witness proofs meet the threshold.
7. Return the DID Document from the final valid entry.

### 7.7 Update

1. Load the current DID log.
2. Build a new log entry with the updated DID Document and/or parameters.
3. If pre-rotation is active: the proof MUST be signed by a key committed to in the previous entry, and new pre-rotation commitments MUST be provided.
4. Chain the new entry to the previous one via hash.
5. Sign with an authorized update key.
6. Append to `did.jsonl`.
7. If witnesses are configured, collect witness signatures into `did-witness.json`.
8. Return the new log entry for the caller to publish.

### 7.8 Deactivate

1. Create a new log entry with `parameters.deactivated = true`.
2. The DID Document in the final state is empty (or minimal).
3. Append to the log, sign, and publish.

### 7.9 Configuration

```csharp
public sealed record DidWebVhCreateOptions : DidCreateOptions
{
    public required string Domain { get; init; }           // e.g., "example.com"
    public string? Path { get; init; }                     // optional sub-path
    public required KeyPair UpdateKeyPair { get; init; }
    public IReadOnlyList<VerificationMethod>? AdditionalVerificationMethods { get; init; }
    public IReadOnlyList<Service>? Services { get; init; }
    public bool EnablePreRotation { get; init; } = false;
    public IReadOnlyList<string>? PreRotationCommitments { get; init; }  // hashes of next update keys
    public IReadOnlyList<string>? WitnessDids { get; init; }  // must be did:key DIDs
    public int WitnessThreshold { get; init; } = 0;
}

public sealed record DidWebVhUpdateOptions : DidUpdateOptions
{
    public required byte[] CurrentLogContent { get; init; }  // existing did.jsonl bytes
    public required KeyPair SigningKeyPair { get; init; }     // authorized update key
    public DidDocument? NewDocument { get; init; }
    public DidWebVhParameterUpdates? ParameterUpdates { get; init; }
}

public sealed record DidWebVhResolveOptions : DidResolutionOptions
{
    public string? VersionId { get; init; }    // resolve a specific version
    public string? VersionTime { get; init; }  // resolve at a point in time
}
```

### 7.10 HTTP Client Abstraction

```csharp
public interface IWebVhHttpClient
{
    Task<byte[]?> FetchDidLogAsync(Uri logUrl, CancellationToken ct);
    Task<byte[]?> FetchWitnessFileAsync(Uri witnessUrl, CancellationToken ct);
}
```

Default implementation uses `HttpClient`. Callers can inject their own for testing or custom auth.

---

## 8. DID Method: did:dht

### 8.1 Specification

DID DHT Method Specification — https://did-dht.com/

### 8.2 DID Format

```
did:dht:<z-base-32-encoded-ed25519-public-key>
```

Example: `did:dht:i9xkp8ddcbcg8jwq54ox699wuzxyifsqx4jru45zodqu453ksz6y`

The suffix is the z-base-32 encoding of the 32-byte Ed25519 public key (the "Identity Key"). This key is always present as verification method `#0` in the resolved DID Document.

### 8.3 DNS Packet Encoding

The DID Document is encoded as DNS TXT resource records:

| Record Name | Value Format                                              | Meaning                                                |
| ----------- | --------------------------------------------------------- | ------------------------------------------------------ |
| `_k0._did`  | `id=0;t=0;k=<base64url-pubkey>`                           | Identity Key (always present)                          |
| `_k1._did`  | `id=1;t=1;k=<base64url-pubkey>`                           | Additional key (t=type index from registry)            |
| `_s0._did`  | `id=s0;t=SovereignVaultPds;se=https://...`                | Service endpoint                                       |
| `_did`      | `v=0;vm=k0,k1;auth=k0;asm=k0;agm=k1;inv=k0;del=k0;srv=s0` | Root record mapping keys to verification relationships |
| `_typ._did` | `id=7`                                                    | DID type indexing for gateway discoverability          |

Key type indices from the did:dht registry:

| Index | Key Type      | JWK Algorithm |
| ----- | ------------- | ------------- |
| 0     | Ed25519       | `EdDSA`       |
| 1     | secp256k1     | `ES256K`      |
| 2     | P-256         | `ES256`       |
| 3     | BLS12-381 G2  | `BBS`         |

### 8.4 Create

1. Generate an Ed25519 key pair — this is the Identity Key. The public key defines the DID.
2. Optionally generate additional key pairs for other purposes.
3. Build service endpoints if desired.
4. Encode the DID Document as DNS TXT records per the spec.
5. Build a DNS response packet (RFC 1035 format).
6. Sign the packet using BEP44 mutable item signing (Ed25519 Identity Key signs the bencoded `v` value with a `seq` sequence number).
7. Publish to Pkarr HTTP gateway: `PUT https://dht.tbd.website/{z-base-32-identity-key}` with body containing the signed BEP44 payload.
8. Return the DID, DID Document, and publication status.

### 8.5 Resolve

1. Parse the DID, extract the z-base-32 suffix, decode to get the 32-byte Identity Key.
2. Query Pkarr gateway: `GET https://dht.tbd.website/{z-base-32-identity-key}`.
3. Receive the BEP44 signed payload.
4. Verify the Ed25519 signature against the Identity Key.
5. Decode the DNS packet from the `v` field.
6. Parse TXT records back into verification methods, services, and verification relationships.
7. Build and return the DID Document.

### 8.6 Update

Same as Create but with an incremented `seq` number. The gateway and DHT will accept updates only with a higher `seq` than the current record.

### 8.7 Deactivate

Publish a DNS packet with an empty record set (no TXT records other than a minimal `_did` root record). This signals deactivation. Alternatively, simply stop republishing — the DHT will drop the record after approximately 2 hours.

### 8.8 Configuration

```csharp
public sealed record DidDhtCreateOptions : DidCreateOptions
{
    public required KeyPair IdentityKeyPair { get; init; }
    public IReadOnlyList<DidDhtAdditionalKey>? AdditionalKeys { get; init; }
    public IReadOnlyList<Service>? Services { get; init; }
    public IReadOnlyList<int>? TypeIndices { get; init; }  // did:dht type indexing
    /// Default Pkarr gateway. TBD's gateway (dht.tbd.website) may be unreliable
    /// following TBD/Block's wind-down. Configure an alternative gateway as needed.
    /// Community-maintained options include pkarr.org and self-hosted instances.
    public required string GatewayUrl { get; init; }
}

public sealed record DidDhtAdditionalKey
{
    public required KeyPair KeyPair { get; init; }
    public required IReadOnlyList<VerificationRelationship> Relationships { get; init; }
}

public interface IPkarrGatewayClient
{
    Task PublishAsync(string zBase32Key, byte[] signedBep44Payload, CancellationToken ct);
    Task<byte[]?> ResolveAsync(string zBase32Key, CancellationToken ct);
}
```

### 8.9 Republishing

The DHT drops records after approximately 2 hours. NetDid provides a utility for periodic republishing:

```csharp
public interface IDhtRepublisher
{
    /// Start periodic republishing for a DID. Interval defaults to 60 minutes.
    Task StartAsync(string did, KeyPair identityKeyPair, TimeSpan? interval = null, CancellationToken ct = default);
    Task StopAsync(string did, CancellationToken ct = default);
}
```

This is provided as a convenience but the consuming application is responsible for orchestrating it (e.g., as a hosted service).

---

## 9. DID Method: did:ethr

### 9.1 Specification

ERC-1056 / DIF ethr-did-resolver — https://github.com/decentralized-identity/ethr-did-resolver/blob/master/doc/did-method-spec.md

### 9.2 DID Format

```
did:ethr:<optional-network>:<ethereum-address-or-public-key>
```

Examples:

- `did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a` (mainnet implied)
- `did:ethr:sepolia:0xb9c5714089478a327f09197987f16f9e5d936e8a` (Sepolia testnet)
- `did:ethr:0xaa36a7:0xb9c5714089478a327f09197987f16f9e5d936e8a` (by chain ID hex)

When no network is specified, Ethereum mainnet (chain ID 1) is assumed.

### 9.3 EthereumDIDRegistry Contract

The `EthereumDIDRegistry` smart contract (ERC-1056) is deployed at a well-known address (`0xdCa7EF03e98e0DC2B855bE647C39ABe984fcF21B`) on mainnet and many testnets. It provides:

- **identityOwner(address)** → returns the current owner of the identity
- **changeOwner(address, newOwner)** → transfer ownership
- **changeOwnerSigned(...)** → meta-transaction variant (signed by identity key, submitted by relayer)
- **addDelegate(address, delegateType, delegate, validity)** → add a time-limited delegate key
- **revokeDelegate(address, delegateType, delegate)** → revoke a delegate
- **setAttribute(address, name, value, validity)** → set an attribute (service endpoints, additional keys)
- **revokeAttribute(address, name, value)** → revoke an attribute

All mutations emit events. Resolution replays these events.

### 9.4 Create

did:ethr creation is implicit — any Ethereum key pair is already a valid DID. "Creating" a did:ethr means:

1. Generate (or accept) a secp256k1 key pair.
2. Derive the Ethereum address from the public key (keccak256 hash, take last 20 bytes, checksum-encode).
3. The DID is `did:ethr:<network>:<address>`.
4. The default DID Document has a single secp256k1 verification method for the controller address.
5. No on-chain transaction needed.

### 9.5 Resolve

1. Parse the DID, extract network identifier and address.
2. Select the appropriate RPC endpoint for the network.
3. Call `identityOwner(address)` to determine the current controller.
4. Query `eth_getLogs` for all `DIDOwnerChanged`, `DIDDelegateChanged`, and `DIDAttributeChanged` events for the address, from the contract deployment block.
5. Replay events chronologically to build the DID Document:
   - Each `DIDOwnerChanged` updates the controller.
   - Each `DIDDelegateChanged` adds/removes delegate verification methods (checking `validity` expiration against current block).
   - Each `DIDAttributeChanged` adds/removes attributes:
     - `did/pub/<keyType>/<purpose>/<encoding>` → verification method
     - `did/svc/<serviceType>` → service endpoint
6. Return the assembled DID Document.

### 9.6 Update

Updates require on-chain transactions:

```csharp
public sealed record DidEthrUpdateOptions : DidUpdateOptions
{
    // Add a service endpoint
    public IReadOnlyList<DidEthrServiceAttribute>? AddServices { get; init; }
    public IReadOnlyList<DidEthrServiceAttribute>? RemoveServices { get; init; }

    // Add/revoke delegate keys
    public IReadOnlyList<DidEthrDelegate>? AddDelegates { get; init; }
    public IReadOnlyList<DidEthrDelegate>? RevokeDelegates { get; init; }

    // Change owner
    public string? NewOwnerAddress { get; init; }

    // The key pair that controls the identity (for signing transactions)
    public required KeyPair ControllerKeyPair { get; init; }

    // Use meta-transaction (signed by controller, submitted by relayer)?
    public bool UseMetaTransaction { get; init; } = false;
}

public sealed record DidEthrDelegate
{
    public required string DelegateType { get; init; }  // e.g., "veriKey", "sigAuth"
    public required string DelegateAddress { get; init; }
    public required TimeSpan Validity { get; init; }
}

public sealed record DidEthrServiceAttribute
{
    public required string ServiceType { get; init; }
    public required string ServiceEndpoint { get; init; }
    public TimeSpan Validity { get; init; } = TimeSpan.FromDays(365 * 10);
}
```

### 9.7 Deactivate

Set the owner to `0x0000000000000000000000000000000000000000` (null address). This makes the identity uncontrollable and the DID Document resolves with `deactivated: true`.

### 9.8 Ethereum RPC Abstraction

```csharp
public interface IEthereumRpcClient
{
    Task<string> CallAsync(string to, string data, CancellationToken ct);
    Task<IReadOnlyList<EthereumLogEntry>> GetLogsAsync(EthereumLogFilter filter, CancellationToken ct);
    Task<string> SendRawTransactionAsync(byte[] signedTransaction, CancellationToken ct);
    Task<ulong> GetBlockNumberAsync(CancellationToken ct);
    Task<ulong> GetTransactionCountAsync(string address, CancellationToken ct);
    Task<ulong> GetGasPriceAsync(CancellationToken ct);
    Task<ulong> GetChainIdAsync(CancellationToken ct);
}

public sealed record EthereumNetworkConfig
{
    public required string Name { get; init; }        // "mainnet", "sepolia", "polygon", etc.
    public required string RpcUrl { get; init; }
    public string? ChainId { get; init; }             // auto-detected if not provided
    public string RegistryAddress { get; init; } = "0xdCa7EF03e98e0DC2B855bE647C39ABe984fcF21B";
}
```

The consumer provides one or more `EthereumNetworkConfig` entries. The library selects the config based on the network segment of the DID being resolved or updated.

---

## 10. DID Document Model

### 10.1 Core Model (W3C DID Core 1.0 Compliant)

```csharp
public sealed record DidDocument
{
    public required string Id { get; init; }
    public IReadOnlyList<string>? AlsoKnownAs { get; init; }

    /// W3C DID Core §5.1.2: controller is a single DID string or an ordered set of DID strings.
    /// Serialized as a string when Count == 1, as an array when Count > 1, omitted when null.
    public IReadOnlyList<string>? Controller { get; init; }

    public IReadOnlyList<VerificationMethod>? VerificationMethod { get; init; }
    public IReadOnlyList<VerificationRelationshipEntry>? Authentication { get; init; }
    public IReadOnlyList<VerificationRelationshipEntry>? AssertionMethod { get; init; }
    public IReadOnlyList<VerificationRelationshipEntry>? KeyAgreement { get; init; }
    public IReadOnlyList<VerificationRelationshipEntry>? CapabilityInvocation { get; init; }
    public IReadOnlyList<VerificationRelationshipEntry>? CapabilityDelegation { get; init; }

    public IReadOnlyList<Service>? Service { get; init; }

    /// JSON-LD @context. Always includes "https://www.w3.org/ns/did/v1" as the first entry.
    /// Additional context URIs are appended dynamically based on verification method types:
    ///   - Multikey           → "https://w3id.org/security/multikey/v1"
    ///   - JsonWebKey2020     → "https://w3id.org/security/suites/jws-2020/v1"
    ///   - BBS+ (bbs-2023)    → "https://w3id.org/security/data-integrity/v2"
    ///   - EcdsaSecp256k1...  → "https://w3id.org/security/suites/secp256k1-2019/v1"
    /// The DidDocumentSerializer computes the correct @context automatically from the
    /// verification methods present in the document. Callers may also supply additional
    /// context URIs that are appended after the auto-detected ones.
    public IReadOnlyList<object> Context { get; init; } = new object[] { "https://www.w3.org/ns/did/v1" };

    /// Extension properties not defined in DID Core.
    public IReadOnlyDictionary<string, JsonElement>? AdditionalProperties { get; init; }
}

public sealed class VerificationMethod
{
    public required string Id { get; init; }
    public required string Type { get; init; }        // "Multikey", "JsonWebKey2020", "EcdsaSecp256k1VerificationKey2019"
    public required string Controller { get; init; }
    public string? PublicKeyMultibase { get; init; }   // for Multikey representation
    public JsonWebKey? PublicKeyJwk { get; init; }     // for JWK representation
    public string? BlockchainAccountId { get; init; }  // for did:ethr (CAIP-10 format)
}

/// A verification relationship entry is either a reference (string DID URL) or an embedded verification method.
public sealed class VerificationRelationshipEntry
{
    public string? Reference { get; init; }
    public VerificationMethod? EmbeddedMethod { get; init; }

    public bool IsReference => Reference is not null;
}

public sealed class Service
{
    public required string Id { get; init; }
    public required string Type { get; init; }

    /// W3C DID Core §5.4: serviceEndpoint can be a URI string, a map (object),
    /// or an ordered set of URIs and/or maps. This is modeled as a discriminated
    /// union to preserve type safety while supporting all three forms.
    public required ServiceEndpointValue ServiceEndpoint { get; init; }

    public IReadOnlyDictionary<string, JsonElement>? AdditionalProperties { get; init; }
}

/// Represents the polymorphic serviceEndpoint value per W3C DID Core §5.4.
public sealed class ServiceEndpointValue
{
    // Exactly one of these is set:
    public string? Uri { get; init; }
    public IReadOnlyDictionary<string, JsonElement>? Map { get; init; }
    public IReadOnlyList<ServiceEndpointValue>? Set { get; init; }

    public bool IsUri => Uri is not null;
    public bool IsMap => Map is not null;
    public bool IsSet => Set is not null;

    public static implicit operator ServiceEndpointValue(string uri) => new() { Uri = uri };
}
```

### 10.2 Serialization

The DID Document model supports serialization to/from:

- **JSON** (primary, via `System.Text.Json`)
- **JSON-LD** (with `@context`)

Serialization is handled by a `DidDocumentSerializer` that produces spec-compliant JSON:

```csharp
public static class DidDocumentSerializer
{
    public static string ToJson(DidDocument doc, JsonSerializerOptions? options = null);
    public static DidDocument FromJson(string json);
    public static DidDocument FromJson(ReadOnlySpan<byte> utf8Json);
}
```

### 10.3 W3C DID Core Normative Requirements on the Document

The model enforces these at construction/deserialization:

- `id` MUST be a valid DID (validated by the `Did` value object).
- `controller`, when present, MUST be a valid DID (string form) or an ordered set of valid DIDs (array form). Serialized as a string when containing a single DID, as an array when containing multiple.
- `verificationMethod[*].id` MUST be a valid DID URL.
- `verificationMethod[*].controller` MUST be a valid DID.
- `service[*].id` MUST be a valid DID URL.
- `service[*].serviceEndpoint` MUST be a URI string, a map, or an ordered set of URIs/maps (§5.4).
- `@context` MUST include `"https://www.w3.org/ns/did/v1"` as the first element. Additional context URIs are computed dynamically from the verification method types present in the document.
- Verification relationship entries that are strings MUST be valid DID URLs.
- All properties follow the registered names in the DID Specification Registries.

---

## 11. Resolver Architecture

### 11.1 Composite Resolver

```csharp
public sealed class CompositeDidResolver : IDidResolver
{
    private readonly IReadOnlyDictionary<string, IDidResolver> _resolvers;

    public CompositeDidResolver(IEnumerable<IDidMethod> methods)
    {
        _resolvers = methods.ToDictionary(m => m.MethodName, m => (IDidResolver)m);
    }

    public bool CanResolve(string did)
    {
        var method = DidParser.ExtractMethod(did);
        return method is not null && _resolvers.ContainsKey(method);
    }

    public async Task<DidResolutionResult> ResolveAsync(string did, DidResolutionOptions? options = null, CancellationToken ct = default)
    {
        var method = DidParser.ExtractMethod(did);
        if (method is null || !_resolvers.TryGetValue(method, out var resolver))
            return DidResolutionResult.MethodNotSupported(did);

        return await resolver.ResolveAsync(did, options, ct);
    }
}
```

### 11.2 Caching Resolver

```csharp
public sealed class CachingDidResolver : IDidResolver
{
    private readonly IDidResolver _inner;
    private readonly IMemoryCache _cache;
    private readonly TimeSpan _ttl;

    public CachingDidResolver(IDidResolver inner, IMemoryCache cache, TimeSpan? ttl = null)
    {
        _inner = inner;
        _cache = cache;
        _ttl = ttl ?? TimeSpan.FromMinutes(15);
    }

    public async Task<DidResolutionResult> ResolveAsync(string did, DidResolutionOptions? options = null, CancellationToken ct = default)
    {
        // Cache key incorporates both the DID and resolution options to avoid
        // returning stale results when the same DID is resolved with different
        // parameters (e.g., versionId or versionTime for did:webvh).
        var cacheKey = ComputeCacheKey(did, options);

        if (_cache.TryGetValue(cacheKey, out DidResolutionResult? cached))
            return cached!;

        var result = await _inner.ResolveAsync(did, options, ct);
        if (result.DidDocument is not null)
            _cache.Set(cacheKey, result, _ttl);

        return result;
    }

    private static string ComputeCacheKey(string did, DidResolutionOptions? options)
    {
        if (options is null) return did;
        // Deterministic key combining DID + option values that affect resolution output.
        return $"{did}|{options.GetCacheDiscriminator()}";
    }
}
```

### 11.3 DID Parser

```csharp
public static class DidParser
{
    /// Validate a DID string conforms to W3C DID syntax: did:<method>:<method-specific-id>
    public static bool IsValid(string did);

    /// Extract the method name from a DID string. Returns null if invalid.
    public static string? ExtractMethod(string did);

    /// Extract the method-specific identifier.
    public static string? ExtractMethodSpecificId(string did);

    /// Parse a DID URL (DID + optional path, query, fragment).
    public static DidUrl? ParseDidUrl(string didUrl);
}

public sealed record DidUrl
{
    public required string Did { get; init; }
    public string? Path { get; init; }
    public string? Query { get; init; }
    public string? Fragment { get; init; }
    public string FullUrl => /* reconstruct */;
}
```

---

## 12. Pluggable Key Management

### 12.1 IKeyStore Interface

NetDid generates keys but does NOT store them. The caller provides an `IKeyStore` implementation:

```csharp
public interface IKeyStore
{
    /// Store a key pair, returning a stable key identifier.
    Task<string> StoreAsync(string alias, KeyPair keyPair, CancellationToken ct = default);

    /// Retrieve a key pair by alias.
    Task<KeyPair?> GetAsync(string alias, CancellationToken ct = default);

    /// List all stored key aliases.
    Task<IReadOnlyList<string>> ListAsync(CancellationToken ct = default);

    /// Delete a key pair by alias.
    Task<bool> DeleteAsync(string alias, CancellationToken ct = default);

    /// Sign data using a stored key (allows HSM-backed stores where the private key never leaves the device).
    Task<byte[]> SignAsync(string alias, ReadOnlyMemory<byte> data, CancellationToken ct = default);
}
```

### 12.2 Provided Implementations

| Implementation       | Purpose                                                                           | Production Use?     |
| -------------------- | --------------------------------------------------------------------------------- | ------------------- |
| `InMemoryKeyStore`   | Dictionary-backed, for unit tests and development                                 | ❌ Testing only     |
| `FileSystemKeyStore` | Encrypted JSON files in a directory (DPAPI on Windows, file permissions on Linux) | ⚠️ Development only |

### 12.3 Expected Third-Party Implementations

The interface is designed to be easily adapted to:

- Azure Key Vault
- AWS KMS
- HashiCorp Vault
- FIDO2/WebAuthn hardware authenticators
- OS-level keystores (Windows CNG, macOS Keychain, Linux Secret Service)
- Custom HSMs

### 12.4 Key Store in DID Operations

When a DID method needs to sign (e.g., creating a did:webvh log entry, publishing to did:dht, sending a did:ethr transaction), the method accepts either:

1. A `KeyPair` directly (caller manages keys externally), OR
2. A `keyAlias` + `IKeyStore` reference (the method calls `keyStore.SignAsync(alias, data)`)

This dual approach allows both simple usage and HSM-backed scenarios where the private key never leaves the secure enclave.

---

## 13. W3C DID Test Suite Conformance

### 13.1 Overview

The W3C DID Test Suite (https://github.com/w3c/did-test-suite) is maintained by the W3C DID Working Group and performs interoperability tests across five conformance categories. NetDid MUST pass all applicable tests for every supported DID method.

### 13.2 Conformance Categories

| Suite                   | What It Tests                                                                                                                                                                                                                                            | NetDid Applicability |
| ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------- |
| **did-identifier**      | DID syntax: method name is ASCII lowercase, method-specific-id conforms to ABNF, overall DID string matches the grammar.                                                                                                                                 | All 5 methods        |
| **did-core-properties** | DID Document properties: `id` is valid DID, `verificationMethod` entries have required fields, `service` entries are well-formed, all verification relationships reference valid VMs, `@context` is correct.                                             | All 5 methods        |
| **did-production**      | Serialization (production) of DID Documents: the JSON representation MUST include `@context`, property names MUST be strings, values MUST conform to the data model type system, JSON members MUST be serialized correctly.                              | All 5 methods        |
| **did-consumption**     | Deserialization (consumption) of DID Documents: a conforming consumer MUST be able to parse a valid DID Document representation and extract the data model.                                                                                              | All 5 methods        |
| **did-resolution**      | DID Resolution: given a DID, the resolver returns a conformant `DidResolutionResult` with correct `didDocument`, `didResolutionMetadata`, and `didDocumentMetadata`. Covers error cases (`notFound`, `invalidDid`, `methodNotSupported`, `deactivated`). | All 5 methods        |

### 13.3 Test Fixture Generation

The W3C test suite expects implementations to provide JSON fixture files that describe the implementation and its test vectors. For each DID method, NetDid generates these fixtures automatically via a CLI tool:

```
netdid-test-fixtures generate --method key --output ./fixtures/did-key.json
netdid-test-fixtures generate --method peer --output ./fixtures/did-peer.json
netdid-test-fixtures generate --method webvh --output ./fixtures/did-webvh.json
netdid-test-fixtures generate --method dht --output ./fixtures/did-dht.json
netdid-test-fixtures generate --method ethr --output ./fixtures/did-ethr.json
```

Each fixture file contains:

```json
{
  "name": "NetDid did:key",
  "implementation": "NetDid",
  "implementer": "Moises Jaramillo",
  "supportedContentTypes": ["application/did+ld+json"],
  "dids": [
    {
      "did": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
      "didDocument": {
        /* full DID Document */
      }
    }
  ],
  "didParameters": {
    "versionId": "...",
    "versionTime": "..."
  }
}
```

### 13.4 Test Harness Integration

The W3C test suite is a Node.js/Jest project. NetDid integrates with it in two ways:

**Approach 1: Fixture-based (primary)**

A .NET CLI tool (`NetDid.TestSuite.W3C.Cli`) generates the fixture JSON files that the W3C test suite consumes. This CLI is invoked in CI before running the Node.js test suite:

```yaml
# CI pipeline
- name: Generate W3C test fixtures
  run: dotnet run --project src/NetDid.TestSuite.W3C.Cli -- generate-all --output ./w3c-fixtures/

- name: Run W3C DID Test Suite
  run: |
    cd w3c-did-test-suite
    npm install
    npm test -- --implementations ../w3c-fixtures/
```

**Approach 2: Resolution endpoint (supplementary)**

For the `did-resolution` suite, NetDid can optionally run a lightweight HTTP server that the W3C test suite queries:

```csharp
// NetDid.TestSuite.W3C.Server — minimal Kestrel app
app.MapGet("/resolve/{did}", async (string did, IDidResolver resolver) =>
{
    var result = await resolver.ResolveAsync(did);
    return Results.Json(new
    {
        didDocument = result.DidDocument,
        didResolutionMetadata = result.ResolutionMetadata,
        didDocumentMetadata = result.DocumentMetadata
    });
});
```

### 13.5 Internal Conformance Test Mirror

In addition to running the external W3C suite, NetDid includes its own xUnit test project (`NetDid.Tests.W3CConformance`) that mirrors every normative statement from the DID Core spec as an explicit test case. This provides fast feedback during development without needing the Node.js toolchain:

```csharp
[Trait("Category", "W3CConformance")]
[Trait("Suite", "did-identifier")]
public class DidIdentifierConformanceTests
{
    [Theory]
    [InlineData("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")]
    [InlineData("did:peer:0z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH")]
    [InlineData("did:dht:i9xkp8ddcbcg8jwq54ox699wuzxyifsqx4jru45zodqu453ksz6y")]
    public void DID_method_name_must_be_ascii_lowercase(string did)
    {
        var method = DidParser.ExtractMethod(did);
        Assert.NotNull(method);
        Assert.All(method, c => Assert.True(char.IsAsciiLetterLower(c)));
    }

    [Theory]
    [InlineData("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")]
    public void DID_must_match_did_syntax(string did)
    {
        Assert.True(DidParser.IsValid(did));
    }

    // ... one test per normative statement
}

[Trait("Category", "W3CConformance")]
[Trait("Suite", "did-core-properties")]
public class DidCorePropertiesConformanceTests
{
    [Fact]
    public void DID_document_id_must_be_valid_did()
    {
        // For each method, create a DID, resolve it, verify doc.Id is valid
    }

    [Fact]
    public void Verification_method_id_must_be_valid_did_url()
    {
        // Verify every VM.Id in every resolved doc is a valid DID URL
    }

    [Fact]
    public void Context_must_include_did_v1_as_first_entry()
    {
        // Verify @context[0] == "https://www.w3.org/ns/did/v1"
    }

    [Fact]
    public void Service_id_must_be_valid_did_url()
    {
        // For methods that support services, verify service IDs
    }

    // ... comprehensive coverage of every DID Core §4-§5 normative statement
}

[Trait("Category", "W3CConformance")]
[Trait("Suite", "did-production")]
public class DidProductionConformanceTests
{
    [Fact]
    public void JSON_representation_must_include_context()
    {
        // Serialize a DID Document, verify "@context" is present in JSON
    }

    [Fact]
    public void All_property_names_must_be_strings()
    {
        // Parse the JSON, verify all keys are string type
    }

    [Fact]
    public void Serialized_document_must_be_valid_json()
    {
        // For each method, create → serialize → verify parseable as JSON
    }
}

[Trait("Category", "W3CConformance")]
[Trait("Suite", "did-consumption")]
public class DidConsumptionConformanceTests
{
    [Fact]
    public void Consumer_must_parse_valid_did_document_json()
    {
        // Feed known-good DID Document JSON → deserialize → verify all fields extracted
    }

    [Fact]
    public void Consumer_must_handle_unknown_properties_without_error()
    {
        // Add unknown properties to a DID Document JSON → deserialize → no exception
    }
}

[Trait("Category", "W3CConformance")]
[Trait("Suite", "did-resolution")]
public class DidResolutionConformanceTests
{
    [Fact]
    public async Task Resolution_must_return_did_resolution_metadata()
    {
        // Resolve a valid DID → result.ResolutionMetadata is not null
    }

    [Fact]
    public async Task Resolution_of_invalid_did_must_return_invalidDid_error()
    {
        var result = await _resolver.ResolveAsync("not-a-did");
        Assert.Equal("invalidDid", result.ResolutionMetadata.Error);
    }

    [Fact]
    public async Task Resolution_of_unknown_method_must_return_methodNotSupported()
    {
        var result = await _resolver.ResolveAsync("did:unknown:abc");
        Assert.Equal("methodNotSupported", result.ResolutionMetadata.Error);
    }

    [Fact]
    public async Task Resolution_of_deactivated_did_must_indicate_deactivation()
    {
        // Create a DID, deactivate it, resolve it, verify metadata.Deactivated == true
    }
}
```

### 13.6 CI Pipeline for Conformance

```yaml
name: W3C Conformance

on: [push, pull_request]

jobs:
  internal-conformance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-dotnet@v4
        with:
          dotnet-version: "10.0.x"
      - run: dotnet test --filter "Category=W3CConformance" --logger "trx"

  w3c-test-suite:
    runs-on: ubuntu-latest
    needs: internal-conformance
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-dotnet@v4
        with:
          dotnet-version: "10.0.x"
      - uses: actions/setup-node@v4
        with:
          node-version: "20"

      # Generate fixtures from NetDid
      - name: Build and generate fixtures
        run: |
          dotnet build src/NetDid.TestSuite.W3C.Cli/
          dotnet run --project src/NetDid.TestSuite.W3C.Cli -- generate-all \
            --output ./w3c-fixtures/

      # Clone and run the W3C test suite
      - name: Clone W3C DID Test Suite
        run: git clone https://github.com/w3c/did-test-suite.git

      # Install NetDid fixtures into the test suite
      - name: Install fixtures
        run: |
          cp ./w3c-fixtures/*.json did-test-suite/packages/did-core-test-server/suites/implementations/

      - name: Run W3C tests
        run: |
          cd did-test-suite
          npm install
          npm test

      - name: Upload test results
        uses: actions/upload-artifact@v4
        with:
          name: w3c-conformance-report
          path: did-test-suite/packages/did-core-test-server/reports/
```

### 13.7 Conformance Badges

Once all tests pass, the project README displays conformance badges:

```markdown
![W3C DID Identifier](https://img.shields.io/badge/W3C-did--identifier-green)
![W3C DID Core Properties](https://img.shields.io/badge/W3C-did--core--properties-green)
![W3C DID Production](https://img.shields.io/badge/W3C-did--production-green)
![W3C DID Consumption](https://img.shields.io/badge/W3C-did--consumption-green)
![W3C DID Resolution](https://img.shields.io/badge/W3C-did--resolution-green)
```

---

## 14. Integration with zcap-dotnet

### 14.1 Bridge Interface

The primary integration point between NetDid and zcap-dotnet is DID-based key resolution for ZCAP-LD signature verification:

```csharp
// In zcap-dotnet, a ZCAP invocation proof references a verificationMethod like:
// "verificationMethod": "did:key:z6Mkf...#z6Mkf..."
//
// NetDid provides the ability to resolve this to actual key material:

public interface IVerificationMethodResolver
{
    /// Resolve a DID URL to its verification method, extracting the public key.
    Task<ResolvedVerificationMethod?> ResolveVerificationMethodAsync(
        string didUrl, CancellationToken ct = default);
}

public sealed record ResolvedVerificationMethod
{
    public required string Id { get; init; }
    public required KeyType KeyType { get; init; }
    public required byte[] PublicKey { get; init; }
    public required string Controller { get; init; }
}
```

### 14.2 Usage in zcap-dotnet

```csharp
// zcap-dotnet verifying a ZCAP invocation:
var verificationMethodUrl = invocation.Proof.VerificationMethod;
var vm = await verificationMethodResolver.ResolveVerificationMethodAsync(verificationMethodUrl);

bool signatureValid = cryptoProvider.Verify(
    vm.KeyType,
    vm.PublicKey,
    invocation.SignedPayload,
    invocation.Proof.SignatureBytes);
```

### 14.3 Signing with DID Keys

For creating ZCAP invocations, zcap-dotnet needs to sign with a DID's key:

```csharp
// The caller provides their DID and key alias:
var did = "did:key:z6Mkf...";
var signature = await keyStore.SignAsync("my-signing-key", payload);

// The ZCAP invocation proof references:
// "verificationMethod": "did:key:z6Mkf...#z6Mkf..."
// "proofValue": "<base64url-signature>"
```

### 14.4 Dual-Identity Pattern in ZCAP Context

When using the dual-identity pattern (see Appendix A), zcap-dotnet signs ZCAPs with the did:key identity but verifiers can discover the TurtleShell PDS endpoint by resolving the discoverable identity (did:webvh, did:dht, or did:ethr) which references the same key material. The ZCAP itself is valid because the key is the same — the DID is just a different pointer to it.

---

## 15. Monorepo Structure

```
netdid/
├── Directory.Build.props              # Shared build config, TFM = net10.0
├── Directory.Packages.props           # Central package management
├── netdid.sln
├── .editorconfig
├── LICENSE                            # Apache 2.0
├── README.md
├── .github/
│   └── workflows/
│       ├── ci.yml                     # Build + test + W3C internal conformance
│       ├── w3c-conformance.yml        # Full W3C DID Test Suite run
│       └── release.yml                # NuGet publish
│
├── src/
│   ├── NetDid.Core/                   # Core abstractions, DID document model, key gen, crypto
│   │   ├── NetDid.Core.csproj
│   │   ├── IDidMethod.cs
│   │   ├── IDidResolver.cs
│   │   ├── DidMethodBase.cs
│   │   ├── Exceptions/
│   │   │   ├── NetDidException.cs
│   │   │   ├── InvalidDidException.cs
│   │   │   ├── MethodNotSupportedException.cs
│   │   │   ├── OperationNotSupportedException.cs
│   │   │   ├── DidResolutionException.cs
│   │   │   ├── CryptoVerificationException.cs
│   │   │   ├── LogChainValidationException.cs
│   │   │   └── EthereumInteractionException.cs
│   │   ├── IKeyGenerator.cs
│   │   ├── IKeyStore.cs
│   │   ├── ICryptoProvider.cs
│   │   ├── Model/
│   │   │   ├── DidDocument.cs
│   │   │   ├── VerificationMethod.cs
│   │   │   ├── Service.cs
│   │   │   ├── VerificationRelationshipEntry.cs
│   │   │   ├── DidResolutionResult.cs
│   │   │   ├── DidResolutionMetadata.cs
│   │   │   ├── DidDocumentMetadata.cs
│   │   │   ├── DidCreateResult.cs
│   │   │   ├── DidUpdateResult.cs
│   │   │   ├── DidDeactivateResult.cs
│   │   │   └── DidUrl.cs
│   │   ├── Crypto/
│   │   │   ├── DefaultCryptoProvider.cs
│   │   │   ├── DefaultKeyGenerator.cs
│   │   │   ├── KeyPair.cs
│   │   │   ├── KeyType.cs
│   │   │   ├── IBbsCryptoProvider.cs
│   │   │   ├── DefaultBbsCryptoProvider.cs
│   │   │   └── Jcs/
│   │   │       └── JsonCanonicalization.cs
│   │   ├── Encoding/
│   │   │   ├── MulticodecEncoder.cs
│   │   │   ├── MultibaseEncoder.cs
│   │   │   ├── Base58Btc.cs
│   │   │   ├── ZBase32.cs
│   │   │   └── Base64UrlNoPadding.cs
│   │   ├── Parsing/
│   │   │   └── DidParser.cs
│   │   ├── Serialization/
│   │   │   └── DidDocumentSerializer.cs
│   │   ├── Resolution/
│   │   │   ├── CompositeDidResolver.cs
│   │   │   ├── CachingDidResolver.cs
│   │   │   └── IVerificationMethodResolver.cs
│   │   ├── KeyStore/
│   │   │   ├── InMemoryKeyStore.cs
│   │   │   └── FileSystemKeyStore.cs
│   │   └── Jwk/
│   │       └── JwkConverter.cs
│   │
│   ├── NetDid.Method.Key/            # did:key implementation
│   │   ├── NetDid.Method.Key.csproj
│   │   ├── DidKeyMethod.cs
│   │   └── DidKeyCreateOptions.cs
│   │
│   ├── NetDid.Method.Peer/           # did:peer implementation
│   │   ├── NetDid.Method.Peer.csproj
│   │   ├── DidPeerMethod.cs
│   │   ├── DidPeerCreateOptions.cs
│   │   ├── Numalgo0Handler.cs
│   │   ├── Numalgo2Handler.cs
│   │   ├── Numalgo2ServiceEncoder.cs
│   │   └── Numalgo4Handler.cs
│   │
│   ├── NetDid.Method.WebVH/          # did:webvh implementation
│   │   ├── NetDid.Method.WebVH.csproj
│   │   ├── DidWebVhMethod.cs
│   │   ├── DidWebVhCreateOptions.cs
│   │   ├── DidWebVhUpdateOptions.cs
│   │   ├── DidWebVhResolveOptions.cs
│   │   ├── LogEntry.cs
│   │   ├── LogEntryParser.cs
│   │   ├── LogChainValidator.cs
│   │   ├── ScidGenerator.cs
│   │   ├── DataIntegrityProof.cs
│   │   ├── PreRotationManager.cs
│   │   ├── WitnessValidator.cs
│   │   └── IWebVhHttpClient.cs
│   │
│   ├── NetDid.Method.Dht/            # did:dht implementation
│   │   ├── NetDid.Method.Dht.csproj
│   │   ├── DidDhtMethod.cs
│   │   ├── DidDhtCreateOptions.cs
│   │   ├── DnsPacketEncoder.cs
│   │   ├── DnsPacketDecoder.cs
│   │   ├── Bep44Signer.cs
│   │   ├── ZBase32Encoder.cs
│   │   ├── IPkarrGatewayClient.cs
│   │   ├── DefaultPkarrGatewayClient.cs
│   │   └── IDhtRepublisher.cs
│   │
│   ├── NetDid.Method.Ethr/           # did:ethr implementation
│   │   ├── NetDid.Method.Ethr.csproj
│   │   ├── DidEthrMethod.cs
│   │   ├── DidEthrCreateOptions.cs
│   │   ├── DidEthrUpdateOptions.cs
│   │   ├── EthereumNetworkConfig.cs
│   │   ├── IEthereumRpcClient.cs
│   │   ├── DefaultEthereumRpcClient.cs
│   │   ├── Erc1056EventParser.cs
│   │   ├── Erc1056Abi.cs
│   │   ├── EthereumTransaction.cs
│   │   ├── Keccak256.cs
│   │   └── RlpEncoder.cs
│   │
│   ├── NetDid.Extensions.DependencyInjection/  # Optional Microsoft.Extensions.DI integration
│   │   ├── NetDid.Extensions.DependencyInjection.csproj
│   │   └── ServiceCollectionExtensions.cs
│   │
│   └── NetDid.TestSuite.W3C.Cli/     # CLI tool that generates W3C test fixtures
│       ├── NetDid.TestSuite.W3C.Cli.csproj
│       ├── Program.cs
│       ├── FixtureGenerator.cs
│       └── Commands/
│           ├── GenerateAllCommand.cs
│           └── GenerateMethodCommand.cs
│
├── tests/
│   ├── NetDid.Core.Tests/
│   │   ├── Parsing/
│   │   │   └── DidParserTests.cs
│   │   ├── Encoding/
│   │   │   ├── MulticodecEncoderTests.cs
│   │   │   ├── MultibaseEncoderTests.cs
│   │   │   ├── Base58BtcTests.cs
│   │   │   └── ZBase32Tests.cs
│   │   ├── Crypto/
│   │   │   ├── DefaultKeyGeneratorTests.cs
│   │   │   ├── DefaultCryptoProviderTests.cs
│   │   │   ├── DefaultBbsCryptoProviderTests.cs
│   │   │   └── JsonCanonicalizationTests.cs
│   │   ├── Model/
│   │   │   └── DidDocumentTests.cs
│   │   ├── Serialization/
│   │   │   └── DidDocumentSerializerTests.cs
│   │   └── Resolution/
│   │       ├── CompositeDidResolverTests.cs
│   │       └── CachingDidResolverTests.cs
│   │
│   ├── NetDid.Method.Key.Tests/
│   │   ├── DidKeyMethodTests.cs
│   │   ├── Ed25519KeyTests.cs
│   │   ├── P256KeyTests.cs
│   │   ├── P384KeyTests.cs
│   │   ├── Secp256k1KeyTests.cs
│   │   ├── X25519KeyTests.cs
│   │   ├── Bls12381G2KeyTests.cs
│   │   └── CrossMethodVectorTests.cs    # Known test vectors from did:key spec
│   │
│   ├── NetDid.Method.Peer.Tests/
│   │   ├── Numalgo0Tests.cs
│   │   ├── Numalgo2Tests.cs
│   │   ├── Numalgo2ServiceEncoderTests.cs
│   │   ├── Numalgo4Tests.cs
│   │   └── PeerInteropVectorTests.cs    # Test vectors from DIF spec
│   │
│   ├── NetDid.Method.WebVH.Tests/
│   │   ├── DidWebVhMethodTests.cs
│   │   ├── LogChainValidatorTests.cs
│   │   ├── ScidGeneratorTests.cs
│   │   ├── PreRotationManagerTests.cs
│   │   ├── WitnessValidatorTests.cs
│   │   └── IntegrationTests/
│   │       └── DidWebVhRoundTripTests.cs
│   │
│   ├── NetDid.Method.Dht.Tests/
│   │   ├── DidDhtMethodTests.cs
│   │   ├── DnsPacketEncoderTests.cs
│   │   ├── DnsPacketDecoderTests.cs
│   │   ├── Bep44SignerTests.cs
│   │   ├── ZBase32EncoderTests.cs
│   │   └── IntegrationTests/
│   │       └── PkarrGatewayIntegrationTests.cs  # Against real gateway
│   │
│   ├── NetDid.Method.Ethr.Tests/
│   │   ├── DidEthrMethodTests.cs
│   │   ├── Erc1056EventParserTests.cs
│   │   ├── EthereumAddressTests.cs
│   │   ├── Keccak256Tests.cs
│   │   ├── RlpEncoderTests.cs
│   │   └── IntegrationTests/
│   │       └── SepoliaIntegrationTests.cs       # Against Sepolia testnet
│   │
│   ├── NetDid.Tests.W3CConformance/             # Internal mirror of W3C test suite
│   │   ├── DidIdentifierConformanceTests.cs
│   │   ├── DidCorePropertiesConformanceTests.cs
│   │   ├── DidProductionConformanceTests.cs
│   │   ├── DidConsumptionConformanceTests.cs
│   │   └── DidResolutionConformanceTests.cs
│   │
│   └── NetDid.Integration.Tests/
│       ├── DualIdentityPatternTests.cs
│       ├── ZcapDotnetBridgeTests.cs
│       └── AllMethodsRoundTripTests.cs
│
└── docs/
    ├── getting-started.md
    ├── did-key-guide.md
    ├── did-peer-guide.md
    ├── did-webvh-guide.md
    ├── did-dht-guide.md
    ├── did-ethr-guide.md
    ├── dual-identity-pattern.md
    ├── key-management-guide.md
    └── w3c-conformance.md
```

---

## 16. Testing Strategy

### 16.1 Test Pyramid

```
              ┌──────────────────┐
              │  W3C Conformance │  ← External test suite (Node.js)
              │  (authoritative) │
             ┌┴──────────────────┴┐
             │  Integration Tests  │  ← Real networks (Pkarr, Sepolia, HTTP)
             │                     │
            ┌┴─────────────────────┴┐
            │  W3C Conformance       │  ← Internal xUnit mirror
            │  (internal, fast)      │
           ┌┴───────────────────────┴┐
           │   Unit Tests             │  ← Every class, every edge case
           │   (many, fast)           │
           └──────────────────────────┘
```

### 16.2 Test Infrastructure

| Tool                 | Usage                                                                      |
| -------------------- | -------------------------------------------------------------------------- |
| **xUnit**            | Test framework                                                             |
| **FluentAssertions** | Readable assertions                                                        |
| **NSubstitute**      | Mocking `IEthereumRpcClient`, `IPkarrGatewayClient`, `IWebVhHttpClient`    |
| **Verify**           | Snapshot testing for DID Document serialization (catch unintended changes) |
| **Bogus**            | Generate random test data                                                  |
| **WireMock.Net**     | Mock HTTP servers for Pkarr gateways and webvh endpoints                   |
| **Testcontainers**   | Ganache/Hardhat container for did:ethr integration tests                   |

### 16.3 Test Categories

```csharp
[Trait("Category", "Unit")]              // No I/O, no Docker, no network
[Trait("Category", "Integration")]       // Requires Docker or network
[Trait("Category", "W3CConformance")]    // Internal W3C conformance tests
[Trait("Category", "W3CExternal")]       // Marks tests driven by external W3C suite
[Trait("Category", "Network")]           // Requires real network (Sepolia, Pkarr gateway)
```

### 16.4 Key Test Scenarios

**Encoding/Decoding Tests:**

- Multicodec round-trip for all 7 key types (Ed25519, X25519, P-256, P-384, secp256k1, BLS12-381 G1, BLS12-381 G2)
- Multibase round-trip for base58btc, base64url, base32lower
- z-base-32 encoding matches known test vectors
- Known test vectors from each DID method specification

**did:key Tests:**

- Create with each key type (Ed25519, X25519, P-256, P-384, secp256k1, BLS12-381 G2) → DID string is correct
- Resolve → DID Document has correct structure
- Ed25519 → derives X25519 key agreement correctly
- BLS12-381 G2 → verification relationships are assertionMethod + capabilityInvocation (NOT authentication)
- BBS+ round-trip: create did:key with BLS12-381 G2, sign messages, derive selective disclosure proof, verify proof
- Known test vectors from W3C CCG spec
- Invalid multibase string → resolution error

**did:peer Tests:**

- Numalgo 0 equivalence with did:key
- Numalgo 2 round-trip: create with keys + services → resolve → keys and services match
- Numalgo 2 service abbreviation encoding
- Numalgo 4 short-form hash matches long-form content
- Numalgo 4 short-form resolution without long-form → notFound
- Test vectors from DIF spec

**did:webvh Tests:**

- Genesis log entry creation and SCID derivation
- Log chain validation: valid chain passes, tampered entry fails
- Pre-rotation: valid rotation succeeds, unauthorized key rejected
- Witness validation: threshold met passes, unmet fails
- did:web backwards compatibility: DID conversion is correct
- Update: new entry chains correctly, proof is valid
- Deactivation: resolved document shows deactivated
- Version resolution: specific version and version-at-time

**did:dht Tests:**

- DNS packet encoding round-trip: encode → decode → identical DID Document
- BEP44 signing and verification
- z-base-32 encoding of Identity Key matches DID suffix
- Pkarr gateway publish and resolve (integration, against real gateway)
- Deactivation via empty record set
- Type indexing

**did:ethr Tests:**

- Address derivation from secp256k1 public key matches known Ethereum addresses
- Default DID Document for a new address (no on-chain history)
- Event replay: simulated DIDOwnerChanged, DIDDelegateChanged, DIDAttributeChanged events → correct DID Document
- Service endpoint attribute encoding: `did/svc/TurtleShellPds` → parsed correctly
- Delegate expiration: expired delegates excluded from document
- Deactivation via owner change to null address
- Multi-network: same address on mainnet vs. sepolia produces distinct DIDs
- RLP encoding for transaction construction
- Meta-transaction signature generation

**Cross-Method Tests:**

- Same Ed25519 key produces consistent DID Documents across did:key, did:peer:0, did:dht, did:webvh
- CompositeDidResolver routes to correct method
- CachingDidResolver caches and expires correctly
- VerificationMethodResolver extracts correct key material from any method

---

## 17. Implementation Phases

### Phase 1: Core Foundation (Week 1-2)

| Item | Description                                                                         |
| ---- | ----------------------------------------------------------------------------------- |
| 1.1  | Monorepo scaffolding: solution, projects, build props, CI pipeline                  |
| 1.2  | `NetDid.Core`: DID Document model, serialization, DidParser                         |
| 1.3  | Cryptographic primitives: `IKeyGenerator`, `ICryptoProvider` with Ed25519, P-256, P-384, and secp256k1 |
| 1.3b | BBS+ cryptographic primitives: `IBbsCryptoProvider` with BLS12-381 G1/G2, multi-message sign, derive proof, verify proof |
| 1.3c | JCS (JSON Canonicalization Scheme, RFC 8785) implementation for Data Integrity Proofs |
| 1.4  | Multicodec and Multibase encoding/decoding                                          |
| 1.5  | `IKeyStore` interface + `InMemoryKeyStore`                                          |
| 1.6  | JWK conversion utilities                                                            |
| 1.7  | `CompositeDidResolver`, `CachingDidResolver`                                        |
| 1.8  | Unit tests for all Core code                                                        |

**Deliverable**: Core library compiles. Key generation, encoding, and DID Document model fully tested.

### Phase 2: did:key + did:peer (Week 3-4)

| Item | Description                                                              |
| ---- | ------------------------------------------------------------------------ |
| 2.1  | `DidKeyMethod`: create and resolve for Ed25519, X25519, P-256, P-384, secp256k1, BLS12-381 G2 |
| 2.2  | X25519 derivation from Ed25519                                           |
| 2.3  | W3C CCG did:key test vectors passing                                     |
| 2.4  | `DidPeerMethod`: numalgo 0, numalgo 2, numalgo 4                         |
| 2.5  | Numalgo 2 service abbreviation encoder/decoder                           |
| 2.6  | DIF did:peer test vectors passing                                        |
| 2.7  | W3C conformance tests (internal) for both methods                        |
| 2.8  | W3C DID Test Suite fixture generation for did:key and did:peer           |

**Deliverable**: did:key and did:peer fully working. First W3C conformance run passes.

### Phase 3: did:webvh (Week 5-7)

| Item | Description                                                     |
| ---- | --------------------------------------------------------------- |
| 3.1  | Log entry model and JSON Lines parser                           |
| 3.2  | SCID generation from genesis entry                              |
| 3.3  | Data Integrity Proof creation (eddsa-jcs-2022) and verification |
| 3.4  | Hash chain validation across log entries                        |
| 3.5  | Create: genesis log entry generation                            |
| 3.6  | Resolve: fetch log, validate chain, return document             |
| 3.7  | Update: append log entry with chaining                          |
| 3.8  | Pre-rotation manager                                            |
| 3.9  | Witness validation                                              |
| 3.10 | Deactivation                                                    |
| 3.11 | did:web backwards compatibility conversion                      |
| 3.12 | `IWebVhHttpClient` with mock for testing                        |
| 3.13 | W3C conformance tests                                           |

**Deliverable**: did:webvh full CRUD operational. Log chain validation hardened.

### Phase 4: did:dht (Week 8-10)

| Item | Description                                                          |
| ---- | -------------------------------------------------------------------- |
| 4.1  | z-base-32 encoder/decoder                                            |
| 4.2  | DNS packet encoder: DID Document → DNS TXT records → RFC 1035 packet |
| 4.3  | DNS packet decoder: reverse                                          |
| 4.4  | BEP44 mutable item signing (Ed25519 over bencoded value)             |
| 4.5  | Pkarr gateway client: HTTP PUT/GET                                   |
| 4.6  | Create: generate Identity Key, encode, sign, publish                 |
| 4.7  | Resolve: fetch from gateway, verify, decode                          |
| 4.8  | Update and deactivation                                              |
| 4.9  | Type indexing support                                                |
| 4.10 | Republisher utility                                                  |
| 4.11 | Integration tests against public Pkarr gateway                       |
| 4.12 | W3C conformance tests                                                |

**Deliverable**: did:dht operational. Publishing and resolving via real gateway verified.

### Phase 5: did:ethr (Week 11-14)

| Item | Description                                                                      |
| ---- | -------------------------------------------------------------------------------- |
| 5.1  | secp256k1 key support (generate, sign, recover)                                  |
| 5.2  | Keccak-256 hash implementation                                                   |
| 5.3  | Ethereum address derivation from secp256k1 public key                            |
| 5.4  | RLP encoding for transaction construction                                        |
| 5.5  | ERC-1056 ABI encoding: function selectors, parameter encoding                    |
| 5.6  | `IEthereumRpcClient` interface and default HTTP JSON-RPC implementation          |
| 5.7  | Event log parser: `DIDOwnerChanged`, `DIDDelegateChanged`, `DIDAttributeChanged` |
| 5.8  | Create: key generation + address derivation (no on-chain tx needed)              |
| 5.9  | Resolve: query events, replay to build DID Document                              |
| 5.10 | Update: `setAttribute` for services, `addDelegate` for keys, `changeOwner`       |
| 5.11 | Meta-transaction support (EIP-712 style signed messages)                         |
| 5.12 | Deactivation: change owner to null address                                       |
| 5.13 | Multi-network configuration and routing                                          |
| 5.14 | Integration tests against Sepolia testnet (or Hardhat in Docker)                 |
| 5.15 | W3C conformance tests                                                            |

**Deliverable**: did:ethr full CRUD on any EVM network. Sepolia integration tests passing.

### Phase 6: W3C Test Suite & Polish (Week 15-16)

| Item | Description                                                     |
| ---- | --------------------------------------------------------------- |
| 6.1  | W3C DID Test Suite CLI fixture generator for all 5 methods      |
| 6.2  | Optional resolution HTTP endpoint for W3C did-resolution suite  |
| 6.3  | Full W3C DID Test Suite run in CI — all 5 suites, all 5 methods |
| 6.4  | Fix any conformance failures                                    |
| 6.5  | `NetDid.Extensions.DependencyInjection` package                 |
| 6.6  | zcap-dotnet bridge: `IVerificationMethodResolver` integration   |
| 6.7  | README, getting-started docs, per-method guides                 |
| 6.8  | NuGet packaging and publish pipeline                            |
| 6.9  | Dual-identity pattern documentation and example                 |
| 6.10 | Performance benchmarks for resolution (each method)             |

**Deliverable**: All W3C tests green. NuGet packages published. zcap-dotnet integration verified.

---

## Appendix A: Dual-Identity Design Pattern

### A.1 Problem Statement

Some DID methods (notably `did:key`) are excellent for cryptographic operations — signing ZCAP invocations, issuing credentials, authenticating — because they are simple, offline-capable, and have no dependency on external infrastructure. However, `did:key` cannot carry service endpoints because the DID Document is algorithmically derived from the key alone. There is no place to advertise "here is my TurtleShell PDS at https://node1.example.com."

Conversely, methods like `did:webvh`, `did:dht`, and `did:ethr` support rich DID Documents with service endpoints, making them ideal for discovery. But they carry operational overhead: web hosting, DHT republishing, or on-chain gas costs.

### A.2 Solution: Pair a Signing Identity with a Discoverable Identity

Use **two DIDs that share the same underlying key material** but serve different purposes:

```
┌──────────────────────────────────────────────────────────────┐
│                        Alice's Identity                       │
│                                                               │
│  ┌─────────────────────────────┐                              │
│  │  Signing Identity           │                              │
│  │  did:key:z6Mkf...          │  ← Used for:                 │
│  │                             │    - ZCAP-LD invocation       │
│  │  (Ed25519 public key)       │      signing                  │
│  │                             │    - VC issuance              │
│  │  • Immutable                │    - Authentication            │
│  │  • No infrastructure        │    - Root ZCAP binding        │
│  │  • Offline-capable          │                              │
│  └─────────────────────────────┘                              │
│                 │                                              │
│                 │ Same Ed25519 key                             │
│                 │                                              │
│  ┌──────────────▼──────────────┐                              │
│  │  Discoverable Identity      │                              │
│  │  did:webvh:Qm...:alice.com │  ← Used for:                 │
│  │    OR                       │    - Service endpoint          │
│  │  did:dht:i9xkp8...         │      discovery                │
│  │    OR                       │    - TurtleShell PDS           │
│  │  did:ethr:0x1:0xabc...     │      advertisement            │
│  │                             │    - Replication peer          │
│  │  • Has service endpoints    │      discovery                │
│  │  • Updatable                │    - Public profile           │
│  │  • alsoKnownAs links to     │                              │
│  │    the did:key              │                              │
│  └─────────────────────────────┘                              │
└──────────────────────────────────────────────────────────────┘
```

### A.3 How It Works

**Step 1: Generate a key pair once.**

```csharp
var keyGen = new DefaultKeyGenerator();
var keyPair = keyGen.Generate(KeyType.Ed25519);
```

**Step 2: Create the signing identity (did:key).**

```csharp
var didKeyMethod = new DidKeyMethod(keyGen);
var signingIdentity = await didKeyMethod.CreateAsync(new DidKeyCreateOptions
{
    KeyType = KeyType.Ed25519,
    // The key pair is provided or generated internally
});
// signingIdentity.Did = "did:key:z6Mkf..."
```

**Step 3: Create the discoverable identity using the SAME key.**

For did:webvh:

```csharp
var didWebVhMethod = new DidWebVhMethod(httpClient, cryptoProvider);
var discoverableIdentity = await didWebVhMethod.CreateAsync(new DidWebVhCreateOptions
{
    Domain = "alice.example.com",
    UpdateKeyPair = keyPair,  // Same Ed25519 key
    Services = new[]
    {
        new Service
        {
            Id = "#pds-1",
            Type = "TurtleShellPds",
            ServiceEndpoint = "https://node1.turtleshell.id/instances/abc123"
        }
    },
    AdditionalVerificationMethods = new[] { /* optionally add the did:key reference */ }
});
```

For did:dht:

```csharp
var didDhtMethod = new DidDhtMethod(pkarrClient, cryptoProvider);
var discoverableIdentity = await didDhtMethod.CreateAsync(new DidDhtCreateOptions
{
    IdentityKeyPair = keyPair,  // Same Ed25519 key — it becomes the DID suffix
    Services = new[]
    {
        new Service
        {
            Id = "#pds-1",
            Type = "TurtleShellPds",
            ServiceEndpoint = "https://node1.turtleshell.id/instances/abc123"
        }
    }
});
```

**Step 4: Link them via `alsoKnownAs`.**

The discoverable identity's DID Document includes:

```json
{
  "id": "did:webvh:Qm...:alice.example.com",
  "alsoKnownAs": ["did:key:z6Mkf..."],
  "verificationMethod": [
    {
      "id": "#key-1",
      "type": "Multikey",
      "controller": "did:webvh:Qm...:alice.example.com",
      "publicKeyMultibase": "z6Mkf..."
    }
  ],
  "service": [
    {
      "id": "#pds-1",
      "type": "TurtleShellPds",
      "serviceEndpoint": "https://node1.turtleshell.id/instances/abc123"
    }
  ]
}
```

### A.4 Verification Flow

When a verifier receives a ZCAP invocation signed by `did:key:z6Mkf...#z6Mkf...`:

1. Resolve `did:key:z6Mkf...` → get the Ed25519 public key.
2. Verify the ZCAP signature. ✅
3. If the verifier needs to discover the owner's PDS (for replication, for example), they look up the `alsoKnownAs` relationship:
   - Check if there's a known `did:webvh` or `did:dht` or `did:ethr` that claims `alsoKnownAs: ["did:key:z6Mkf..."]`.
   - Resolve that discoverable identity → find the `TurtleShellPds` service endpoint.
4. Verify the discoverable identity's DID Document contains the same public key as the did:key. This proves the same entity controls both identities.

### A.5 Security Considerations

- **Key equivalence verification is REQUIRED**: The verifier MUST confirm that the discoverable identity's DID Document contains a verification method with the same public key as the signing did:key. The `alsoKnownAs` claim alone is insufficient — anyone could claim it.
- **Bidirectional linking is RECOMMENDED**: Ideally both documents reference each other, but since did:key documents are algorithmic, the link from discoverable → did:key (via `alsoKnownAs`) combined with key equivalence is sufficient.
- **The signing identity (did:key) is the source of authority**: ZCAPs are bound to it, not to the discoverable identity. The discoverable identity is an index, not an authority.

### A.6 NetDid Helper

NetDid provides a utility for establishing and verifying dual-identity relationships:

```csharp
public interface IDualIdentityManager
{
    /// Verify that two DIDs share the same key material.
    Task<DualIdentityVerification> VerifyKeyEquivalenceAsync(
        string signingDid, string discoverableDid, CancellationToken ct = default);

    /// Extract service endpoints from a discoverable identity linked to a signing identity.
    Task<IReadOnlyList<Service>> DiscoverServicesAsync(
        string signingDid, string discoverableDid, string? serviceType = null, CancellationToken ct = default);
}

public sealed record DualIdentityVerification
{
    public required bool KeysMatch { get; init; }
    public required bool AlsoKnownAsLinkPresent { get; init; }
    public required string? MatchedKeyId { get; init; }
}
```

---

## Appendix B: Specification References

| Specification                    | URL                                                                                            | Version | Status             |
| -------------------------------- | ---------------------------------------------------------------------------------------------- | ------- | ------------------ |
| W3C DID Core 1.0                 | https://www.w3.org/TR/did-core/                                                                | 1.0     | W3C Recommendation |
| W3C DID Specification Registries | https://www.w3.org/TR/did-spec-registries/                                                     | 1.0     | W3C Note           |
| W3C DID Test Suite               | https://github.com/w3c/did-test-suite                                                          | —       | W3C WG Internal    |
| W3C DID Implementation Report    | https://w3c.github.io/did-test-suite/                                                          | —       | Auto-generated     |
| did:key Method                   | https://w3c-ccg.github.io/did-method-key/                                                      | —       | W3C CCG Final      |
| did:key Test Suite               | https://w3c-ccg.github.io/did-key-test-suite/                                                  | —       | CCG Report         |
| did:peer Method                  | https://identity.foundation/peer-did-method-spec/                                              | 2.0     | DIF Spec           |
| did:webvh Method                 | https://identity.foundation/didwebvh/                                                          | 1.0     | DIF Recommended    |
| did:webvh Info Site              | https://didwebvh.info/                                                                         | —       | Info/Tutorials     |
| did:dht Method                   | https://did-dht.com/                                                                           | —       | DIF Spec           |
| did:dht Registry                 | https://did-dht.com/registry/                                                                  | —       | DIF Registry       |
| ERC-1056 (did:ethr)              | https://eips.ethereum.org/EIPS/eip-1056                                                        | —       | ERC Draft          |
| did:ethr Resolver Spec           | https://github.com/decentralized-identity/ethr-did-resolver/blob/master/doc/did-method-spec.md | —       | DIF                |
| EthereumDIDRegistry Contract     | https://github.com/uport-project/ethr-did-registry                                             | —       | uPort              |
| Pkarr                            | https://github.com/pubky/pkarr                                                                 | —       | Open Source        |
| BEP44 (Mutable Items)            | https://www.bittorrent.org/beps/bep_0044.html                                                  | —       | BEP                |
| Multicodec                       | https://github.com/multiformats/multicodec                                                     | —       | Multiformats       |
| Multibase                        | https://github.com/multiformats/multibase                                                      | —       | Multiformats       |
| Data Integrity (eddsa-jcs-2022)  | https://www.w3.org/TR/vc-di-eddsa/                                                             | —       | W3C CR             |
| BBS Signature Scheme             | https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-07.html                         | -07     | IETF CFRG Draft    |
| Data Integrity BBS Cryptosuites  | https://www.w3.org/TR/vc-di-bbs/                                                               | —       | W3C CR             |
| RFC 8785 (JCS)                   | https://tools.ietf.org/html/rfc8785                                                            | —       | IETF Proposed Std  |
| RFC 1035 (DNS)                   | https://tools.ietf.org/html/rfc1035                                                            | —       | IETF Standard      |

---

## Appendix C: Glossary

| Term                          | Definition                                                                                                                                           |
| ----------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| **DID**                       | Decentralized Identifier — a URI that resolves to a DID Document without a centralized registry.                                                     |
| **DID Document**              | A JSON-LD document containing public keys, service endpoints, and metadata associated with a DID.                                                    |
| **DID Method**                | A specification defining how to create, resolve, update, and deactivate a specific type of DID (e.g., did:key, did:ethr).                            |
| **DID URL**                   | A DID plus optional path, query, and/or fragment components. Used to reference specific elements within a DID Document.                              |
| **Verification Method**       | A public key or other mechanism in a DID Document used to verify digital signatures or perform key agreement.                                        |
| **Verification Relationship** | The purpose a verification method serves: authentication, assertion, key agreement, capability invocation, or capability delegation.                 |
| **SCID**                      | Self-Certifying Identifier — used in did:webvh to cryptographically bind the DID to its genesis state.                                               |
| **Identity Key**              | In did:dht, the Ed25519 key pair whose public key is the DID suffix. Signs all DHT records.                                                          |
| **Pkarr**                     | Public Key Addressable Resource Records — an HTTP relay layer over the BitTorrent Mainline DHT for storing DNS records keyed by Ed25519 public keys. |
| **BEP44**                     | BitTorrent Enhancement Proposal 44 — defines mutable and immutable items in the Mainline DHT, used by did:dht for signed DID record storage.         |
| **ERC-1056**                  | Ethereum Improvement Proposal defining the `EthereumDIDRegistry` smart contract for lightweight identity management.                                 |
| **Multicodec**                | A self-describing codec prefix system. Prepended to raw key bytes to indicate the key type.                                                          |
| **Multibase**                 | A self-describing base encoding. The first character indicates the encoding (e.g., `z` = base58btc).                                                 |
| **Numalgo**                   | "Numeric algorithm" — the variant selector in did:peer (0, 2, or 4), each defining a different generation and resolution algorithm.                  |
| **ZCAP-LD**                   | Authorization Capabilities for Linked Data — an object-capability security model where capabilities are cryptographically delegatable tokens.        |
| **BBS+ / BBS Signatures**     | A pairing-based signature scheme over BLS12-381 that supports multi-message signing, selective disclosure (revealing only chosen attributes), and zero-knowledge proof derivation. Standardized as IETF draft-irtf-cfrg-bbs-signatures. |
| **BLS12-381**                 | A pairing-friendly elliptic curve with two groups (G1, G2) and a target group (GT). G2 public keys (96 bytes) are used for BBS+ signing. Named after Barreto-Lynn-Scott with a 381-bit field. |
| **Selective Disclosure**      | The ability for a credential holder to present only specific attributes from a signed credential without revealing the full credential, enabled by BBS+ proof derivation. |
| **JCS**                       | JSON Canonicalization Scheme (RFC 8785) — deterministic serialization of JSON for signing. Required by the `eddsa-jcs-2022` and `bbs-2023` Data Integrity cryptosuites. |
| **Dual-Identity Pattern**     | Using a did:key (for signing) paired with a discoverable DID (for service endpoints), linked by shared key material and `alsoKnownAs`.               |
| **HLC**                       | Hybrid Logical Clock — used in the TurtleShell PDS for causal ordering across replicated nodes.                                                      |
| **CRDT**                      | Conflict-free Replicated Data Type — data structures that can be replicated across nodes and merged without coordination.                            |

---
