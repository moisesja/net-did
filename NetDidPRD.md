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
8. [DID Method: did:ethr](#8-did-method-didethr)
9. [DID Document Model](#9-did-document-model)
10. [Resolver Architecture](#10-resolver-architecture)
11. [Pluggable Key Management](#11-pluggable-key-management)
12. [W3C DID Test Suite Conformance](#12-w3c-did-test-suite-conformance)
13. [Integration with zcap-dotnet](#13-integration-with-zcap-dotnet)
14. [Monorepo Structure](#14-monorepo-structure)
15. [Testing Strategy](#15-testing-strategy)
16. [Implementation Phases](#16-implementation-phases)
17. [Appendix A: Dual-Identity Design Pattern](#appendix-a-dual-identity-design-pattern)
18. [Appendix B: Specification References](#appendix-b-specification-references)
19. [Appendix C: Glossary](#appendix-c-glossary)

---

## 1. Vision & Goals

### 1.1 Purpose

NetDid is an open-source .NET 10 library that provides a unified, specification-compliant interface for creating, resolving, updating, and deactivating Decentralized Identifiers. Currently implemented: `did:key` and `did:peer`. Planned: `did:webvh` and `did:ethr`.

The library generates cryptographic keys using well-tested elliptic curve algorithms but delegates key storage and lifecycle management to the consuming application through a pluggable `IKeyStore` interface. This separation ensures that NetDid remains focused on DID operations while allowing developers to integrate their own HSM, vault, or file-based key management solution.

> **Note**: W3C DID Test Suite conformance testing is planned but not yet implemented. The current test suite validates DID document structure, serialization, and method-specific behavior through unit tests.

### 1.2 Design Goals

| Goal                            | Description                                                                                                                                                                                                        |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Spec Compliance**             | 100% compliant with W3C DID Core 1.0 and each method's published specification. No shortcuts, no partial implementations.                                                                                          |
| **W3C Test Suite Pass** _(planned)_ | Every DID method implementation should pass the W3C DID Test Suite conformance categories. Not yet integrated — tracked as a future milestone.                                                                   |
| **Key Generation, Not Storage** | Generate and restore keys across Ed25519, secp256k1, P-256, P-384, X25519, and BLS12-381 (G1/G2). Storage is the caller's responsibility via `IKeyStore`.                                                          |
| **Pluggable Everything**        | Key stores, HTTP clients, Ethereum RPC providers — all injectable.                                                                                                                                                 |
| **Zero Opinions on Frameworks** | No dependency on ASP.NET, no DI container requirement. Pure library with optional DI extensions.                                                                                                                   |
| **Test-Driven**                 | Every public API surface covered by unit tests. Integration tests against real networks (testnets) planned for `did:webvh` and `did:ethr`.                                                                        |
| **zcap-dotnet Compatible**      | Designed to be consumed directly by the zcap-dotnet library for ZCAP-LD signing and verification using DID-resolved keys.                                                                                          |

### 1.3 Non-Goals

- **Key vault implementation**: NetDid does NOT ship a production key store. It ships an `InMemoryKeyStore` for testing and development only.
- **Verifiable Credentials**: VC issuance/verification is out of scope. NetDid provides the identity layer that VC libraries build on.
- **DID method registration**: NetDid does not run a DID registrar service. It provides the programmatic building blocks.
- **Wallet UI**: No UI components.

---

## 2. Scope & DID Methods

### 2.1 Supported Methods Summary

| Method        | Status          | Spec Status            | Create | Resolve | Update         | Deactivate     | Service Endpoints | Key Types                                              |
| ------------- | --------------- | ---------------------- | ------ | ------- | -------------- | -------------- | ----------------- | ------------------------------------------------------ |
| **did:key**   | ✅ Implemented  | W3C CCG Final          | ✅     | ✅      | ❌ (immutable) | ❌ (immutable) | ❌                | Ed25519, P-256, P-384, secp256k1, X25519, BLS12-381 G2 |
| **did:peer**  | ✅ Implemented  | DIF v2 (numalgo 0,2,4) | ✅     | ✅      | ❌ (static)    | ❌             | ✅ (numalgo 2,4)  | Ed25519, X25519                                        |
| **did:webvh** | ✅ Implemented | DIF v1.0               | ✅     | ✅      | ✅             | ✅             | ✅                | Ed25519 (required), P-256 (optional)                   |
| **did:ethr**  | 🔲 Planned     | ERC-1056 / DIF         | ✅     | ✅      | ✅             | ✅             | ✅                | secp256k1 (primary), Ed25519 (delegate)                |

### 2.2 CRUD Operations Per Method

Each method implements the standard DID CRUD lifecycle, but the mechanics differ significantly:

**did:key** — Create-only. The DID _is_ the key. No network interaction. Resolution is purely algorithmic: decode the multicodec-prefixed key from the DID string, expand into a DID Document deterministically. The DID Document is always derived, never stored.

**did:peer** — Create and resolve locally. Numalgo 0 is equivalent to did:key. Numalgo 2 encodes verification methods and services directly in the DID string using purpose-prefixed multibase keys and JSON-encoded service blocks. Numalgo 4 hashes a full input document into a short-form DID with a long-form for initial exchange. No network interaction for any numalgo.

**did:webvh** — Full CRUD. "did:web + Verifiable History." Each update appends to a JSON Lines log file (`did.jsonl`) hosted at a web URL. The log is a cryptographically chained sequence of DID Document versions, anchored by a Self-Certifying Identifier (SCID) derived from the initial state. Resolution fetches the log and validates the entire chain. The DID can also be consumed as a plain `did:web` by legacy resolvers (backwards compatible). Supports pre-rotation keys, witnesses (did:key DIDs that co-sign updates), and watchers. Every version links back to its predecessor via a hash chain. Update authorization keys MUST rotate on every version when pre-rotation is active.

**did:ethr** — Full CRUD. Based on the ERC-1056 `EthereumDIDRegistry` smart contract deployed at a well-known address. Any Ethereum address is automatically a valid DID with no registration needed (identity creation is free). Updates are recorded as on-chain events: `changeOwner` for ownership transfer, `setAttribute` for adding service endpoints and additional keys, `addDelegate`/`revokeDelegate` for time-limited delegate keys. Resolution replays contract events (via `eth_getLogs`) to reconstruct the DID Document. Supports meta-transactions (signed by the identity key, submitted by a third-party relayer). The network identifier is part of the DID: `did:ethr:0x1:0xabc...` for mainnet, `did:ethr:sepolia:0xabc...` for testnet. Pluggable RPC endpoint means any EVM chain that an ERC-1056 registry deployed will work.

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
│  │  VerificationRelationshipEntry, Did, DidUrl             │  │
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
│  │  ISigner, IKeyStore (pluggable), KeyPair, KeyType enum   │  │
│  └─────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│                   Method Implementations                      │
│                                                               │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐                   │
│  │ NetDid.   │ │ NetDid.   │ │ NetDid.   │                   │
│  │ Method.   │ │ Method.   │ │ Method.   │                   │
│  │ Key       │ │ Peer      │ │ WebVH     │                   │
│  └───────────┘ └───────────┘ └───────────┘                   │
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
    /// Method name (e.g., "key", "peer", "webvh", "ethr")
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
    public required Did Did { get; init; }
    public DidDocumentMetadata? Metadata { get; init; }

    /// Method-specific artifacts (e.g., did.jsonl content for webvh, tx hash for ethr)
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

/// Base class for resolution options. Method-specific option types inherit from this.
public record DidResolutionOptions
{
    /// The preferred Media Type for the DID Document representation.
    /// Supported values:
    ///   - "application/did+ld+json" (default) — JSON-LD representation, includes @context
    ///   - "application/did+json"              — plain JSON representation, @context omitted
    /// Affects both the serialized output and the contentType in DidResolutionMetadata.
    public string Accept { get; init; } = "application/did+ld+json";

    /// W3C DID Core §7.2 query parameters — passed through by the dereferencer.
    /// Methods that do not support versioned resolution ignore these.
    public string? VersionId { get; init; }
    public string? VersionTime { get; init; }
}

/// Base class for create options. Each DID method defines its own derived type.
public abstract record DidCreateOptions;

/// Base class for update options. Each DID method defines its own derived type.
public abstract record DidUpdateOptions;

/// Base class for deactivate options. Each DID method defines its own derived type.
public abstract record DidDeactivateOptions;
```

### 3.4 Architectural Patterns

| Pattern             | Usage                                                                                                                        |
| ------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| **Strategy**        | Each DID method is an `IDidMethod` strategy. The `DidMethodRegistry` selects the correct one based on the DID string prefix. |
| **Factory**         | `IKeyGenerator` implementations are factories for key pairs per curve type.                                                  |
| **Adapter**         | External dependencies (HTTP for did:webvh log fetch, Ethereum JSON-RPC) are wrapped behind interfaces for testability.       |
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

| Key Type         | Algorithm      | Multicodec Prefix                   | Usage                                                                                          |
| ---------------- | -------------- | ----------------------------------- | ---------------------------------------------------------------------------------------------- |
| **Ed25519**      | EdDSA          | `0xed` (public), `0x8026` (private) | Signing, verification. Required by did:webvh.                                                  |
| **X25519**       | ECDH           | `0xec` (public)                     | Key agreement only. Used in did:peer and did:key.                                              |
| **P-256**        | ECDSA (ES256)  | `0x8024` (public)                   | Signing, verification. Optional in did:webvh, supported in did:key.                            |
| **P-384**        | ECDSA (ES384)  | `0x8124` (public)                   | Signing, verification. Supported in did:key. Common in government/enterprise contexts.         |
| **secp256k1**    | ECDSA (ES256K) | `0xe7` (public)                     | Signing, verification. Required by did:ethr.                                                   |
| **BLS12-381 G1** | BBS (BLS)      | `0xea` (public)                     | BBS+ signature verification (short signatures). Used in did:key.                               |
| **BLS12-381 G2** | BBS (BLS)      | `0xeb` (public)                     | BBS+ signing, selective disclosure, ZKPs. Primary curve for BBS+ credentials. Used in did:key. |

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

### 4.3 Cryptographic Signing & Verification Interface

```csharp
public interface ICryptoProvider
{
    // --- Signing (used internally by KeyPairSigner; callers should use ISigner) ---
    byte[] Sign(KeyType keyType, ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> data);

    // --- Verification (public-key-only operations) ---
    bool Verify(KeyType keyType, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature);

    // --- Key Agreement (X25519 ECDH) ---
    byte[] KeyAgreement(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> publicKey);
}
```

> **Note**: `ICryptoProvider.Sign` is a low-level primitive used internally by `KeyPairSigner`. Application code and DID method implementations should use `ISigner.SignAsync()` instead, which works with both in-memory keys and HSM-backed keys.

### 4.3.1 ISigner — The Operational Signing Interface

DID method implementations need exactly two things from a key: the **public key** (for building DID documents, deriving addresses, computing SCIDs) and the ability to **sign data**. They never need raw private key bytes. `ISigner` captures this contract:

```csharp
/// The signing interface used by all DID method implementations.
/// Abstracts away whether the private key is in-memory or in a secure enclave.
public interface ISigner
{
    KeyType KeyType { get; }

    /// The public key bytes (always available, even for HSM-backed signers).
    ReadOnlyMemory<byte> PublicKey { get; }

    /// The multicodec-prefixed, multibase-encoded public key (e.g., "z6Mkf...")
    string MultibasePublicKey { get; }

    /// Sign data. For HSM-backed signers, this delegates to the secure enclave
    /// without the private key ever leaving the device.
    Task<byte[]> SignAsync(ReadOnlyMemory<byte> data, CancellationToken ct = default);
}
```

Two factory implementations are provided:

```csharp
/// Wraps a raw KeyPair for in-memory signing (simple path).
public sealed class KeyPairSigner : ISigner
{
    private readonly KeyPair _keyPair;
    private readonly ICryptoProvider _crypto;

    public KeyPairSigner(KeyPair keyPair, ICryptoProvider crypto)
    {
        _keyPair = keyPair;
        _crypto = crypto;
    }

    public KeyType KeyType => _keyPair.KeyType;
    public ReadOnlyMemory<byte> PublicKey => _keyPair.PublicKey;
    public string MultibasePublicKey => _keyPair.MultibasePublicKey;

    public Task<byte[]> SignAsync(ReadOnlyMemory<byte> data, CancellationToken ct = default)
    {
        var sig = _crypto.Sign(_keyPair.KeyType, _keyPair.PrivateKey, data.Span);
        return Task.FromResult(sig);
    }
}

/// Wraps a key store alias for HSM/vault-backed signing (secure path).
/// The private key never leaves the store.
public sealed class KeyStoreSigner : ISigner
{
    private readonly IKeyStore _store;
    private readonly string _alias;

    public KeyStoreSigner(IKeyStore store, string alias, KeyType keyType, byte[] publicKey)
    {
        _store = store;
        _alias = alias;
        KeyType = keyType;
        PublicKey = publicKey;
    }

    public KeyType KeyType { get; }
    public ReadOnlyMemory<byte> PublicKey { get; }
    public string MultibasePublicKey => MultibaseEncoder.Encode(MulticodecEncoder.Prefix(KeyType, PublicKey.Span));

    public Task<byte[]> SignAsync(ReadOnlyMemory<byte> data, CancellationToken ct = default)
        => _store.SignAsync(_alias, data, ct);
}
```

**Why ISigner exists**: Without it, every DID method option type would need a `KeyPair` property — which forces callers to extract private key bytes and passes them across API boundaries. This makes HSM, Azure Key Vault, AWS KMS, and hardware authenticator integrations impossible, since those systems never expose private key material. With `ISigner`, the method implementation calls `signer.SignAsync(data)` without knowing or caring whether the key is in-memory or in a hardware enclave.

```csharp
// Simple path — raw key pair:
var signer = new KeyPairSigner(keyPair, cryptoProvider);

// HSM path — key never leaves the vault:
var info = await keyStore.GetInfoAsync("my-update-key");
var signer = new KeyStoreSigner(keyStore, "my-update-key", info.KeyType, info.PublicKey);

// Or use the convenience factory on IKeyStore:
var signer = await keyStore.CreateSignerAsync("my-update-key");
```

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

````

### 4.4 Implementation Notes

- **Ed25519**: Use `System.Security.Cryptography` (.NET 10 has native Ed25519 support) or `NSec.Cryptography` as fallback for older targets.
- **X25519**: Same as Ed25519 — native in .NET 10 via `ECDiffieHellman` with `Curve25519`, or `NSec`.
- **P-256**: `System.Security.Cryptography.ECDsa` with `ECCurve.NamedCurves.nistP256`.
- **P-384**: `System.Security.Cryptography.ECDsa` with `ECCurve.NamedCurves.nistP384`. Native .NET support, no third-party dependency needed.
- **secp256k1**: `System.Security.Cryptography.ECDsa` with explicit curve parameters (secp256k1 is not a named curve in .NET), or `NBitcoin.Secp256k1` for a battle-tested implementation with Ethereum-compatible signing (recoverable signatures with v, r, s).
- **BLS12-381 (G1/G2)**: No native .NET support. Uses `Nethermind.Crypto.Bls` v1.0.5 (C# wrapper around the Supranational `blst` library, Apache 2.0). The `blst` library is the most widely deployed and audited BLS12-381 implementation (used by Ethereum 2.0 consensus clients). Nethermind exposes full pairing primitives: `SecretKey` (keygen, import/export), `P1`/`P2` (point operations, hash-to-curve, sign), `P1Affine`/`P2Affine` (decode, group check, compress), `Pairing` (aggregate, commit, final verify), `Scalar` (field arithmetic), and `PT` (Miller loop, final exponentiation). Key generation uses `SecretKey.Keygen(ikm)` for G1 and `P2.Generator().Mult(scalar)` for G2 (since P2 lacks `FromSk()`). Signature verification uses `Pairing.Aggregate` + `Pairing.Commit` + `Pairing.FinalVerify` with DST `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_`.
- **BBS+ Signatures**: Implemented via a Rust FFI shim (`native/zkryptium-ffi/`) wrapping the [zkryptium](https://github.com/Cybersecurity-LINKS/zkryptium) crate v0.2 (Apache 2.0, IETF draft-irtf-cfrg-bbs-signatures-10, BLS12-381-SHA-256 ciphersuite). The Rust shim compiles to a `cdylib` and is consumed via .NET `[LibraryImport]` P/Invoke source generation (NativeAOT-compatible). BBS+ keys use the same BLS12-381 scalar field as BLS keys (SK: 32 bytes, PK: 96 bytes G2 point), but are generated via the BBS+-specific `KeyGen` algorithm from the IETF draft. Signatures are 80 bytes; selective-disclosure proofs are variable-length. See `native/zkryptium-ffi/README.md` for build instructions and platform support.
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

public static class JwkConverter
{
    /// Convert a KeyPair to a public-only JWK.
    public static JsonWebKey ToPublicJwk(KeyPair keyPair);

    /// Convert a KeyPair to a JWK that includes private key material.
    public static JsonWebKey ToPrivateJwk(KeyPair keyPair);

    /// Extract the key type and raw public key bytes from a JWK.
    /// Inverse of ToPublicJwk — determines KeyType from the JWK's "crv" parameter
    /// and decodes the raw public key bytes from the coordinate parameters.
    public static (KeyType KeyType, byte[] PublicKey) ExtractPublicKey(JsonWebKey jwk);
}
````

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

1. If `ExistingKey` is provided, validate that `ExistingKey.KeyType == KeyType` and use
   `ExistingKey.PublicKey` as the raw public key bytes. Otherwise, generate a new key pair
   of the requested `KeyType`.
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

| KeyType      | VM Type (Multikey) | VM Type (JWK)    | Curve        |
| ------------ | ------------------ | ---------------- | ------------ |
| Ed25519      | `Multikey`         | `JsonWebKey2020` | Ed25519      |
| X25519       | `Multikey`         | `JsonWebKey2020` | X25519       |
| P-256        | `Multikey`         | `JsonWebKey2020` | P-256        |
| P-384        | `Multikey`         | `JsonWebKey2020` | P-384        |
| secp256k1    | `Multikey`         | `JsonWebKey2020` | secp256k1    |
| BLS12-381 G1 | `Multikey`         | `JsonWebKey2020` | BLS12-381 G1 |
| BLS12-381 G2 | `Multikey`         | `JsonWebKey2020` | BLS12-381 G2 |

### 5.6 BBS+ Key Usage in did:key

When creating a `did:key` with a BLS12-381 G2 key, the resulting DID Document advertises the key for `assertionMethod` (credential issuance with selective disclosure) and `capabilityInvocation`. The key is NOT added to `authentication` because BBS+ signatures are not suitable for challenge-response authentication (they are designed for credential signing and proof derivation).

Example DID: `did:key:zUC7DerdEmfZ8GgSqnmUZjJiKJGYmVzRR7YXVP5eq3jtyLMtnDq...`

The multicodec prefix `0xeb` identifies the key as a BLS12-381 G2 public key (96 bytes).

### 5.7 Configuration

```csharp
public sealed record DidKeyCreateOptions : DidCreateOptions
{
    public required KeyType KeyType { get; init; }

    /// Optional: wrap an existing key instead of generating a new one.
    /// When provided, the did:key is derived from ExistingKey.PublicKey.
    /// ExistingKey.KeyType must match KeyType (validated at creation time).
    /// Accepts any ISigner — works with both in-memory KeyPairSigner and
    /// HSM-backed signers where the private key never leaves the enclave.
    public ISigner? ExistingKey { get; init; }

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

**Numalgo 2** — Inline keys and services. Each key is purpose-prefixed per the DIF peer-DID spec:

- `A` = assertion (assertionMethod)
- `E` = encryption / key agreement (keyAgreement)
- `V` = verification / authentication (authentication)
- `I` = capability invocation (capabilityInvocation)
- `D` = capability delegation (capabilityDelegation)
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

/// did:peer only needs the public key (it's encoded into the DID string, no signing occurs).
/// Accepts ISigner for consistency with other methods and HSM compatibility
/// (the public key is extracted via signer.PublicKey; SignAsync is not called).
public sealed record PeerKeyPurpose(ISigner Key, PeerPurpose Purpose);

public enum PeerPurpose { Assertion, KeyAgreement, Authentication, CapabilityInvocation, CapabilityDelegation }
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

The SCID (Self-Certifying Identifier) is the multihash of the JCS-canonicalized genesis log entry (computed with `{SCID}` placeholders — see §7.5). This makes the DID self-certifying: the SCID cryptographically binds to the genesis state, and any tampering with the genesis entry invalidates the SCID.

### 7.3 Legacy Fallback to did:web

A `did:webvh` can be mapped to a `did:web` URL by removing `vh` from the method name and dropping the SCID segment:

```
did:webvh:QmRwq46V...:example.com  →  did:web:example.com
```

This provides a **legacy fallback** for resolvers that only understand did:web — they can
consume the `did.json` file at the web endpoint. However, this is NOT an equivalent
representation: the did:web fallback loses the SCID binding (the document is no longer
self-certifying), the cryptographic history chain (`did.jsonl` verification), and the
pre-rotation and witness security guarantees that make did:webvh distinct. The
`alsoKnownAs` property in the DID Document links back to the did:webvh identifier,
allowing consumers to upgrade to full did:webvh verification when possible.

### 7.4 DID Log Structure

The DID history is stored as a JSON Lines file (`did.jsonl`), where each line is a log entry.
The genesis entry shown below is the **final form** (after SCID placeholder replacement and signing — see §7.5):

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
    /* full DID Document — id is "did:webvh:QmRwq46V...:example.com" */
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

Each entry's `versionId` has the format `<version-number>-<entry-hash>`, where the entry hash chains to the previous entry. For the genesis entry, the entry hash IS the SCID.

### 7.5 Create

The genesis entry uses a two-pass algorithm to resolve the inherent circularity: the SCID
is derived from the entry, but the entry contains the SCID. The did:webvh spec defines a
well-known placeholder string (`{SCID}`) that stands in for the real SCID during the first pass.

1. Generate an Ed25519 key pair (the "update key").
2. Build the initial DID Document with desired verification methods and services. Use the
   literal placeholder `{SCID}` everywhere the SCID would appear (the DID `id` field,
   verification method `id` and `controller` values, etc.).
3. Construct the genesis log entry with parameters: `scid` set to `{SCID}`, `updateKeys`,
   optional pre-rotation commitment, optional witnesses. The `versionId` is `1-{SCID}`.
4. JCS-canonicalize the genesis entry (with placeholders in place) and hash it (multihash,
   base58btc-encoded) to produce the SCID value.
5. Replace every occurrence of the `{SCID}` placeholder in the log entry with the computed
   SCID value — in `parameters.scid`, `versionId`, the DID Document `id`, verification
   method IDs, controllers, and any other fields that reference the DID.
6. Sign the finalized genesis log entry with the update key using Data Integrity Proof
   (eddsa-jcs-2022). The proof is over the entry with the real SCID, not the placeholder.
7. Return: the DID string, the DID Document, the `did.jsonl` content (single line), and a
   `did.json` file for did:web compatibility.
8. The caller is responsible for publishing `did.jsonl` and `did.json` at the correct web URL.

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
    public required ISigner UpdateKey { get; init; }       // signs genesis log entry (HSM-safe)
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
    public required ISigner SigningKey { get; init; }        // authorized update key (HSM-safe)
    public DidDocument? NewDocument { get; init; }
    public DidWebVhParameterUpdates? ParameterUpdates { get; init; }
}

/// VersionId and VersionTime are inherited from the base DidResolutionOptions.
/// Add webvh-specific resolution options here if needed in the future.
public sealed record DidWebVhResolveOptions : DidResolutionOptions;

public sealed record DidWebVhDeactivateOptions : DidDeactivateOptions
{
    public required byte[] CurrentLogContent { get; init; }  // existing did.jsonl bytes
    public required ISigner SigningKey { get; init; }        // authorized update key (HSM-safe)
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

## 8. DID Method: did:ethr

### 8.1 Specification

ERC-1056 / DIF ethr-did-resolver — https://github.com/decentralized-identity/ethr-did-resolver/blob/master/doc/did-method-spec.md

### 8.2 DID Format

```
did:ethr:<optional-network>:<ethereum-address-or-public-key>
```

Examples:

- `did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a` (mainnet implied)
- `did:ethr:sepolia:0xb9c5714089478a327f09197987f16f9e5d936e8a` (Sepolia testnet)
- `did:ethr:0xaa36a7:0xb9c5714089478a327f09197987f16f9e5d936e8a` (by chain ID hex)

When no network is specified, Ethereum mainnet (chain ID 1) is assumed.

### 8.3 EthereumDIDRegistry Contract

The `EthereumDIDRegistry` smart contract (ERC-1056) is deployed at a well-known address (`0xdCa7EF03e98e0DC2B855bE647C39ABe984fcF21B`) on mainnet and many testnets. It provides:

- **identityOwner(address)** → returns the current owner of the identity
- **changeOwner(address, newOwner)** → transfer ownership
- **changeOwnerSigned(...)** → meta-transaction variant (signed by identity key, submitted by relayer)
- **addDelegate(address, delegateType, delegate, validity)** → add a time-limited delegate key
- **revokeDelegate(address, delegateType, delegate)** → revoke a delegate
- **setAttribute(address, name, value, validity)** → set an attribute (service endpoints, additional keys)
- **revokeAttribute(address, name, value)** → revoke an attribute

All mutations emit events. Resolution replays these events.

### 8.4 Create

did:ethr creation is implicit — any Ethereum key pair is already a valid DID. "Creating" a did:ethr means:

1. If `ExistingKey` is provided, validate that `ExistingKey.KeyType == Secp256k1` and use
   `ExistingKey.PublicKey`. Otherwise, generate a new secp256k1 key pair.
2. Derive the Ethereum address from the public key (keccak256 hash, take last 20 bytes, checksum-encode).
3. The DID is `did:ethr:<network>:<address>`.
4. The default DID Document has a single secp256k1 verification method for the controller address.
5. No on-chain transaction needed.

```csharp
public sealed record DidEthrCreateOptions : DidCreateOptions
{
    /// The Ethereum network for the DID (e.g., "mainnet", "sepolia", "polygon").
    /// Determines the network identifier in the DID string and the RPC endpoint used.
    public required string Network { get; init; }

    /// Optional: wrap an existing secp256k1 key instead of generating a new one.
    /// When provided, the Ethereum address is derived from ExistingKey.PublicKey.
    /// ExistingKey.KeyType must be Secp256k1 (validated at creation time).
    public ISigner? ExistingKey { get; init; }
}
```

### 8.5 Resolve

1. Parse the DID, extract network identifier and address.
2. Select the appropriate RPC endpoint for the network.
3. Call `identityOwner(address)` to determine the current controller.
4. Query `eth_getLogs` for all `DIDOwnerChanged`, `DIDDelegateChanged`, and `DIDAttributeChanged` events for the address, from the contract deployment block.
5. Replay events chronologically to build the DID Document:
   - Each `DIDOwnerChanged` updates the controller.
   - Each `DIDDelegateChanged` adds/removes delegate verification methods (checking `validity` expiration against current block).
   - Each `DIDAttributeChanged` adds/removes attributes:
     - `did/pub/<keyType>/<purpose>/<encoding>` → verification method (with `publicKeyJwk`
       or `publicKeyMultibase` when the encoding provides full key material)
     - `did/svc/<serviceType>` → service endpoint
6. Return the assembled DID Document.

**Note on key material representations**: The default (implicit) VM for a did:ethr uses
`EcdsaSecp256k1RecoveryMethod2020` with only a `blockchainAccountId` — the Ethereum address,
not the full public key. This is sufficient for ecrecover-based signature verification but
is NOT compatible with `IVerificationMethodResolver`, which requires extractable public key
bytes. VMs added via `setAttribute` with `did/pub/Secp256k1/veriKey/publicKeyJwk` produce
VMs with full key material that work through the standard verification path. For ZCAP use
cases, ensure the signing key has been registered on-chain with full public key encoding.

### 8.6 Update

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

    // Signs transactions. ISigner provides the public key (for address derivation)
    // and signing without exposing private key material (HSM-safe).
    public required ISigner ControllerKey { get; init; }

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

### 8.7 Deactivate

Set the owner to `0x0000000000000000000000000000000000000000` (null address). This makes the identity uncontrollable and the DID Document resolves with `deactivated: true`.

```csharp
public sealed record DidEthrDeactivateOptions : DidDeactivateOptions
{
    /// Signs the changeOwner transaction that transfers ownership to the null address.
    public required ISigner ControllerKey { get; init; }

    /// Use meta-transaction (signed by controller, submitted by relayer)?
    public bool UseMetaTransaction { get; init; } = false;
}
```

### 8.8 Ethereum RPC Abstraction

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

## 9. DID Document Model

### 9.1 Core Model (W3C DID Core 1.0 Compliant)

```csharp
/// Value object that represents a validated DID string.
/// Construction validates that the string conforms to W3C DID syntax: did:<method>:<method-specific-id>.
/// Illegal states are unrepresentable — if you have a Did, it is syntactically valid.
public readonly record struct Did
{
    public string Value { get; }
    public string Method { get; }
    public string MethodSpecificId { get; }

    public Did(string value)
    {
        if (!DidParser.IsValid(value))
            throw new InvalidDidException(value, $"'{value}' does not conform to W3C DID syntax.");

        Value = value;
        Method = DidParser.ExtractMethod(value)!;
        MethodSpecificId = DidParser.ExtractMethodSpecificId(value)!;
    }

    /// Implicit conversion from string — validates on construction.
    public static implicit operator Did(string value) => new(value);

    /// Implicit conversion to string for interop.
    public static implicit operator string(Did did) => did.Value;

    public override string ToString() => Value;
}

public sealed record DidDocument
{
    public required Did Id { get; init; }
    public IReadOnlyList<string>? AlsoKnownAs { get; init; }

    /// W3C DID Core §5.1.2: controller is a single DID or an ordered set of DIDs.
    /// Serialized as a string when Count == 1, as an array when Count > 1, omitted when null.
    public IReadOnlyList<Did>? Controller { get; init; }

    public IReadOnlyList<VerificationMethod>? VerificationMethod { get; init; }
    public IReadOnlyList<VerificationRelationshipEntry>? Authentication { get; init; }
    public IReadOnlyList<VerificationRelationshipEntry>? AssertionMethod { get; init; }
    public IReadOnlyList<VerificationRelationshipEntry>? KeyAgreement { get; init; }
    public IReadOnlyList<VerificationRelationshipEntry>? CapabilityInvocation { get; init; }
    public IReadOnlyList<VerificationRelationshipEntry>? CapabilityDelegation { get; init; }

    public IReadOnlyList<Service>? Service { get; init; }

    /// JSON-LD @context. Present only when the document is produced as application/did+ld+json.
    /// When set, MUST include "https://www.w3.org/ns/did/v1" as the first entry.
    /// Additional context URIs are appended dynamically based on verification method types:
    ///   - Multikey           → "https://w3id.org/security/multikey/v1"
    ///   - JsonWebKey2020     → "https://w3id.org/security/suites/jws-2020/v1"
    ///   - BBS+ (bbs-2023)    → "https://w3id.org/security/data-integrity/v2"
    ///   - EcdsaSecp256k1...  → "https://w3id.org/security/suites/secp256k1-2019/v1"
    /// The DidDocumentSerializer computes the correct @context automatically from the
    /// verification methods present when producing JSON-LD. Callers may also supply
    /// additional context URIs that are appended after the auto-detected ones.
    /// Null when the document is consumed from or produced as application/did+json.
    public IReadOnlyList<object>? Context { get; init; }

    /// Extension properties not defined in DID Core.
    public IReadOnlyDictionary<string, JsonElement>? AdditionalProperties { get; init; }
}

public sealed class VerificationMethod
{
    public required string Id { get; init; }          // DID URL (validated at deserialization)
    public required string Type { get; init; }        // "Multikey", "JsonWebKey2020", "EcdsaSecp256k1VerificationKey2019"
    public required Did Controller { get; init; }
    public string? PublicKeyMultibase { get; init; }   // for Multikey representation
    public JsonWebKey? PublicKeyJwk { get; init; }     // for JWK representation
    public string? BlockchainAccountId { get; init; }  // for did:ethr (CAIP-10 format)
}

/// A verification relationship entry is either a reference (DID URL string) or an embedded
/// verification method — never both, never neither. Construction is restricted to the two
/// factory methods to make illegal states unrepresentable.
public sealed class VerificationRelationshipEntry
{
    /// The referenced DID URL (set when IsReference == true).
    public string? Reference { get; }

    /// The embedded verification method (set when IsReference == false).
    public VerificationMethod? EmbeddedMethod { get; }

    public bool IsReference => Reference is not null;

    private VerificationRelationshipEntry(string? reference, VerificationMethod? embedded)
    {
        Reference = reference;
        EmbeddedMethod = embedded;
    }

    /// Create a reference entry (DID URL pointing to a verification method defined elsewhere).
    public static VerificationRelationshipEntry FromReference(string didUrl)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(didUrl);
        return new VerificationRelationshipEntry(didUrl, null);
    }

    /// Create an embedded entry (inline verification method definition).
    public static VerificationRelationshipEntry FromEmbedded(VerificationMethod method)
    {
        ArgumentNullException.ThrowIfNull(method);
        return new VerificationRelationshipEntry(null, method);
    }

    /// Implicit conversion from string for ergonomic reference creation.
    public static implicit operator VerificationRelationshipEntry(string didUrl) => FromReference(didUrl);
}

public sealed class Service
{
    public required string Id { get; init; }          // DID URL (validated at deserialization)
    public required string Type { get; init; }

    /// W3C DID Core §5.4: serviceEndpoint can be a URI string, a map (object),
    /// or an ordered set of URIs and/or maps.
    public required ServiceEndpointValue ServiceEndpoint { get; init; }

    public IReadOnlyDictionary<string, JsonElement>? AdditionalProperties { get; init; }
}

/// Represents the polymorphic serviceEndpoint value per W3C DID Core §5.4.
/// Exactly one variant is set — enforced by private constructor and factory methods.
/// Illegal states (zero variants, multiple variants) are unrepresentable.
public sealed class ServiceEndpointValue
{
    public string? Uri { get; }
    public IReadOnlyDictionary<string, JsonElement>? Map { get; }
    public IReadOnlyList<ServiceEndpointValue>? Set { get; }

    public bool IsUri => Uri is not null;
    public bool IsMap => Map is not null;
    public bool IsSet => Set is not null;

    private ServiceEndpointValue(string? uri, IReadOnlyDictionary<string, JsonElement>? map,
        IReadOnlyList<ServiceEndpointValue>? set)
    {
        Uri = uri;
        Map = map;
        Set = set;
    }

    public static ServiceEndpointValue FromUri(string uri)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(uri);
        return new(uri, null, null);
    }

    public static ServiceEndpointValue FromMap(IReadOnlyDictionary<string, JsonElement> map)
    {
        ArgumentNullException.ThrowIfNull(map);
        return new(null, map, null);
    }

    public static ServiceEndpointValue FromSet(IReadOnlyList<ServiceEndpointValue> set)
    {
        ArgumentNullException.ThrowIfNull(set);
        if (set.Count == 0) throw new ArgumentException("Set must contain at least one entry.", nameof(set));
        return new(null, null, set);
    }

    /// Implicit conversion from string for ergonomic URI creation.
    public static implicit operator ServiceEndpointValue(string uri) => FromUri(uri);
}
```

### 9.2 Serialization & Content Type Negotiation

W3C DID Core §6 defines two distinct JSON-based representations with different production and consumption rules:

|                 | `application/did+ld+json` (JSON-LD)                                                                              | `application/did+json` (plain JSON)                                                                   |
| --------------- | ---------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| **`@context`**  | **Required**. MUST start with `"https://www.w3.org/ns/did/v1"`. Additional contexts auto-computed from VM types. | **Omitted**. `@context` has no normative meaning in plain JSON and MUST NOT be required by consumers. |
| **Properties**  | All DID Core properties + JSON-LD keywords                                                                       | All DID Core properties, no JSON-LD keywords                                                          |
| **When to use** | Interop with JSON-LD processors, Linked Data ecosystems, Verifiable Credentials                                  | Lightweight consumers, REST APIs, internal storage                                                    |

NetDid supports **both** representations. The `DidDocumentSerializer` selects the correct production rules based on a `DidRepresentationContentType` parameter:

```csharp
/// The two W3C-defined DID Document content types.
public static class DidContentTypes
{
    public const string JsonLd = "application/did+ld+json";
    public const string Json   = "application/did+json";
}

public static class DidDocumentSerializer
{
    /// Produce the DID Document as a JSON string in the specified representation.
    /// - JsonLd: includes @context (auto-computed from VM types), all JSON-LD keywords
    /// - Json:   omits @context and any JSON-LD-only properties
    public static string Serialize(DidDocument doc, string contentType = DidContentTypes.JsonLd,
        JsonSerializerOptions? options = null);

    /// Produce the DID Document as UTF-8 bytes.
    public static byte[] SerializeToUtf8(DidDocument doc, string contentType = DidContentTypes.JsonLd,
        JsonSerializerOptions? options = null);

    /// Consume (deserialize) a DID Document from JSON.
    /// Per W3C DID Core §6.2 (JSON consumption): MUST NOT require @context.
    /// Per W3C DID Core §6.3 (JSON-LD consumption): MUST verify @context when
    /// the input is known to be application/did+ld+json.
    public static DidDocument Deserialize(string json, string? contentType = null);
    public static DidDocument Deserialize(ReadOnlySpan<byte> utf8Json, string? contentType = null);
}
```

**Default content type**: `application/did+ld+json` (JSON-LD) is the default for production because it carries the richest semantic information and is required by most DID-consuming ecosystems (Verifiable Credentials, ZCAP-LD, Data Integrity Proofs). Callers who need plain JSON explicitly pass `DidContentTypes.Json`.

### 9.3 W3C DID Core Normative Requirements on the Document

**Data model requirements** (enforced at construction, independent of representation):

- `id` MUST be a valid DID. The `Did` value object (a `readonly record struct`) validates W3C DID syntax at construction — if a `Did` exists, it is syntactically valid. This makes invalid DIDs unrepresentable in the type system.
- `controller`, when present, MUST be a list of valid `Did` values. Serialized as a string when Count == 1, as an array when Count > 1, omitted when null.
- `verificationMethod[*].id` MUST be a valid DID URL.
- `verificationMethod[*].controller` MUST be a valid `Did`.
- `service[*].id` MUST be a valid DID URL.
- `service[*].serviceEndpoint` MUST be exactly one of: a URI string, a map, or an ordered set of URIs/maps (§5.4). The `ServiceEndpointValue` type enforces this via factory methods (`FromUri`, `FromMap`, `FromSet`) — the private constructor makes it impossible to construct an instance with zero or multiple variants set.
- Verification relationship entries are either a reference string (DID URL) or an embedded `VerificationMethod`, never both and never neither. The `VerificationRelationshipEntry` type enforces this via `FromReference` and `FromEmbedded` factory methods.
- All properties follow the registered names in the DID Specification Registries.

**JSON-LD production requirements** (§6.3, `application/did+ld+json`):

- `@context` MUST be present and MUST include `"https://www.w3.org/ns/did/v1"` as the first element. Additional context URIs are computed dynamically from the verification method types present in the document.
- All JSON-LD keywords (`@context`, `@type`, etc.) MUST be serialized correctly.

**Plain JSON production requirements** (§6.2, `application/did+json`):

- `@context` MUST NOT be included in the serialized output. The property has no normative meaning in the plain JSON representation.
- All DID Core properties MUST be serialized as defined in the DID Core data model.

**Consumption requirements**:

- A conforming consumer of `application/did+json` MUST NOT require `@context`. If `@context` is present, it MAY be ignored.
- A conforming consumer of `application/did+ld+json` MUST verify the presence and correctness of `@context`.

---

## 10. Resolver Architecture

### 10.1 Composite Resolver

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

### 10.2 Caching Resolver

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

### 10.3 DID Parser

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
    public required Did Did { get; init; }
    public string? Path { get; init; }
    public string? Query { get; init; }
    public string? Fragment { get; init; }
    public string FullUrl => /* reconstruct */;
}
```

### 10.4 DID URL Dereferencer

W3C DID Core §7.2 defines DID URL Dereferencing as a distinct function from DID Resolution. While resolution takes a DID and returns a full DID Document, dereferencing takes a DID URL (which may include path, query, and/or fragment components) and returns the specific resource identified by that URL.

NetDid provides a standard `IDidUrlDereferencer` interface that implements the W3C §7.2 function signature:

```csharp
public interface IDidUrlDereferencer
{
    /// Dereference a DID URL to the resource it identifies.
    ///
    /// Per W3C DID Core §7.2, the inputs are:
    ///   - didUrl: A conformant DID URL (DID + optional path, query, fragment)
    ///   - options: DID URL dereferencing options (accept content type, etc.)
    ///
    /// The output is:
    ///   - DereferencingMetadata: metadata about the dereferencing process (contentType, error)
    ///   - ContentStream: the resource (VerificationMethod, Service, DID Document, or byte[])
    ///   - ContentMetadata: metadata about the content (same structure as DidDocumentMetadata)
    Task<DidUrlDereferencingResult> DereferenceAsync(
        string didUrl,
        DidUrlDereferencingOptions? options = null,
        CancellationToken ct = default);
}

public sealed record DidUrlDereferencingResult
{
    /// Metadata about the dereferencing process itself.
    /// Contains contentType (required on success) and error (if dereferencing failed).
    public required DereferencingMetadata DereferencingMetadata { get; init; }

    /// The dereferenced resource. Null when an error occurs.
    /// May be a VerificationMethod, Service, DidDocument, or raw byte[] depending on the DID URL.
    /// For service endpoint redirects, this is the constructed URL string.
    public object? ContentStream { get; init; }

    /// Metadata about the content (equivalent to didDocumentMetadata when the
    /// content is a full DID Document, empty otherwise).
    public IReadOnlyDictionary<string, object>? ContentMetadata { get; init; }

    // Factory methods used by DefaultDidUrlDereferencer:

    public static DidUrlDereferencingResult Error(string errorCode) => new()
    {
        DereferencingMetadata = new DereferencingMetadata { Error = errorCode }
    };

    public static DidUrlDereferencingResult Success(
        object content, string contentType, DidDocumentMetadata? metadata = null) => new()
    {
        DereferencingMetadata = new DereferencingMetadata { ContentType = contentType },
        ContentStream = content,
        ContentMetadata = metadata?.ToPropertyDictionary()
    };

    /// Service endpoint selection: returns the constructed URL for the caller to follow.
    /// ContentType is "text/uri-list" per convention.
    public static DidUrlDereferencingResult ServiceEndpointRedirect(string serviceUrl) => new()
    {
        DereferencingMetadata = new DereferencingMetadata { ContentType = "text/uri-list" },
        ContentStream = serviceUrl
    };
}

public sealed record DereferencingMetadata
{
    /// The Media Type of the returned content (e.g., "application/did+ld+json").
    /// MUST be expressed as an ASCII string per W3C DID Core §7.2.
    public string? ContentType { get; init; }

    /// Error code if dereferencing failed. Standard values:
    /// "invalidDidUrl", "notFound", "contentTypeNotSupported".
    public string? Error { get; init; }
}

public sealed record DidUrlDereferencingOptions
{
    /// The Media Type the caller prefers for the dereferenced content.
    public string? Accept { get; init; }
}
```

**Default implementation**: `DefaultDidUrlDereferencer` composes with `IDidResolver` and implements
the W3C §7.2 dereferencing algorithm for fragment, service endpoint selection (with path and
`relativeRef`), and `versionId`/`versionTime` query parameters:

```csharp
public sealed class DefaultDidUrlDereferencer : IDidUrlDereferencer
{
    private readonly IDidResolver _resolver;

    public DefaultDidUrlDereferencer(IDidResolver resolver) => _resolver = resolver;

    public async Task<DidUrlDereferencingResult> DereferenceAsync(
        string didUrl, DidUrlDereferencingOptions? options = null, CancellationToken ct = default)
    {
        var parsed = DidParser.ParseDidUrl(didUrl);
        if (parsed is null)
            return DidUrlDereferencingResult.Error("invalidDidUrl");

        var accept = options?.Accept ?? DidContentTypes.JsonLd;
        var queryParams = ParseQueryString(parsed.Query);

        // Step 1: Resolve the base DID, passing through versionId/versionTime if present
        var resolutionOptions = new DidResolutionOptions
        {
            Accept = accept,
            VersionId = queryParams.GetValueOrDefault("versionId"),
            VersionTime = queryParams.GetValueOrDefault("versionTime")
        };
        var resolution = await _resolver.ResolveAsync(parsed.Did, resolutionOptions, ct);
        if (resolution.DidDocument is null)
            return DidUrlDereferencingResult.Error(resolution.ResolutionMetadata.Error ?? "notFound");

        // Step 2: Service endpoint selection + URL construction (§7.2 service query)
        if (queryParams.TryGetValue("service", out var serviceId))
        {
            var service = FindServiceById(resolution.DidDocument, serviceId);
            if (service is null)
                return DidUrlDereferencingResult.Error("notFound");

            // Construct the dereferenced URL from the service endpoint, applying
            // the DID URL path and/or relativeRef query parameter per §7.2.
            var serviceUrl = ConstructServiceUrl(
                service.ServiceEndpoint,
                parsed.Path,
                queryParams.GetValueOrDefault("relativeRef"),
                parsed.Fragment);

            return DidUrlDereferencingResult.ServiceEndpointRedirect(serviceUrl);
        }

        // Step 3: Fragment-only → select resource from DID Document
        if (parsed.Fragment is not null)
        {
            var resource = FindByFragment(resolution.DidDocument, parsed.Fragment);
            if (resource is null)
                return DidUrlDereferencingResult.Error("notFound");
            return DidUrlDereferencingResult.Success(resource, accept);
        }

        // Step 4: Path without service query → DID Core does not define semantics
        // for bare paths; return an error rather than silently ignoring the path.
        if (parsed.Path is not null)
            return DidUrlDereferencingResult.Error("notFound");

        // No path, fragment, or service query: return the full DID Document
        return DidUrlDereferencingResult.Success(
            resolution.DidDocument, accept,
            resolution.DocumentMetadata);
    }

    /// Parse "service=hub&relativeRef=%2Fprofile" → { "service": "hub", "relativeRef": "/profile" }
    private static Dictionary<string, string> ParseQueryString(string? query);

    /// Find a service by matching the service query value against the fragment portion
    /// of each service's id. Per W3C DID Core §7.2, "?service=pds-1" matches a service
    /// with id "#pds-1" or "did:example:123#pds-1". The match is against the id, NOT
    /// the service type.
    private static Service? FindServiceById(DidDocument doc, string serviceId);

    /// Find a verification method or service within the DID Document by fragment.
    private static object? FindByFragment(DidDocument doc, string fragment);

    /// Construct the final URL from service endpoint + path + relativeRef + fragment.
    /// Per §7.2: serviceEndpoint + path + relativeRef, with fragment appended.
    private static string ConstructServiceUrl(
        string serviceEndpoint, string? path, string? relativeRef, string? fragment);
}
```

---

## 11. Pluggable Key Management

### 11.1 IKeyStore Interface

NetDid generates keys via `IKeyGenerator` but does NOT store them. The caller provides an `IKeyStore` implementation for persistent key management. The interface is designed around a critical constraint: **private key material may never be extractable** (HSMs, Azure Key Vault, AWS KMS, hardware authenticators).

```csharp
public interface IKeyStore
{
    /// Generate a new key pair inside the store. For HSM-backed stores, the private
    /// key is created within the secure enclave and never leaves it.
    /// Returns metadata including the public key (always safe to expose).
    Task<StoredKeyInfo> GenerateAsync(string alias, KeyType keyType, CancellationToken ct = default);

    /// Import an externally-generated key pair into the store.
    /// For HSMs that prohibit import, this throws NotSupportedException.
    Task<StoredKeyInfo> ImportAsync(string alias, KeyPair keyPair, CancellationToken ct = default);

    /// Get public key and metadata for a stored key. The private key is never exposed.
    Task<StoredKeyInfo?> GetInfoAsync(string alias, CancellationToken ct = default);

    /// Sign data using a stored key. The private key never leaves the store.
    Task<byte[]> SignAsync(string alias, ReadOnlyMemory<byte> data, CancellationToken ct = default);

    /// Create an ISigner backed by this store for the given key alias.
    /// This is the primary integration point with DID method APIs.
    Task<ISigner> CreateSignerAsync(string alias, CancellationToken ct = default);

    /// List all stored key aliases.
    Task<IReadOnlyList<string>> ListAsync(CancellationToken ct = default);

    /// Delete a key by alias.
    Task<bool> DeleteAsync(string alias, CancellationToken ct = default);
}

/// Metadata about a stored key. Never contains private key material.
public sealed record StoredKeyInfo
{
    public required string Alias { get; init; }
    public required KeyType KeyType { get; init; }
    public required byte[] PublicKey { get; init; }

    /// The multicodec-prefixed, multibase-encoded public key.
    public string MultibasePublicKey => MultibaseEncoder.Encode(MulticodecEncoder.Prefix(KeyType, PublicKey));
}
```

> **Key design decision**: The old `GetAsync(alias) → KeyPair?` method has been removed. Returning a `KeyPair` (which contains `PrivateKey` bytes) would make HSM integration impossible — the entire point of an HSM is that private key material never leaves the device. Instead, `GetInfoAsync` returns only public metadata, and `SignAsync`/`CreateSignerAsync` provide signing without key extraction.

### 11.2 Provided Implementations

| Implementation       | Purpose                                                                           | Production Use?     |
| -------------------- | --------------------------------------------------------------------------------- | ------------------- |
| `InMemoryKeyStore`   | Dictionary-backed, for unit tests and development                                 | ❌ Testing only     |
| `FileSystemKeyStore` | Encrypted JSON files in a directory (DPAPI on Windows, file permissions on Linux) | ⚠️ Development only |

### 11.3 Expected Third-Party Implementations

The interface is designed to be easily adapted to:

- Azure Key Vault
- AWS KMS
- HashiCorp Vault
- FIDO2/WebAuthn hardware authenticators
- OS-level keystores (Windows CNG, macOS Keychain, Linux Secret Service)
- Custom HSMs

### 11.4 Key Store in DID Operations

All DID method option types that require signing accept an `ISigner` — never a raw `KeyPair`. This is the single integration point between key management and DID operations:

**Simple path** — caller has a raw key pair (testing, development, software-managed keys):

```csharp
var keyPair = keyGenerator.Generate(KeyType.Ed25519);
var signer = new KeyPairSigner(keyPair, cryptoProvider);

var result = await didWebVhMethod.CreateAsync(new DidWebVhCreateOptions
{
    Domain = "alice.example.com",
    UpdateKey = signer,  // ISigner, not KeyPair
    // ...
});
```

**HSM/Vault path** — private key never leaves the secure enclave:

```csharp
// Key generated inside the HSM (private key never exposed):
var keyInfo = await keyStore.GenerateAsync("webvh-update-key", KeyType.Ed25519);

// Create an ISigner that delegates signing to the HSM:
var signer = await keyStore.CreateSignerAsync("webvh-update-key");

var result = await didWebVhMethod.CreateAsync(new DidWebVhCreateOptions
{
    Domain = "alice.example.com",
    UpdateKey = signer,  // signing happens inside the HSM
    // ...
});
```

The DID method implementation calls `signer.SignAsync(data)` and `signer.PublicKey` — it never knows or cares whether the key is in-memory or in a hardware enclave. This makes HSM, Azure Key Vault, AWS KMS, and FIDO2 integrations first-class citizens rather than afterthoughts.

---

## 12. W3C DID Test Suite Conformance

### 12.1 Overview

The W3C DID Test Suite (https://github.com/w3c/did-test-suite) is maintained by the W3C DID Working Group and performs interoperability tests across five conformance categories. NetDid MUST pass all applicable tests for every supported DID method (did:key, did:peer, did:webvh, did:ethr).

### 12.2 Conformance Categories

These match the five suites in the W3C DID Implementation Report (https://w3c.github.io/did-test-suite/):

| Suite                     | What It Tests                                                                                                                                                                                                                                                                                                                                                                                                                            | NetDid Applicability |
| ------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------- |
| **did-identifier**        | DID syntax: method name is ASCII lowercase, method-specific-id conforms to ABNF, overall DID string matches the grammar.                                                                                                                                                                                                                                                                                                                 | All 4 methods        |
| **did-core-properties**   | DID Document properties: `id` is valid DID, `verificationMethod` entries have required fields, `service` entries are well-formed, all verification relationships reference valid VMs. For JSON-LD representations, `@context` must be correct. Also covers consumption (deserialization) — a conforming JSON consumer MUST NOT require `@context`; a JSON-LD consumer MUST verify it. Both MUST handle unknown properties without error. | All 4 methods        |
| **did-production**        | Serialization (production) of DID Documents per content type. For `application/did+ld+json`: MUST include `@context` with correct entries. For `application/did+json`: MUST NOT include `@context`. Both: property names MUST be strings, values MUST conform to the data model type system.                                                                                                                                             | All 4 methods        |
| **did-resolution**        | DID Resolution (§7.1): given a DID, the resolver returns a conformant `DidResolutionResult` with correct `didDocument`, `didResolutionMetadata`, and `didDocumentMetadata`. Covers error cases (`notFound`, `invalidDid`, `methodNotSupported`, `deactivated`).                                                                                                                                                                          | All 4 methods        |
| **did-url-dereferencing** | DID URL Dereferencing (§7.2): given a DID URL (DID + optional path, query, and/or fragment), the dereferencer returns the specific resource identified by the URL. Fragment dereferencing returns elements within the DID Document (verification methods, services). Query-based dereferencing supports service endpoint selection. Covers error handling and content type negotiation.                                                  | All 4 methods        |

### 12.3 Test Fixture Generation

The W3C test suite expects implementations to provide JSON fixture files that describe the implementation and its test vectors. For each DID method, NetDid generates these fixtures automatically via a CLI tool:

```
netdid-test-fixtures generate --method key --output ./fixtures/did-key.json
netdid-test-fixtures generate --method peer --output ./fixtures/did-peer.json
netdid-test-fixtures generate --method webvh --output ./fixtures/did-webvh.json
netdid-test-fixtures generate --method ethr --output ./fixtures/did-ethr.json
```

Each fixture file contains:

```json
{
  "name": "NetDid did:key",
  "implementation": "NetDid",
  "implementer": "Moises Jaramillo",
  "supportedContentTypes": ["application/did+ld+json", "application/did+json"],
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

### 12.4 Test Harness Integration

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

**Approach 2: Resolution & dereferencing endpoints (supplementary)**

For the `did-resolution` and `did-url-dereferencing` suites, NetDid can optionally run a lightweight HTTP server that the W3C test suite queries:

```csharp
// NetDid.TestSuite.W3C.Server — minimal Kestrel app with content negotiation
app.MapGet("/resolve/{did}", async (string did, HttpContext ctx, IDidResolver resolver) =>
{
    // Content negotiation: Accept header determines representation
    var accept = ctx.Request.Headers.Accept.FirstOrDefault() ?? DidContentTypes.JsonLd;
    var options = new DidResolutionOptions { Accept = accept };
    var result = await resolver.ResolveAsync(did, options);

    ctx.Response.ContentType = result.ResolutionMetadata.ContentType ?? accept;
    return Results.Json(new
    {
        didDocument = result.DidDocument,
        didResolutionMetadata = result.ResolutionMetadata,
        didDocumentMetadata = result.DocumentMetadata
    });
});

app.MapGet("/dereference/{*didUrl}", async (string didUrl, HttpContext ctx, IDidUrlDereferencer dereferencer) =>
{
    var accept = ctx.Request.Headers.Accept.FirstOrDefault() ?? DidContentTypes.JsonLd;
    var options = new DidUrlDereferencingOptions { Accept = accept };
    var result = await dereferencer.DereferenceAsync(didUrl, options);

    ctx.Response.ContentType = result.DereferencingMetadata.ContentType ?? accept;
    return Results.Json(new
    {
        dereferencingMetadata = result.DereferencingMetadata,
        contentStream = result.ContentStream,
        contentMetadata = result.ContentMetadata
    });
});
```

### 12.5 Internal Conformance Test Mirror

In addition to running the external W3C suite, NetDid includes its own xUnit test project (`NetDid.Tests.W3CConformance`) that mirrors every normative statement from the DID Core spec as an explicit test case. This provides fast feedback during development without needing the Node.js toolchain:

```csharp
[Trait("Category", "W3CConformance")]
[Trait("Suite", "did-identifier")]
public class DidIdentifierConformanceTests
{
    [Theory]
    [InlineData("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")]
    [InlineData("did:peer:0z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH")]
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
    public void JsonLd_context_must_include_did_v1_as_first_entry()
    {
        // When produced as application/did+ld+json:
        // Verify @context[0] == "https://www.w3.org/ns/did/v1"
    }

    [Fact]
    public void Json_consumer_must_not_require_context()
    {
        // A valid application/did+json document without @context must deserialize successfully
        var json = """{"id": "did:key:z6Mkf...", "verificationMethod": [...]}""";
        var doc = DidDocumentSerializer.Deserialize(json, DidContentTypes.Json);
        Assert.NotNull(doc);
        Assert.Null(doc.Context);
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
    // --- application/did+ld+json (JSON-LD) production ---

    [Fact]
    public void JsonLd_representation_must_include_context()
    {
        // Serialize as did+ld+json, verify "@context" is present and starts with DID v1 URI
        var json = DidDocumentSerializer.Serialize(doc, DidContentTypes.JsonLd);
        var root = JsonDocument.Parse(json).RootElement;
        Assert.True(root.TryGetProperty("@context", out var ctx));
        Assert.Equal("https://www.w3.org/ns/did/v1", ctx[0].GetString());
    }

    [Fact]
    public void JsonLd_context_must_include_additional_contexts_for_vm_types()
    {
        // If document contains Multikey VMs, @context must include multikey context
    }

    // --- application/did+json (plain JSON) production ---

    [Fact]
    public void Json_representation_must_not_include_context()
    {
        // Serialize as did+json, verify "@context" is NOT present
        var json = DidDocumentSerializer.Serialize(doc, DidContentTypes.Json);
        var root = JsonDocument.Parse(json).RootElement;
        Assert.False(root.TryGetProperty("@context", out _));
    }

    // --- Shared production requirements ---

    [Fact]
    public void All_property_names_must_be_strings()
    {
        // Parse the JSON (both representations), verify all keys are string type
    }

    [Fact]
    public void Serialized_document_must_be_valid_json()
    {
        // For each method, create → serialize (both content types) → verify parseable as JSON
    }

    [Fact]
    public void Both_representations_must_preserve_all_did_core_properties()
    {
        // Serialize as did+ld+json and did+json, verify both contain id, verificationMethod, etc.
        // The only difference should be presence/absence of @context
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

[Trait("Category", "W3CConformance")]
[Trait("Suite", "did-url-dereferencing")]
public class DidUrlDereferencingConformanceTests
{
    [Fact]
    public async Task Fragment_must_dereference_to_verification_method()
    {
        // did:key:z6Mkf...#z6Mkf... → returns the VerificationMethod resource
    }

    [Fact]
    public async Task Fragment_must_dereference_to_service()
    {
        // did:webvh:...#pds-1 → returns the Service resource
    }

    [Fact]
    public async Task Dereferencing_must_use_complete_did_url_including_fragment()
    {
        // W3C §7.2: "To dereference a DID fragment, the complete DID URL
        // including the DID fragment MUST be used."
    }

    [Fact]
    public async Task Dereferencing_invalid_fragment_must_return_error()
    {
        // did:key:z6Mkf...#nonexistent → error in dereferencingMetadata
    }

    [Fact]
    public async Task Dereferencing_must_return_content_type_as_ascii_string()
    {
        // The Media Type MUST be expressed as an ASCII string
    }

    [Fact]
    public async Task Service_query_must_dereference_to_service_endpoint()
    {
        // did:webvh:...?service=pds-1 → returns the service endpoint URL
        // The service query matches by the fragment portion of the service id
        // (e.g., "#pds-1"), NOT by service type (e.g., "TurtleShellPds").
    }

    // ... one test per normative statement from §7.2
}
```

### 12.6 CI Pipeline for Conformance

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

### 12.7 Conformance Badges

Once all tests pass, the project README displays conformance badges:

```markdown
![W3C DID Identifier](https://img.shields.io/badge/W3C-did--identifier-green)
![W3C DID Core Properties](https://img.shields.io/badge/W3C-did--core--properties-green)
![W3C DID Production](https://img.shields.io/badge/W3C-did--production-green)
![W3C DID Resolution](https://img.shields.io/badge/W3C-did--resolution-green)
![W3C DID URL Dereferencing](https://img.shields.io/badge/W3C-did--url--dereferencing-green)
```

---

## 13. Integration with zcap-dotnet

### 13.1 Bridge Interface

The primary integration point between NetDid and zcap-dotnet is DID URL Dereferencing — the W3C §7.2 standard mechanism for resolving a DID URL to the specific resource it identifies. ZCAP-LD invocation proofs reference a `verificationMethod` by DID URL (e.g., `did:key:z6Mkf...#z6Mkf...`), so zcap-dotnet needs to dereference that URL to obtain the actual public key material.

**Primary interface**: `IDidUrlDereferencer` (defined in §10.4) is the standard W3C-compliant interface that zcap-dotnet consumes directly:

```csharp
// zcap-dotnet verifying a ZCAP invocation — standard path via IDidUrlDereferencer:
var didUrl = invocation.Proof.VerificationMethod; // "did:key:z6Mkf...#z6Mkf..."

var result = await dereferencer.DereferenceAsync(didUrl);
if (result.DereferencingMetadata.Error is not null)
    throw new VerificationException($"Cannot dereference {didUrl}: {result.DereferencingMetadata.Error}");

// DereferenceAsync returns a VerificationMethod — the W3C data model with
// PublicKeyMultibase / PublicKeyJwk. To get verification-ready KeyType + raw bytes,
// use the convenience wrapper (IVerificationMethodResolver) shown below.
var vm = result.ContentStream as VerificationMethod
    ?? throw new VerificationException($"Expected VerificationMethod, got {result.ContentStream?.GetType().Name}");
```

**Convenience wrapper**: For consumers that only need verification method resolution (a common case), NetDid also provides `IVerificationMethodResolver` — a thin wrapper around `IDidUrlDereferencer` that handles the type extraction:

```csharp
public interface IVerificationMethodResolver
{
    /// Convenience method: dereference a DID URL and extract the verification method.
    /// Returns null if the URL cannot be dereferenced or does not point to a verification method.
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

/// Default implementation delegates to IDidUrlDereferencer and extracts
/// verification-ready key material from the W3C data-model properties.
public sealed class DefaultVerificationMethodResolver : IVerificationMethodResolver
{
    private readonly IDidUrlDereferencer _dereferencer;

    public DefaultVerificationMethodResolver(IDidUrlDereferencer dereferencer)
        => _dereferencer = dereferencer;

    public async Task<ResolvedVerificationMethod?> ResolveVerificationMethodAsync(
        string didUrl, CancellationToken ct = default)
    {
        var result = await _dereferencer.DereferenceAsync(didUrl, ct: ct);
        if (result.ContentStream is not VerificationMethod vm)
            return null;

        // Extract KeyType + raw public key bytes from the representation stored
        // in the VerificationMethod. Multikey/Multibase is the preferred path;
        // JWK is the fallback.
        KeyType keyType;
        byte[] publicKey;

        if (vm.PublicKeyMultibase is not null)
        {
            // Multibase-decode → multicodec-decode → (KeyType, rawKeyBytes)
            var prefixed = MultibaseEncoder.Decode(vm.PublicKeyMultibase);
            (keyType, publicKey) = MulticodecEncoder.Decode(prefixed);
        }
        else if (vm.PublicKeyJwk is not null)
        {
            (keyType, publicKey) = JwkConverter.ExtractPublicKey(vm.PublicKeyJwk);
        }
        else if (vm.BlockchainAccountId is not null)
        {
            // BlockchainAccountId (CAIP-10) contains only an Ethereum address — the
            // keccak256 hash of the public key, not the key itself. Standard signature
            // verification requires the full public key, so this path cannot produce a
            // ResolvedVerificationMethod. Callers verifying against address-only VMs must
            // use ecrecover-based verification (recover the public key from the signature,
            // derive the address, compare). See §8.5 for how did:ethr resolution produces
            // VMs with full public key material when available from on-chain events.
            return null;
        }
        else
        {
            return null; // No recognized key material representation
        }

        return new ResolvedVerificationMethod
        {
            Id = vm.Id,
            KeyType = keyType,
            PublicKey = publicKey,
            Controller = vm.Controller.ToString()
        };
    }
}
```

### 13.2 Usage in zcap-dotnet

```csharp
// Option A — direct use of IDidUrlDereferencer (W3C-standard):
// Returns the VerificationMethod data model (PublicKeyMultibase, PublicKeyJwk, etc.).
// The caller must extract key material manually — prefer Option B for verification.
var result = await dereferencer.DereferenceAsync(invocation.Proof.VerificationMethod);
var vm = result.ContentStream as VerificationMethod;

// Option B — convenience wrapper (preferred for verification):
// Returns a ResolvedVerificationMethod with KeyType + raw PublicKey bytes,
// ready for cryptographic operations.
var resolved = await verificationMethodResolver.ResolveVerificationMethodAsync(
    invocation.Proof.VerificationMethod);

bool signatureValid = cryptoProvider.Verify(
    resolved.KeyType,
    resolved.PublicKey,
    invocation.SignedPayload,
    invocation.Proof.SignatureBytes);
```

### 13.3 Signing with DID Keys

For creating ZCAP invocations, zcap-dotnet needs to sign with a DID's key via `ISigner`:

```csharp
// The caller provides their DID and an ISigner (from KeyPair or key store):
var did = "did:key:z6Mkf...";
var signer = await keyStore.CreateSignerAsync("my-signing-key");
var signature = await signer.SignAsync(payload);

// The ZCAP invocation proof references:
// "verificationMethod": "did:key:z6Mkf...#z6Mkf..."
// "proofValue": "<base64url-signature>"
```

### 13.4 Dual-Identity Pattern in ZCAP Context

When using the dual-identity pattern (see Appendix A), zcap-dotnet signs ZCAPs with the did:key identity. The discoverable identity (did:webvh or did:ethr) must be known to the verifier through an out-of-band channel — typically the ZCAP delegation chain or a prior relationship (see §A.4). Once both DIDs are known, `IDualIdentityManager.VerifyLinkAsync` confirms key equivalence and `alsoKnownAs`, and `GetVerifiedServicesAsync` extracts the TurtleShell PDS endpoint. The ZCAP itself is valid because the key is the same — the DID is just a different pointer to it.

---

## 14. Monorepo Structure

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
│   │   ├── DidContentTypes.cs
│   │   ├── IKeyGenerator.cs
│   │   ├── IKeyStore.cs
│   │   ├── ISigner.cs
│   │   ├── ICryptoProvider.cs
│   │   ├── Model/
│   │   │   ├── Did.cs
│   │   │   ├── DidDocument.cs
│   │   │   ├── VerificationMethod.cs
│   │   │   ├── Service.cs
│   │   │   ├── VerificationRelationshipEntry.cs
│   │   │   ├── DidResolutionResult.cs
│   │   │   ├── DidResolutionMetadata.cs
│   │   │   ├── DidResolutionOptions.cs
│   │   │   ├── DidDocumentMetadata.cs
│   │   │   ├── DidCreateResult.cs
│   │   │   ├── DidUpdateResult.cs
│   │   │   ├── DidDeactivateResult.cs
│   │   │   ├── DidUrl.cs
│   │   │   ├── DidUrlDereferencingResult.cs
│   │   │   ├── DereferencingMetadata.cs
│   │   │   └── DidUrlDereferencingOptions.cs
│   │   ├── Crypto/
│   │   │   ├── DefaultCryptoProvider.cs
│   │   │   ├── DefaultKeyGenerator.cs
│   │   │   ├── DefaultBbsCryptoProvider.cs
│   │   │   ├── KeyPairSigner.cs
│   │   │   ├── KeyStoreSigner.cs
│   │   │   ├── KeyPair.cs
│   │   │   ├── StoredKeyInfo.cs
│   │   │   ├── KeyType.cs
│   │   │   ├── Native/
│   │   │   │   └── ZkryptiumNative.cs       # P/Invoke declarations for BBS+ FFI
│   │   │   └── Jcs/
│   │   │       └── JsonCanonicalization.cs
│   │   ├── runtimes/                        # Platform-specific native libraries
│   │   │   └── osx-arm64/native/            # (additional RIDs as built)
│   │   ├── Encoding/
│   │   │   ├── MulticodecEncoder.cs
│   │   │   ├── MultibaseEncoder.cs
│   │   │   ├── Base58Btc.cs
│   │   │   └── Base64UrlNoPadding.cs
│   │   ├── Parsing/
│   │   │   └── DidParser.cs
│   │   ├── Serialization/
│   │   │   └── DidDocumentSerializer.cs
│   │   ├── Resolution/
│   │   │   ├── CompositeDidResolver.cs
│   │   │   ├── CachingDidResolver.cs
│   │   │   ├── IDidUrlDereferencer.cs
│   │   │   ├── DefaultDidUrlDereferencer.cs
│   │   │   ├── IVerificationMethodResolver.cs
│   │   │   └── DefaultVerificationMethodResolver.cs
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
│   │   │   └── Base58BtcTests.cs
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
├── native/
│   └── zkryptium-ffi/                  # Rust FFI shim for BBS+ signatures
│       ├── Cargo.toml
│       ├── src/lib.rs
│       ├── build-all.sh                # Cross-platform build script
│       └── README.md
│
└── docs/
    ├── getting-started.md
    ├── did-key-guide.md
    ├── did-peer-guide.md
    ├── did-webvh-guide.md
    ├── did-ethr-guide.md
    ├── dual-identity-pattern.md
    ├── key-management-guide.md
    └── w3c-conformance.md
```

---

## 15. Testing Strategy

### 15.1 Test Pyramid

```
              ┌──────────────────┐
              │  W3C Conformance │  ← External test suite (Node.js)
              │  (authoritative) │
             ┌┴──────────────────┴┐
             │  Integration Tests  │  ← Real networks (Sepolia, HTTP)
             │                     │
            ┌┴─────────────────────┴┐
            │  W3C Conformance       │  ← Internal xUnit mirror
            │  (internal, fast)      │
           ┌┴───────────────────────┴┐
           │   Unit Tests             │  ← Every class, every edge case
           │   (many, fast)           │
           └──────────────────────────┘
```

### 15.2 Test Infrastructure

| Tool                 | Usage                                                                      |
| -------------------- | -------------------------------------------------------------------------- |
| **xUnit**            | Test framework                                                             |
| **FluentAssertions** | Readable assertions                                                        |
| **NSubstitute**      | Mocking `IEthereumRpcClient`, `IWebVhHttpClient`                           |
| **Verify**           | Snapshot testing for DID Document serialization (catch unintended changes) |
| **Bogus**            | Generate random test data                                                  |
| **WireMock.Net**     | Mock HTTP servers for webvh endpoints                                      |
| **Testcontainers**   | Ganache/Hardhat container for did:ethr integration tests                   |

### 15.3 Test Categories

```csharp
[Trait("Category", "Unit")]              // No I/O, no Docker, no network
[Trait("Category", "Integration")]       // Requires Docker or network
[Trait("Category", "W3CConformance")]    // Internal W3C conformance tests
[Trait("Category", "W3CExternal")]       // Marks tests driven by external W3C suite
[Trait("Category", "Network")]           // Requires real network (Sepolia testnet)
```

### 15.4 Key Test Scenarios

**Encoding/Decoding Tests:**

- Multicodec round-trip for all 7 key types (Ed25519, X25519, P-256, P-384, secp256k1, BLS12-381 G1, BLS12-381 G2)
- Multibase round-trip for base58btc, base64url, base32lower
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

- Same Ed25519 key produces consistent DID Documents across did:key, did:peer:0, did:webvh
- CompositeDidResolver routes to correct method
- CachingDidResolver caches and expires correctly
- VerificationMethodResolver extracts correct key material from any method

---

## 16. Implementation Phases

### Phase 1: Core Foundation (Week 1-2) — COMPLETE

| Item | Description                                                                                                              | Status |
| ---- | ------------------------------------------------------------------------------------------------------------------------ | ------ |
| 1.1  | Monorepo scaffolding: solution, projects, build props, CI pipeline                                                       | Done   |
| 1.2  | `NetDid.Core`: DID Document model, serialization, DidParser                                                              | Done   |
| 1.3  | Cryptographic primitives: `IKeyGenerator`, `ICryptoProvider` with Ed25519, P-256, P-384, secp256k1, BLS12-381 G1/G2      | Done   |
| 1.3b | BBS+ cryptographic primitives: `IBbsCryptoProvider` with BLS12-381 G2, multi-message sign, derive proof, verify proof    | Done   |
| 1.3c | JCS (JSON Canonicalization Scheme, RFC 8785) implementation for Data Integrity Proofs                                    | Done   |
| 1.4  | Multicodec and Multibase encoding/decoding                                                                               | Done   |
| 1.5  | `IKeyStore` interface + `InMemoryKeyStore`                                                                               | Done   |
| 1.6  | JWK conversion utilities                                                                                                 | Done   |
| 1.7  | `CompositeDidResolver`, `CachingDidResolver`, `DefaultDidUrlDereferencer`                                                | Done   |
| 1.8  | Unit tests for all Core code (219 tests, 0 failures, 0 warnings)                                                        | Done   |

**Deliverable**: Core library compiles with zero warnings. All cryptographic primitives fully implemented and tested including BLS12-381 and BBS+ selective disclosure.

#### Phase 1 Implementation Summary

**Cryptographic primitives** (7 key types, 219 tests):
- Ed25519, X25519, P-256, P-384, secp256k1 — implemented using NSec.Cryptography, System.Security.Cryptography, and NBitcoin.Secp256k1
- BLS12-381 G1/G2 key generation and sign/verify — implemented using `Nethermind.Crypto.Bls` (C# wrapper around Supranational's `blst` C library). G1 public keys are 48 bytes compressed, G2 public keys are 96 bytes compressed, private keys are 32-byte scalars. The G2 variant uses `P2.Generator().Mult(scalar)` for key derivation since P2 lacks `FromSk()`. Pairing-based signature verification uses the `Pairing` class with `Aggregate` + `Commit` + `FinalVerify`
- BBS+ multi-message signatures with selective disclosure — implemented via a Rust FFI shim (`native/zkryptium-ffi/`) wrapping the [zkryptium](https://github.com/Cybersecurity-LINKS/zkryptium) crate (IETF draft-irtf-cfrg-bbs-signatures-10, BLS12-381-SHA-256 ciphersuite). The shim exposes 6 C-ABI functions (`bbs_keygen`, `bbs_sk_to_pk`, `bbs_sign`, `bbs_verify`, `bbs_proof_gen`, `bbs_proof_verify`) consumed via `[LibraryImport]` P/Invoke source generation. Messages and indices are serialized as flat little-endian TLV buffers across the FFI boundary. Signatures are 80 bytes; proofs are variable-length

**Native interop architecture**:
```
Rust (zkryptium crate, Apache 2.0)
  └── native/zkryptium-ffi/src/lib.rs    (C-ABI extern functions)
       └── libzkryptium_ffi.{dylib,so,dll}  (per-platform native binary)
            └── Crypto/Native/ZkryptiumNative.cs  ([LibraryImport] P/Invoke)
                 └── Crypto/DefaultBbsCryptoProvider.cs  (managed IBbsCryptoProvider)
```

**Test coverage**: 219 unit tests across 19 test files covering all public API surface — cryptographic operations (keygen, sign/verify, key agreement, BBS+ selective disclosure), encoding (multibase, multicodec, base58, base64url), serialization (JSON-LD/JSON round-trips, polymorphic DID Document properties), resolution (composite routing, caching, URL dereferencing), key storage (InMemoryKeyStore), JWK conversion, and JSON canonicalization (RFC 8785).

### Phase 2: did:key + did:peer (Week 3-4)

| Item | Description                                                                                   |
| ---- | --------------------------------------------------------------------------------------------- |
| 2.1  | `DidKeyMethod`: create and resolve for Ed25519, X25519, P-256, P-384, secp256k1, BLS12-381 G2 |
| 2.2  | X25519 derivation from Ed25519                                                                |
| 2.3  | W3C CCG did:key test vectors passing                                                          |
| 2.4  | `DidPeerMethod`: numalgo 0, numalgo 2, numalgo 4                                              |
| 2.5  | Numalgo 2 service abbreviation encoder/decoder                                                |
| 2.6  | DIF did:peer test vectors passing                                                             |
| 2.7  | W3C conformance tests (internal) for both methods                                             |
| 2.8  | W3C DID Test Suite fixture generation for did:key and did:peer                                |

**Deliverable**: did:key and did:peer fully working. First W3C conformance run passes.

### Phase 3: did:webvh (Week 5-7) — COMPLETE

| Item | Description                                                     | Status |
| ---- | --------------------------------------------------------------- | ------ |
| 3.1  | Log entry model and JSON Lines parser                           | Done   |
| 3.2  | SCID generation from genesis entry                              | Done   |
| 3.3  | Data Integrity Proof creation (eddsa-jcs-2022) and verification | Done   |
| 3.4  | Hash chain validation across log entries                        | Done   |
| 3.5  | Create: genesis log entry generation                            | Done   |
| 3.6  | Resolve: fetch log, validate chain, return document             | Done   |
| 3.7  | Update: append log entry with chaining                          | Done   |
| 3.8  | Pre-rotation manager                                            | Done   |
| 3.9  | Witness validation                                              | Done   |
| 3.10 | Deactivation                                                    | Done   |
| 3.11 | did:web backwards compatibility conversion                      | Done   |
| 3.12 | `IWebVhHttpClient` with mock for testing                        | Done   |
| 3.13 | W3C conformance tests                                           | Done   |

**Deliverable**: did:webvh full CRUD operational. Log chain validation hardened.

#### Phase 3 Implementation Summary

**did:webvh method** (47 dedicated tests + W3C conformance coverage):
- Full CRUD lifecycle: Create, Resolve, Update, Deactivate with cryptographically chained JSON Lines log
- SCID (Self-Certifying Identifier) generation via two-pass algorithm: JCS canonicalize → SHA-256 → multihash → base58btc multibase
- Data Integrity Proofs (eddsa-jcs-2022) engine in NetDid.Core for reuse by future methods
- Hash chain validation across log entries with entry hash linking
- Pre-rotation manager with key commitment validation (SHA-256 hash commitments via nextKeyHashes)
- Witness validation with configurable threshold and weighted witness proofs
- did:web backwards compatibility: automatic did.json generation alongside did.jsonl
- HTTP client abstraction (`IWebVhHttpClient`) with mock for testing
- DID URL mapper: `did:webvh:<SCID>:<domain>` → `https://<domain>/.well-known/did.jsonl`
- Comprehensive samples with 7 usage examples (create, resolve, update, key rotation, deactivate, dual-identity)
- Web server setup documentation (ASP.NET Core, NGINX, Apache, Caddy, cloud hosting)

### Phase 4: did:ethr (Week 8-11)

| Item | Description                                                                      |
| ---- | -------------------------------------------------------------------------------- |
| 4.1  | secp256k1 key support (generate, sign, recover)                                  |
| 4.2  | Keccak-256 hash implementation                                                   |
| 4.3  | Ethereum address derivation from secp256k1 public key                            |
| 4.4  | RLP encoding for transaction construction                                        |
| 4.5  | ERC-1056 ABI encoding: function selectors, parameter encoding                    |
| 4.6  | `IEthereumRpcClient` interface and default HTTP JSON-RPC implementation          |
| 4.7  | Event log parser: `DIDOwnerChanged`, `DIDDelegateChanged`, `DIDAttributeChanged` |
| 4.8  | Create: key generation + address derivation (no on-chain tx needed)              |
| 4.9  | Resolve: query events, replay to build DID Document                              |
| 4.10 | Update: `setAttribute` for services, `addDelegate` for keys, `changeOwner`       |
| 4.11 | Meta-transaction support (EIP-712 style signed messages)                         |
| 4.12 | Deactivation: change owner to null address                                       |
| 4.13 | Multi-network configuration and routing                                          |
| 4.14 | Integration tests against Sepolia testnet (or Hardhat in Docker)                 |
| 4.15 | W3C conformance tests                                                            |

**Deliverable**: did:ethr full CRUD on any EVM network. Sepolia integration tests passing.

### Phase 5: W3C Test Suite & Polish (Week 12-14)

| Item | Description                                                                           |
| ---- | ------------------------------------------------------------------------------------- |
| 5.1  | W3C DID Test Suite CLI fixture generator for all 4 methods                            |
| 5.2  | Optional resolution HTTP endpoint for W3C did-resolution suite                        |
| 5.3  | Full W3C DID Test Suite run in CI — all 5 suites, all 4 methods                       |
| 5.4  | Fix any conformance failures                                                          |
| 5.5  | `NetDid.Extensions.DependencyInjection` package                                       |
| 5.6  | zcap-dotnet bridge: `IDidUrlDereferencer` + `IVerificationMethodResolver` integration |
| 5.7  | README, getting-started docs, per-method guides                                       |
| 5.8  | NuGet packaging and publish pipeline                                                  |
| 5.9  | Dual-identity pattern documentation and example                                       |
| 5.10 | Performance benchmarks for resolution (each method)                                   |

**Deliverable**: All W3C tests green for all 4 methods. NuGet packages published. zcap-dotnet integration verified.

---

## Appendix A: Dual-Identity Design Pattern

### A.1 Problem Statement

Some DID methods (notably `did:key`) are excellent for cryptographic operations — signing ZCAP invocations, issuing credentials, authenticating — because they are simple, offline-capable, and have no dependency on external infrastructure. However, `did:key` cannot carry service endpoints because the DID Document is algorithmically derived from the key alone. There is no place to advertise "here is my TurtleShell PDS at https://node1.example.com."

Conversely, methods like `did:webvh` and `did:ethr` support rich DID Documents with service endpoints, making them ideal for discovery. But they carry operational overhead: web hosting or on-chain gas costs.

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
│  │  did:ethr:0x1:0xabc...     │      discovery                │
│  │                             │    - TurtleShell PDS           │
│  │  • Has service endpoints    │      advertisement            │
│  │  • Updatable                │    - Replication peer          │
│  │  • alsoKnownAs links to     │      discovery                │
│  │    the did:key              │    - Public profile           │
│  └─────────────────────────────┘                              │
└──────────────────────────────────────────────────────────────┘
```

### A.3 How It Works

**Step 1: Generate a key pair and create a signer.**

```csharp
var keyGen = new DefaultKeyGenerator();
var keyPair = keyGen.Generate(KeyType.Ed25519);
var signer = new KeyPairSigner(keyPair, cryptoProvider);

// Or with an HSM-backed key store:
// var keyInfo = await keyStore.GenerateAsync("alice-main-key", KeyType.Ed25519);
// var signer = await keyStore.CreateSignerAsync("alice-main-key");
```

**Step 2: Create the signing identity (did:key) from the SAME key.**

```csharp
var didKeyMethod = new DidKeyMethod(keyGen);
var signingIdentity = await didKeyMethod.CreateAsync(new DidKeyCreateOptions
{
    KeyType = KeyType.Ed25519,
    ExistingKey = signer,  // Same key from Step 1 — did:key is derived from its public key
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
    UpdateKey = signer,  // Same Ed25519 key, via ISigner (HSM-safe)
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

### A.4 Discovery Prerequisite

The dual-identity pattern does **not** include a built-in discovery mechanism. DID resolution is one-directional (DID → Document) — there is no reverse index from a `did:key` to the discoverable DIDs that reference it. The verifier must already know the discoverable DID through an **out-of-band channel** before the verification flow begins.

Typical out-of-band channels:

- **ZCAP delegation chain**: When a root ZCAP capability is delegated, the delegation context includes both the signing `did:key` and the discoverable DID. Downstream verifiers receive both through the chain.
- **Prior relationship**: During onboarding or initial key exchange, the entity shares both their signing and discoverable DIDs (e.g., in a DIDComm introduction, a trust registry entry, or an application-level profile).
- **Application registry**: The consuming application maintains a mapping of signing DIDs to discoverable DIDs, populated when identities are registered.

NetDid itself is agnostic to how the mapping is established — it only provides the tools to **verify** the link once both DIDs are known.

### A.5 Verification Flow

Given a ZCAP invocation signed by `did:key:z6Mkf...#z6Mkf...` and a previously known discoverable DID `did:webvh:Qm...:alice.example.com`:

1. Resolve `did:key:z6Mkf...` → get the Ed25519 public key.
2. Verify the ZCAP signature. ✅
3. If the verifier needs to discover the owner's PDS (for replication, for example):
   - Resolve the known discoverable identity `did:webvh:Qm...:alice.example.com`.
   - Verify that its DID Document contains a verification method with the same public key as the signing `did:key`. This proves the same entity controls both identities.
   - Verify that `alsoKnownAs` includes the signing `did:key`. This confirms the link is intentional, not coincidental.
   - Extract the `TurtleShellPds` service endpoint from the resolved DID Document.

### A.6 Security Considerations

- **Key equivalence verification is REQUIRED**: The verifier MUST confirm that the discoverable identity's DID Document contains a verification method with the same public key as the signing did:key. The `alsoKnownAs` claim alone is insufficient — anyone could claim it.
- **Bidirectional linking is RECOMMENDED**: Ideally both documents reference each other, but since did:key documents are algorithmic, the link from discoverable → did:key (via `alsoKnownAs`) combined with key equivalence is sufficient.
- **The signing identity (did:key) is the source of authority**: ZCAPs are bound to it, not to the discoverable identity. The discoverable identity is an index, not an authority.
- **Out-of-band channel integrity**: The security of the dual-identity pattern depends on the integrity of the channel through which the verifier learns the discoverable DID. If an attacker can substitute a different discoverable DID (one that shares the same key but points to a malicious PDS), the verifier would be misled. Applications SHOULD establish the mapping over an authenticated channel.

### A.7 NetDid Helper

NetDid provides a utility for verifying dual-identity relationships. Both DIDs must be known to the caller — NetDid does not perform discovery:

```csharp
public interface IDualIdentityManager
{
    /// Verify that two DIDs share the same key material and that the discoverable
    /// identity's alsoKnownAs includes the signing identity.
    /// Both DIDs must be provided by the caller (obtained out-of-band).
    Task<DualIdentityVerification> VerifyLinkAsync(
        string signingDid, string discoverableDid, CancellationToken ct = default);

    /// Extract service endpoints from a discoverable identity linked to a signing identity.
    /// Performs full verification (key equivalence + alsoKnownAs) before returning services.
    /// Both DIDs must be provided by the caller (obtained out-of-band).
    Task<IReadOnlyList<Service>> GetVerifiedServicesAsync(
        string signingDid, string discoverableDid, string? serviceType = null, CancellationToken ct = default);
}

public sealed record DualIdentityVerification
{
    public required bool KeysMatch { get; init; }
    public required bool AlsoKnownAsLinkPresent { get; init; }
    public required string? MatchedKeyId { get; init; }
    public bool IsValid => KeysMatch && AlsoKnownAsLinkPresent;
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
| ERC-1056 (did:ethr)              | https://eips.ethereum.org/EIPS/eip-1056                                                        | —       | ERC Draft          |
| did:ethr Resolver Spec           | https://github.com/decentralized-identity/ethr-did-resolver/blob/master/doc/did-method-spec.md | —       | DIF                |
| EthereumDIDRegistry Contract     | https://github.com/uport-project/ethr-did-registry                                             | —       | uPort              |
| Multicodec                       | https://github.com/multiformats/multicodec                                                     | —       | Multiformats       |
| Multibase                        | https://github.com/multiformats/multibase                                                      | —       | Multiformats       |
| Data Integrity (eddsa-jcs-2022)  | https://www.w3.org/TR/vc-di-eddsa/                                                             | —       | W3C CR             |
| BBS Signature Scheme             | https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-07.html                         | -07     | IETF CFRG Draft    |
| Data Integrity BBS Cryptosuites  | https://www.w3.org/TR/vc-di-bbs/                                                               | —       | W3C CR             |
| RFC 8785 (JCS)                   | https://tools.ietf.org/html/rfc8785                                                            | —       | IETF Proposed Std  |
| RFC 1035 (DNS)                   | https://tools.ietf.org/html/rfc1035                                                            | —       | IETF Standard      |

---

## Appendix C: Glossary

| Term                          | Definition                                                                                                                                                                                                                              |
| ----------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **DID**                       | Decentralized Identifier — a URI that resolves to a DID Document without a centralized registry.                                                                                                                                        |
| **DID Document**              | A document containing public keys, service endpoints, and metadata associated with a DID. Can be represented as `application/did+ld+json` (JSON-LD, with `@context`) or `application/did+json` (plain JSON, without `@context`).        |
| **DID Method**                | A specification defining how to create, resolve, update, and deactivate a specific type of DID (e.g., did:key, did:ethr).                                                                                                               |
| **DID URL**                   | A DID plus optional path, query, and/or fragment components. Used to reference specific elements within a DID Document.                                                                                                                 |
| **Verification Method**       | A public key or other mechanism in a DID Document used to verify digital signatures or perform key agreement.                                                                                                                           |
| **Verification Relationship** | The purpose a verification method serves: authentication, assertion, key agreement, capability invocation, or capability delegation.                                                                                                    |
| **SCID**                      | Self-Certifying Identifier — used in did:webvh to cryptographically bind the DID to its genesis state.                                                                                                                                  |
| **ERC-1056**                  | Ethereum Improvement Proposal defining the `EthereumDIDRegistry` smart contract for lightweight identity management.                                                                                                                    |
| **Multicodec**                | A self-describing codec prefix system. Prepended to raw key bytes to indicate the key type.                                                                                                                                             |
| **Multibase**                 | A self-describing base encoding. The first character indicates the encoding (e.g., `z` = base58btc).                                                                                                                                    |
| **Numalgo**                   | "Numeric algorithm" — the variant selector in did:peer (0, 2, or 4), each defining a different generation and resolution algorithm.                                                                                                     |
| **ZCAP-LD**                   | Authorization Capabilities for Linked Data — an object-capability security model where capabilities are cryptographically delegatable tokens.                                                                                           |
| **BBS+ / BBS Signatures**     | A pairing-based signature scheme over BLS12-381 that supports multi-message signing, selective disclosure (revealing only chosen attributes), and zero-knowledge proof derivation. Standardized as IETF draft-irtf-cfrg-bbs-signatures. |
| **BLS12-381**                 | A pairing-friendly elliptic curve with two groups (G1, G2) and a target group (GT). G2 public keys (96 bytes) are used for BBS+ signing. Named after Barreto-Lynn-Scott with a 381-bit field.                                           |
| **Selective Disclosure**      | The ability for a credential holder to present only specific attributes from a signed credential without revealing the full credential, enabled by BBS+ proof derivation.                                                               |
| **JCS**                       | JSON Canonicalization Scheme (RFC 8785) — deterministic serialization of JSON for signing. Required by the `eddsa-jcs-2022` and `bbs-2023` Data Integrity cryptosuites.                                                                 |
| **Dual-Identity Pattern**     | Using a did:key (for signing) paired with a discoverable DID (did:webvh or did:ethr, for service endpoints), linked by shared key material and `alsoKnownAs`. The discoverable DID must be obtained out-of-band (see §A.4).             |
| **HLC**                       | Hybrid Logical Clock — used in the TurtleShell PDS for causal ordering across replicated nodes.                                                                                                                                         |
| **CRDT**                      | Conflict-free Replicated Data Type — data structures that can be replicated across nodes and merged without coordination.                                                                                                               |

---
