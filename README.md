# NetDid

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![.NET](https://img.shields.io/badge/.NET-10.0-purple.svg)](https://dotnet.microsoft.com/)

A specification-compliant .NET library for Decentralized Identifiers (DIDs). NetDid provides a unified interface for creating, resolving, updating, and deactivating DIDs across multiple DID methods.

## Features

- **Four DID methods**: `did:key`, `did:peer`, `did:webvh`, `did:ethr`
- **Seven key types**: Ed25519, X25519, P-256, P-384, secp256k1, BLS12-381 G1/G2
- **W3C DID Core 1.0** compliant DID Document model and serialization
- **Dual content types**: `application/did+ld+json` (JSON-LD) and `application/did+json`
- **Pluggable key storage**: Bring your own HSM, vault, or file-based key store via `IKeyStore`
- **Resolver infrastructure**: Composite routing, caching, and W3C DID URL dereferencing
- **JWK conversion**: Round-trip between raw key bytes and JSON Web Keys
- **Zero framework opinions**: No ASP.NET dependency, no DI container required

## Installation

```bash
dotnet add package NetDid.Core
```

> **Note**: NetDid targets .NET 10. Ensure you have the [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0) installed.

## Quick Start

### Generate a Key Pair

```csharp
using NetDid.Core.Crypto;

var keyGen = new DefaultKeyGenerator();
var keyPair = keyGen.Generate(KeyType.Ed25519);

Console.WriteLine($"Public key (multibase): {keyPair.MultibasePublicKey}");
```

### Build a DID Document

```csharp
using NetDid.Core.Model;

var doc = new DidDocument
{
    Id = new Did("did:example:123"),
    Controller = new List<Did> { new("did:example:123") },
    VerificationMethod = new List<VerificationMethod>
    {
        new()
        {
            Id = "did:example:123#key-1",
            Type = "Multikey",
            Controller = new Did("did:example:123"),
            PublicKeyMultibase = keyPair.MultibasePublicKey
        }
    },
    Authentication = new List<VerificationRelationshipEntry>
    {
        VerificationRelationshipEntry.FromReference("did:example:123#key-1")
    }
};
```

### Serialize a DID Document

```csharp
using NetDid.Core.Serialization;

// JSON-LD (includes @context)
string jsonLd = DidDocumentSerializer.Serialize(doc, DidContentTypes.JsonLd);

// Plain JSON (omits @context)
string json = DidDocumentSerializer.Serialize(doc, DidContentTypes.Json);

// Deserialize
DidDocument restored = DidDocumentSerializer.Deserialize(jsonLd, DidContentTypes.JsonLd);
```

### Sign and Verify Data

```csharp
using NetDid.Core.Crypto;

var crypto = new DefaultCryptoProvider();
var signer = new KeyPairSigner(keyPair, crypto);

byte[] data = "Hello, DIDs!"u8.ToArray();
byte[] signature = await signer.SignAsync(data);

bool valid = crypto.Verify(KeyType.Ed25519, keyPair.PublicKey, data, signature);
```

### Use the In-Memory Key Store

```csharp
using NetDid.Core.KeyStore;

var store = new InMemoryKeyStore(keyGen, crypto);
var info = await store.GenerateAsync("my-signing-key", KeyType.Ed25519);

ISigner signer = await store.CreateSignerAsync("my-signing-key");
byte[] sig = await signer.SignAsync("payload"u8.ToArray());
```

## Architecture

NetDid is built around a small set of core interfaces:

| Interface | Purpose |
|-----------|---------|
| `IDidMethod` | Unified CRUD operations for a DID method (create, resolve, update, deactivate) |
| `IDidResolver` | Standalone DID resolution (for consumers who only need to resolve) |
| `IKeyStore` | Pluggable key storage — swap in HSM, vault, or cloud KMS |
| `ISigner` | Signing abstraction — works with in-memory keys or secure enclaves |
| `IKeyGenerator` | Key pair generation and derivation for all supported key types |
| `ICryptoProvider` | Low-level sign, verify, and key agreement operations |

### Resolution Pipeline

```
DID string
  --> CompositeDidResolver (routes by method name)
    --> CachingDidResolver (IMemoryCache + TTL)
      --> IDidMethod.ResolveAsync()
        --> DidDocument
```

### DID URL Dereferencing

`DefaultDidUrlDereferencer` implements the W3C DID Core section 7.2 algorithm: parse URL, resolve the base DID, then select resources by fragment, service query, or path.

## Project Structure

```
netdid/
├── src/
│   └── NetDid.Core/
│       ├── Crypto/              # Key types, providers, signers
│       │   └── Jcs/             # JSON Canonicalization (RFC 8785)
│       ├── Encoding/            # Multibase, multicodec, Base58, Base64Url
│       ├── Exceptions/          # Domain-specific exception hierarchy
│       ├── Jwk/                 # JWK <-> raw key conversion
│       ├── KeyStore/            # InMemoryKeyStore implementation
│       ├── Model/               # DID Document, result types, options
│       ├── Parsing/             # DID syntax validation and URL parsing
│       ├── Resolution/          # Composite, caching, and URL dereferencing
│       └── Serialization/       # DID Document JSON/JSON-LD serializer
├── tests/
│   └── NetDid.Core.Tests/       # 194 unit tests
├── Directory.Build.props        # Shared build settings (net10.0)
├── Directory.Packages.props     # Central NuGet version management
└── netdid.sln
```

## Building

```bash
dotnet build
```

## Testing

```bash
dotnet test
```

## Roadmap

NetDid is developed in four phases (see [NetDidPRD.md](NetDidPRD.md) for full details):

| Phase | Scope | Status |
|-------|-------|--------|
| **I** | Core Foundation — DID Document model, crypto primitives, encoding, serialization, resolver infrastructure | Complete |
| **II** | `did:key` and `did:peer` method implementations | Planned |
| **III** | `did:webvh` method implementation | Planned |
| **IV** | `did:ethr` method implementation | Planned |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup instructions, code conventions, and how to add new DID methods or key types.

## Security

See [SECURITY.md](SECURITY.md) for the security policy and how to report vulnerabilities.

## License

Licensed under the [Apache License 2.0](LICENSE).
