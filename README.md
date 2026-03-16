# NetDid

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![.NET](https://img.shields.io/badge/.NET-10.0-purple.svg)](https://dotnet.microsoft.com/)

A specification-compliant .NET library for Decentralized Identifiers (DIDs). NetDid provides a unified interface for creating, resolving, updating, and deactivating DIDs across multiple DID methods.

## Features

- **DID methods**: `did:key`, `did:peer`, and `did:webvh` (implemented), `did:ethr` (planned)
- **Seven key types**: Ed25519, X25519, P-256, P-384, secp256k1, BLS12-381 G1/G2
- **BBS+ signatures**: Multi-message signing with selective disclosure proofs (IETF draft-10)
- **W3C DID Core 1.0** compliant DID Document model and serialization
- **Dual content types**: `application/did+ld+json` (JSON-LD) and `application/did+json`
- **Pluggable key storage**: Bring your own HSM, vault, or file-based key store via `IKeyStore`
- **Resolver infrastructure**: Composite routing, caching, and W3C DID URL dereferencing (fragment, service, serviceType, verificationRelationship)
- **JWK conversion**: Round-trip between raw key bytes and JSON Web Keys
- **DI integration**: `services.AddNetDid()` for Microsoft.Extensions.DependencyInjection, or use standalone with zero framework opinions
- **Fluent document builder**: `new DidDocumentBuilder(did).AddVerificationMethod(...).Build()`

## Installation

```bash
dotnet add package NetDid.Core
dotnet add package NetDid.Method.Key    # did:key method
dotnet add package NetDid.Method.Peer   # did:peer method
dotnet add package NetDid.Method.WebVh  # did:webvh method
dotnet add package NetDid.Extensions.DependencyInjection  # Microsoft DI integration
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

### Sign and Verify Data

```csharp
var crypto = new DefaultCryptoProvider();
var signer = new KeyPairSigner(keyPair, crypto);

byte[] data = "Hello, DIDs!"u8.ToArray();
byte[] signature = await signer.SignAsync(data);

bool valid = crypto.Verify(KeyType.Ed25519, keyPair.PublicKey, data, signature);
```

## did:key

`did:key` is a deterministic, self-certifying DID method where the public key is encoded directly in the DID string. No network interaction is needed — resolution is purely algorithmic.

### Create a did:key

```csharp
using NetDid.Core.Crypto;
using NetDid.Method.Key;

var keyGen = new DefaultKeyGenerator();
var didKey = new DidKeyMethod(keyGen);

// Create with Ed25519 (most common)
var result = await didKey.CreateAsync(new DidKeyCreateOptions
{
    KeyType = KeyType.Ed25519
});

Console.WriteLine(result.Did);
// Output: did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK
```

Ed25519 keys automatically derive an X25519 key agreement key, so the DID Document will contain two verification methods: one for signing (Ed25519) and one for encryption (X25519).

### Resolve a did:key

```csharp
var resolved = await didKey.ResolveAsync("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");
var doc = resolved.DidDocument!;

Console.WriteLine($"VMs: {doc.VerificationMethod!.Count}");          // 2 (Ed25519 + X25519)
Console.WriteLine($"Auth: {doc.Authentication!.Count}");              // 1
Console.WriteLine($"Key Agreement: {doc.KeyAgreement!.Count}");       // 1
```

### Use an existing key (HSM / vault compatible)

```csharp
var crypto = new DefaultCryptoProvider();
var existingKeyPair = keyGen.Generate(KeyType.P256);
var signer = new KeyPairSigner(existingKeyPair, crypto);

var result = await didKey.CreateAsync(new DidKeyCreateOptions
{
    KeyType = KeyType.P256,
    ExistingKey = signer   // Works with any ISigner — HSM, vault, or in-memory
});
```

### JsonWebKey2020 representation

```csharp
var result = await didKey.CreateAsync(new DidKeyCreateOptions
{
    KeyType = KeyType.Ed25519,
    Representation = VerificationMethodRepresentation.JsonWebKey2020
});
// VM type: "JsonWebKey2020" with "publicKeyJwk" property
```

### BLS12-381 G2 for selective disclosure

```csharp
var result = await didKey.CreateAsync(new DidKeyCreateOptions
{
    KeyType = KeyType.Bls12381G2
});
// assertionMethod: yes (credential issuance with BBS+)
// authentication: no (BBS+ not suitable for challenge-response auth)
```

### Supported key types

| Key Type | Multicodec | VM Relationships |
|----------|-----------|------------------|
| Ed25519 | `0xed` | authentication, assertionMethod, capabilityInvocation, capabilityDelegation + X25519 keyAgreement |
| X25519 | `0xec` | keyAgreement only |
| P-256 | `0x8024` | authentication, assertionMethod, capabilityInvocation, capabilityDelegation |
| P-384 | `0x8124` | authentication, assertionMethod, capabilityInvocation, capabilityDelegation |
| secp256k1 | `0xe7` | authentication, assertionMethod, capabilityInvocation, capabilityDelegation |
| BLS12-381 G1 | `0xea` | assertionMethod, capabilityInvocation |
| BLS12-381 G2 | `0xeb` | assertionMethod, capabilityInvocation |

## did:peer

`did:peer` is designed for peer-to-peer interactions where DIDs don't need to be published to a ledger. Three numalgo variants are supported.

### Numalgo 0 — Inception key

Functionally identical to `did:key` but with a `did:peer:0` prefix. Useful when you want peer DID semantics with a single key.

```csharp
using NetDid.Core.Crypto;
using NetDid.Method.Peer;

var keyGen = new DefaultKeyGenerator();
var didPeer = new DidPeerMethod(keyGen);

var result = await didPeer.CreateAsync(new DidPeerCreateOptions
{
    Numalgo = PeerNumalgo.Zero,
    InceptionKeyType = KeyType.Ed25519
});

Console.WriteLine(result.Did);
// Output: did:peer:0z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH
```

### Numalgo 2 — Inline keys and services (DIDComm)

The most practical variant for DIDComm messaging. Keys and service endpoints are encoded directly in the DID string. Purpose codes follow the DIF peer-DID spec: `A`=assertion, `E`=encryption (key agreement), `V`=verification (authentication), `I`=capability invocation, `D`=capability delegation, `S`=service.

```csharp
var crypto = new DefaultCryptoProvider();
var authKey = keyGen.Generate(KeyType.Ed25519);
var agreeKey = keyGen.Generate(KeyType.X25519);

var result = await didPeer.CreateAsync(new DidPeerCreateOptions
{
    Numalgo = PeerNumalgo.Two,
    Keys =
    [
        new PeerKeyPurpose(new KeyPairSigner(authKey, crypto), PeerPurpose.Authentication),
        new PeerKeyPurpose(new KeyPairSigner(agreeKey, crypto), PeerPurpose.KeyAgreement)
    ],
    Services =
    [
        new Service
        {
            Id = "#didcomm",
            Type = "DIDCommMessaging",
            ServiceEndpoint = ServiceEndpointValue.FromUri("https://example.com/didcomm")
        }
    ]
});

Console.WriteLine(result.Did);
// Output: did:peer:2.Vz6Mkf5r...Ez6LSb...SeyJ0IjoiZG0i...
```

Resolution decodes everything from the DID string — no network call needed:

```csharp
var resolved = await didPeer.ResolveAsync(result.Did.Value);
var doc = resolved.DidDocument!;

Console.WriteLine(doc.Service![0].Type);                    // "DIDCommMessaging"
Console.WriteLine(doc.Service[0].ServiceEndpoint.Uri);      // "https://example.com/didcomm"
```

All five verification relationships are supported — use `PeerPurpose.Assertion`, `PeerPurpose.CapabilityInvocation`, or `PeerPurpose.CapabilityDelegation` to assign keys to additional relationships.

Service types are abbreviated in the DID string per the DIF spec (`DIDCommMessaging` → `dm`, `type` → `t`, `serviceEndpoint` → `s`).

### Numalgo 4 — Hash-based short/long form

Uses a SHA-256 hash as the short form and encodes the full input document as the long form. The long form is exchanged initially; subsequent interactions use the short form.

```csharp
var peer4Key = keyGen.Generate(KeyType.Ed25519);
var inputDoc = new DidDocument
{
    // Per spec: input document MUST NOT include id — it's assigned during creation
    VerificationMethod =
    [
        new VerificationMethod
        {
            Id = "#key-0",
            Type = "Multikey",
            PublicKeyMultibase = peer4Key.MultibasePublicKey
        }
    ],
    Authentication =
    [
        VerificationRelationshipEntry.FromReference("#key-0")
    ]
};

var result = await didPeer.CreateAsync(new DidPeerCreateOptions
{
    Numalgo = PeerNumalgo.Four,
    InputDocument = inputDoc
});

// Long-form DID (exchanged initially)
Console.WriteLine(result.Did);
// did:peer:4zQm...:<base64url-encoded-document>

// Resolution verifies the hash matches the encoded document
var resolved = await didPeer.ResolveAsync(result.Did.Value);
```

Short-form-only resolution returns `notFound` (requires prior long-form exchange).

## did:webvh

`did:webvh` (DID Web with Verifiable History) combines web-based hosting with a cryptographically verifiable log of all changes. Full CRUD with hash chain integrity, pre-rotation, and witness validation.

### Create a did:webvh

```csharp
using NetDid.Core.Crypto;
using NetDid.Core.Model;
using NetDid.Method.WebVh;

var keyGen = new DefaultKeyGenerator();
var crypto = new DefaultCryptoProvider();
var updateKey = keyGen.Generate(KeyType.Ed25519);
var signer = new KeyPairSigner(updateKey, crypto);

var httpClient = new DefaultWebVhHttpClient();
var didWebVh = new DidWebVhMethod(httpClient, crypto);

var result = await didWebVh.CreateAsync(new DidWebVhCreateOptions
{
    Domain = "example.com",
    UpdateKey = signer,
    Services =
    [
        new Service
        {
            Id = "#pds",
            Type = "TurtleShellPds",
            ServiceEndpoint = ServiceEndpointValue.FromUri("https://example.com/pds")
        }
    ]
});

Console.WriteLine(result.Did);
// Output: did:webvh:z6Rk8Rx...:example.com
```

The result includes `Artifacts["did.jsonl"]` (the verifiable log) and `Artifacts["did.json"]` (did:web backwards-compatible document). Host these at `https://example.com/.well-known/did.jsonl` and `did.json`. When `WitnessProofs` are provided, a `did-witness.json` artifact is also produced.

### Resolve a did:webvh

```csharp
var resolved = await didWebVh.ResolveAsync("did:webvh:z6Rk8Rx...:example.com");
var doc = resolved.DidDocument!;

Console.WriteLine(doc.Service![0].Type);  // "TurtleShellPds"
Console.WriteLine(resolved.DocumentMetadata!.VersionId);  // "1-z6Rk8Rx..."
```

Resolution fetches the `did.jsonl` log over HTTPS, validates the hash chain and Data Integrity Proofs, and returns the latest DID Document.

### Update (append to log)

```csharp
var updatedDoc = result.DidDocument with
{
    Service = [ result.DidDocument.Service![0], new Service
    {
        Id = $"{result.Did}#api",
        Type = "ApiEndpoint",
        ServiceEndpoint = ServiceEndpointValue.FromUri("https://api.example.com/v1")
    }]
};

var updateResult = await didWebVh.UpdateAsync(result.Did.Value, new DidWebVhUpdateOptions
{
    CurrentLogContent = (byte[])result.Artifacts!["did.jsonl"],
    SigningKey = signer,
    NewDocument = updatedDoc
});
// Re-host the updated did.jsonl
```

### Pre-rotation (key commitment)

```csharp
var nextKey = keyGen.Generate(KeyType.Ed25519);
var commitment = PreRotationManager.ComputeKeyCommitment(nextKey.MultibasePublicKey);

var result = await didWebVh.CreateAsync(new DidWebVhCreateOptions
{
    Domain = "example.com",
    UpdateKey = signer,
    EnablePreRotation = true,
    PreRotationCommitments = [commitment]
});
```

Pre-rotation commits to the next update key hash at creation time. Every subsequent update must rotate to the committed key, preventing unauthorized key changes even if the current key is compromised.

### Deactivate

```csharp
await didWebVh.DeactivateAsync(result.Did.Value, new DidWebVhDeactivateOptions
{
    CurrentLogContent = logContent,
    SigningKey = signer
});
```

## Serialization

```csharp
using NetDid.Core.Serialization;

// JSON-LD (includes @context)
string jsonLd = DidDocumentSerializer.Serialize(doc, DidContentTypes.JsonLd);

// Plain JSON (omits @context)
string json = DidDocumentSerializer.Serialize(doc, DidContentTypes.Json);

// Deserialize
DidDocument restored = DidDocumentSerializer.Deserialize(jsonLd, DidContentTypes.JsonLd);
```

## Key Store

```csharp
using NetDid.Core.KeyStore;

var store = new InMemoryKeyStore(keyGen, crypto);
var info = await store.GenerateAsync("my-signing-key", KeyType.Ed25519);

ISigner signer = await store.CreateSignerAsync("my-signing-key");
byte[] sig = await signer.SignAsync("payload"u8.ToArray());
```

## Document Builder

Build DID Documents programmatically with the fluent API:

```csharp
using NetDid.Core.Model;

var doc = new DidDocumentBuilder("did:example:123")
    .AddVerificationMethod(vm => vm
        .WithId("#key-1")
        .WithType("Multikey")
        .WithMultibasePublicKey("z6MkSigningKey"))
    .AddVerificationMethod(vm => vm
        .WithId("#key-2")
        .WithType("Multikey")
        .WithMultibasePublicKey("z6LSKeyAgree"))
    .AddAuthentication("#key-1")
    .AddAssertionMethod("#key-1")
    .AddKeyAgreement("#key-2")
    .AddService(svc => svc
        .WithId("#pds")
        .WithType("PersonalDataStore")
        .WithEndpoint("https://example.com/pds"))
    .Build();
```

The builder auto-sets `controller` to the document `id` when not explicitly specified. Validates required fields (`Id`, `Type`) at `Build()` time.

## Dependency Injection

For ASP.NET Core or any Microsoft DI host, use the builder pattern to register all methods in one call:

```csharp
using NetDid.Extensions.DependencyInjection;

services.AddNetDid(builder =>
{
    builder.AddDidKey();
    builder.AddDidPeer();
    builder.AddDidWebVh();
    builder.AddCaching(TimeSpan.FromMinutes(15));
});
```

Then inject `IDidManager` or `IDidResolver`:

```csharp
public class MyService(IDidManager manager)
{
    public async Task CreateIdentity()
    {
        var result = await manager.CreateAsync(new DidKeyCreateOptions
        {
            KeyType = KeyType.Ed25519
        });

        // Resolve any DID — auto-routes to the correct method
        var resolved = await manager.ResolveAsync(result.Did.Value);
    }
}
```

## Architecture

NetDid is built around a small set of core interfaces:

| Interface | Purpose |
|-----------|---------|
| `IDidManager` | Unified DID lifecycle manager — routes CRUD operations across registered methods |
| `IDidMethod` | Single DID method implementation (create, resolve, update, deactivate) |
| `IDidResolver` | Standalone DID resolution (for consumers who only need to resolve) |
| `IKeyStore` | Pluggable key storage — swap in HSM, vault, or cloud KMS |
| `ISigner` | Signing abstraction — works with in-memory keys or secure enclaves |
| `IKeyGenerator` | Key pair generation and derivation for all supported key types |
| `ICryptoProvider` | Low-level sign, verify, and key agreement operations |
| `IBbsCryptoProvider` | BBS+ multi-message signatures with selective disclosure |

### Resolution Pipeline

```
DID string
  --> CompositeDidResolver (routes by method name)
    --> CachingDidResolver (IMemoryCache + TTL)
      --> IDidMethod.ResolveAsync()
        --> DidDocument
```

### DID URL Dereferencing

`DefaultDidUrlDereferencer` implements the W3C DID Core section 7.2 algorithm: parse URL, resolve the base DID, then select resources by fragment, service ID or type query, or path. Supports `verificationRelationship` filtering and `text/uri-list` redirect with RFC 3986 URL resolution.

## Project Structure

```
netdid/
├── src/
│   ├── NetDid.Core/                         # Core abstractions, crypto, encoding, serialization
│   ├── NetDid.Method.Key/                   # did:key method
│   ├── NetDid.Method.Peer/                  # did:peer method (numalgo 0, 2, 4)
│   ├── NetDid.Method.WebVh/                 # did:webvh method (full CRUD)
│   └── NetDid.Extensions.DependencyInjection/  # Microsoft DI integration
├── tests/
│   ├── NetDid.Core.Tests/                   # 292 unit tests
│   ├── NetDid.Method.Key.Tests/             # 28 tests
│   ├── NetDid.Method.Peer.Tests/            # 31 tests
│   ├── NetDid.Method.WebVh.Tests/           # 70 tests
│   ├── NetDid.Tests.W3CConformance/         # 173 W3C conformance tests
│   └── NetDid.Extensions.DependencyInjection.Tests/  # 10 tests
├── samples/
│   ├── NetDid.Samples.DidKey/               # did:key usage examples
│   ├── NetDid.Samples.DidPeer/              # did:peer usage examples
│   ├── NetDid.Samples.DidWebVh/             # did:webvh CRUD examples
│   └── NetDid.Samples.DependencyInjection/  # DI registration pattern
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

## Samples

```bash
dotnet run --project samples/NetDid.Samples.DidKey
dotnet run --project samples/NetDid.Samples.DidPeer
dotnet run --project samples/NetDid.Samples.DidWebVh
dotnet run --project samples/NetDid.Samples.DependencyInjection
```

## Roadmap

NetDid is developed in four phases (see [NetDidPRD.md](NetDidPRD.md) for full details):

| Phase | Scope | Status |
|-------|-------|--------|
| **I** | Core Foundation — DID Document model, crypto primitives, encoding, serialization, resolver infrastructure | Complete |
| **II** | `did:key` and `did:peer` method implementations | Complete |
| **III** | `did:webvh` method implementation | Complete |
| **IV** | `did:ethr` method implementation | Planned |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup instructions, code conventions, and how to add new DID methods or key types.

## Security

See [SECURITY.md](SECURITY.md) for the security policy and how to report vulnerabilities.

## License

Licensed under the [Apache License 2.0](LICENSE).
