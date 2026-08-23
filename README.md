# NetDid

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![.NET](https://img.shields.io/badge/.NET-10.0-purple.svg)](https://dotnet.microsoft.com/)

A specification-compliant .NET library for Decentralized Identifiers (DIDs). NetDid provides a unified interface for creating, resolving, updating, and deactivating DIDs across multiple DID methods.

## Features

- **DID methods**: `did:key`, `did:peer`, `did:webvh`, and `did:ethr` (all full CRUD; did:ethr includes historical resolution and relayed meta-transactions)
- **Eight key types**: Ed25519, X25519, P-256, P-384, P-521, secp256k1, BLS12-381 G1/G2
- **BBS+ signatures**: Multi-message signing with selective disclosure proofs (IETF draft-10)
- **W3C DID Core 1.0** compliant DID Document model and serialization
- **Dual content types**: `application/did+ld+json` (JSON-LD) and `application/did+json`
- **Pluggable key storage**: Bring your own HSM, vault, or file-based key store via `IKeyStore`
- **Resolver infrastructure**: Composite routing, caching, and W3C DID URL dereferencing (fragment, service, serviceType, verificationRelationship)
- **JWK conversion**: Round-trip between raw key bytes and JSON Web Keys
- **DI integration**: `services.AddNetDid()` for Microsoft.Extensions.DependencyInjection, or use standalone with zero framework opinions
- **Fluent document builder**: `new DidDocumentBuilder(did).AddVerificationMethod(...).Build()`

> **Cryptography is provided by [NetCrypto](https://www.nuget.org/packages/NetCrypto).** NetDid
> carries no cryptographic primitives — key generation, signing, verification, key agreement,
> BBS+, JWK conversion, and the native crypto payloads all come from NetCrypto (the
> [`crypto-dotnet`](https://github.com/moisesja/crypto-dotnet) project). `did:webvh` Data Integrity
> proofs are produced and verified by
> [DataProofsDotnet](https://www.nuget.org/packages/DataProofsDotnet.Core). Types like `KeyType`,
> `DefaultKeyGenerator`, `ISigner`, and `InMemoryKeyStore` live in the `NetCrypto` namespace.

## Installation

```bash
dotnet add package NetDid.Core
dotnet add package NetDid.Method.Key    # did:key method
dotnet add package NetDid.Method.Peer   # did:peer method
dotnet add package NetDid.Method.WebVh  # did:webvh method
dotnet add package NetDid.Method.Ethr   # did:ethr method
dotnet add package NetDid.Extensions.DependencyInjection  # Microsoft DI integration
dotnet add package NetCrypto            # key generation, signing, JWK (NetCrypto namespace)
```

> **Note**: NetDid targets .NET 10. Ensure you have the [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0) installed. NetCrypto is pulled in transitively by the NetDid packages; add it explicitly only if you use its types directly (as the examples below do).

## Quick Start

### Generate a Key Pair

```csharp
using NetCrypto;

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
using NetCrypto;
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
using NetCrypto;
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

## did:ethr

`did:ethr` resolves DIDs anchored to any EVM-compatible blockchain via the [ERC-1056 registry contract](https://github.com/decentralized-identity/ethr-did-resolver). Create derives an Ethereum address from a secp256k1 key pair; resolve walks the on-chain event log to reconstruct the DID Document at any point in history.

### Create a did:ethr

```csharp
using NetCrypto;
using NetDid.Method.Ethr;
using NetDid.Method.Ethr.Rpc;

var config  = KnownNetworks.Sepolia with { RpcUrl = "https://sepolia.drpc.org" };
var factory = DefaultEthereumRpcClientFactory.CreateDirect([config]);
var method  = new DidEthrMethod(factory, [config], new DefaultKeyGenerator());

var result = await method.CreateAsync(new DidEthrCreateOptions { Network = "sepolia" });

Console.WriteLine(result.Did);
// Output: did:ethr:sepolia:0x4b0d...
```

No on-chain transaction is required to create a `did:ethr`. The DID is derived deterministically from the secp256k1 key pair. `DidEthrMethod.Capabilities` is `Create | Resolve | Update | Deactivate | ServiceEndpoints` — full CRUD.

### Resolve a did:ethr

```csharp
var resolved = await method.ResolveAsync(
    "did:ethr:sepolia:0xf61c81096c96f97e95ac52a570966195ad6c90dd");

var doc = resolved.DidDocument!;
Console.WriteLine(doc.VerificationMethod![0].BlockchainAccountId);
// eip155:11155111:0xF36cAD0fb057f01F852557317bB8aa05F8c2dF4D
```

Resolve walks the on-chain ERC-1056 event chain (owner changes, delegate keys, attribute keys, services) and builds a W3C DID Document. Key types supported: `EcdsaSecp256k1RecoveryMethod2020` (delegates), `EcdsaSecp256k1VerificationKey2019`, `Ed25519VerificationKey2020`, `X25519KeyAgreementKey2020`, `Multikey`, and unknown types via `publicKeyHex`.

For identities with long histories, finalized-event caching can avoid replaying the immutable
prefix on every resolution. It is explicitly opt-in and disabled by default:

```csharp
services.AddNetDid(builder => builder.AddDidEthr(
    networks,
    cacheFinalizedEventHistory: true));
```

When enabled, the resolver asks `eth_getBlockByNumber("finalized")`, then caches validated raw
ERC-1056 logs at or below that watermark under `(chainId, registryAddress, identityAddress)`.
The next resolution still calls `changed(identity)` and fetches every newer block, but it performs
no `eth_getLogs` calls for the cached finalized prefix. Non-finalized events are never stored in
the indefinite cache. Cached logs are parsed and checked again on every read through the same
registry, identity, block, `logIndex`, and `previousChange` validator as fresh RPC data, so a
corrupt cache entry fails closed as `internalError`. The cache is resolver-owned rather than shared
with application components, is hard-limited to 64 MiB in aggregate, skips empty histories, and
keeps only the greatest finalized watermark when resolutions race. Each entry is additionally
bounded by the resolver's existing 5,000-event and 32 MiB limits. If a chain, custom
RPC client, or endpoint does not support the optional finalized-block capability, resolution
silently retains the full uncached walk.

Delegates and attribute keys carry a `validTo` timestamp, and ERC-1056 revocation re-emits
the same entry with an elapsed `validTo` — so both expiry and revocation drop the entry from
the resolved document, while a historical resolution before that point still shows it.
`#delegate-N` numbering follows the on-chain event counter, so removed entries leave gaps.
An identity whose owner was transferred to `0x000…000` resolves to a stripped document with
`deactivated: true` in the document metadata.

### Historical resolution via `?versionId`

`DefaultDidUrlDereferencer` passes `?versionId` directly through to the resolver — no extra wiring needed:

```csharp
using NetDid.Core.Resolution;

var dereferencer = new DefaultDidUrlDereferencer(new CompositeDidResolver([method]));

// Genesis document — state before any on-chain events
var genesis = await dereferencer.DereferenceAsync(
    "did:ethr:sepolia:0xf61c81096c96f97e95ac52a570966195ad6c90dd?versionId=0");

var doc = (DidDocument)genesis.ContentStream!;
Console.WriteLine(doc.VerificationMethod!.Count); // 1 — only #controller
Console.WriteLine(genesis.ContentMetadata!["nextVersionId"]); // first event block
Console.WriteLine(genesis.ContentMetadata!["nextUpdate"]);    // its block time, e.g. 2024-01-15T01:42:24Z
```

Document metadata matches the reference `ethr-did-resolver`: `updated` carries the block
time of the last applied change whenever `versionId` is present, and historical queries
report `nextUpdate` beside `nextVersionId` (ISO 8601 UTC, whole seconds — the canonical
form used by the Ethereum block-time metadata). Which fields appear depends on the history
in view: an **unregistered** DID (no events at all) omits all four; a `versionId=0` query on
a DID **with** later history — the example above — omits `versionId`/`updated` (no change
applied yet) but still reports `nextVersionId`/`nextUpdate` for the first change.

`versionTime` is also supported in normalized UTC form, for example
`2026-07-24T12:34:56Z`. Subsecond values and numeric UTC offsets are rejected. `versionId`
must be a canonical unsigned decimal block number (`0`, `12`, and so on); leading zeroes,
signs, whitespace, hexadecimal notation, and overflow are rejected. Supplying both selectors
is invalid. Invalid historical options return `resolutionMetadata.error = "invalidOptions"`
before any RPC request instead of silently resolving the latest state. `invalidOptions` is
defined by the [DID Resolution specification](https://www.w3.org/TR/did-resolution/#errors);
it is not a DID Core 1.0 error code.

Historical replay is fail-closed. Every registry log returned for an asserted history block
must parse and match the requested registry, identity, and block; each must carry a unique,
canonical `logIndex`. Logs explicitly marked `removed: true` are rejected; the optional
`removed` member may be absent and, when present, must be Boolean. The `changed(identity)` call
must return one exact ABI word; within each sorted block, the first event must point to an earlier
block and every later event must point to the current block. `versionTime` replay also requires
event-block timestamps to be non-decreasing. Equal whole-second timestamps are valid for distinct
ordered blocks; a decrease is rejected. Missing, malformed, removed, duplicated, or inconsistent
history metadata returns `internalError` rather than a partial DID Document — these are
resolver-infrastructure failures (pruned/non-archive or hostile node, transport error, timeout),
never a statement that the DID does not exist, so `notFound` is not used on the RPC path. The
pruned/non-archive case is avoidable up front: resolution needs an endpoint serving historical
`eth_getLogs` — see [Archive nodes and endpoint auto-configuration](#archive-nodes-and-endpoint-auto-configuration). The
resolution metadata carries a fixed, library-owned `message` beside `error` (a pruned/incomplete
history is distinguished from a generic RPC failure; exception text from injectable seams is
never exposed); a genuinely unregistered identity resolves to the ERC-1056 genesis document with
no error. Error codes use the legacy DID Spec Registries string vocabulary (`internalError`,
`notFound`, …) shared by the whole library and the reference `ethr-did-resolver`; migration to
the current W3C DID Resolution draft's RFC 9457 error-object model is tracked in issue #123.

### Use an existing key

```csharp
var existingKey = keyGen.Generate(KeyType.Secp256k1);
var signer = new KeyPairSigner(existingKey, new DefaultCryptoProvider());

var result = await method.CreateAsync(new DidEthrCreateOptions
{
    Network     = "sepolia",
    ExistingKey = signer   // Must be Secp256k1; works with any ISigner
});
```

### Update a did:ethr

Updates are on-chain ERC-1056 transactions. The controller key is an
`IRecoverableDigestSigner` (NetCrypto ≥ 1.4.0) — Ethereum signatures are recoverable ECDSA
over a caller-computed keccak digest, which the general-purpose `ISigner` cannot produce, and
the interface keeps HSM/key-store-held keys usable (`KeyPairSigner` implements it):

```csharp
var controller = new KeyPairSigner(existingKey, new DefaultCryptoProvider());

var updated = await method.UpdateAsync(result.Did.Value, new DidEthrUpdateOptions
{
    ControllerKey = controller,
    AddServices   = [new DidEthrServiceAttribute
    {
        ServiceType     = "MessagingService",
        ServiceEndpoint = "https://hub.example.com/messages",
    }],
    AddDelegates  = [new DidEthrDelegate
    {
        DelegateType    = "sigAuth",              // → authentication + assertionMethod
        DelegateAddress = "0xb0b0…0002",
        Validity        = TimeSpan.FromDays(30),
    }],
    AddAttributes = [new DidEthrAttribute
    {
        // Raw did/pub attributes publish FULL key material — the implicit
        // blockchainAccountId controller VM cannot (an address is a hash, not a key).
        Name  = "did/pub/Ed25519/veriKey/base64",
        Value = ed25519PublicKey,
    }],
    // NewOwnerAddress = "0x…",  // transfers the update authority; always submitted last.
    //                            // Passing 0x000…000 here performs a DEACTIVATION —
    //                            // prefer DeactivateAsync, which says so explicitly.
});

var txHashes = (IReadOnlyList<string>)updated.Artifacts!["transactions"];
```

Operations are submitted sequentially — revocations, then additions, then (always last) the
owner change, because `changeOwner` strips the current key's authority over any later
operation. The submitting account must hold ETH for gas; a pre-flight `identityOwner` check
fails closed *before anything is broadcast* if `ControllerKey` is not the current owner, and
every write — including post-transaction readback — is bounded by an overall deadline. Once
transaction submission begins, failures carry evidence split by what the client actually
proved:

- `Exception.Data[DidEthrMethod.LandedTransactionsKey]` is a `string[]` of hashes with observed
  receipts (including reverted transactions, which still consumed gas and account nonce).
- `Exception.Data[DidEthrMethod.InFlightTransactionsKey]` is a `string[]` of locally computed
  hashes that may have been broadcast but have no observed receipt. Query each hash before
  retrying; a lost send response or receipt can hide a transaction that later confirms.

Validation and pre-flight failures that occur before a transaction hash exists do not promise
these evidence keys. Receipt evidence is accepted only when its hash matches the locally
computed submitted hash; metadata on exceptions from an injected RPC client is never treated
as transaction evidence. Evidence is projected onto a fresh library-owned exception, so a
custom client cannot suppress the hashes with a throwing or read-only `Exception.Data`.
The carrier surfaces the dependency's exception type and message for diagnosis, but reads them
through a guard (a hostile `Message` accessor may throw), strips control characters so a
dependency cannot forge log lines, and bounds the length. Well-known failure types keep their
identity — notably `TaskCanceledException`, which is how `HttpClient` reports a timeout — so
`catch` blocks that discriminate on type still match. The original exception remains available
as `InnerException`, and dependency text is never treated as transaction evidence.

`DidUpdateResult` carries the update-authority evidence
(`AuthorizationChange`/`UpdateKeyChange` flip only on an owner change;
`Effective`/`RevealedUpdateKeys` hold lowercase account addresses — did:ethr's canonical
authority form).

### Meta-transactions — the identity owner never needs ETH

The controller signs the ERC-1056 `0x19 0x00` operation payload; a funded relayer signs and
pays for the wrapping transaction:

```csharp
await method.UpdateAsync(did, new DidEthrUpdateOptions
{
    ControllerKey      = controller,     // signs the operation payloads only
    UseMetaTransaction = true,
    Relayer            = relayerSigner,  // pays gas
    AddServices        = [ … ],
});
```

The contract's own nonce mapping makes each signed payload single-use — replays revert.
Registries predating `ethr-did-registry` 0.0.3 (the mainnet `0xdCa7EF03…` deployment) track
that nonce differently; `EthereumNetworkConfig.LegacyNonce` — pre-set in `KnownNetworks` —
selects the correct scheme, including the legacy quirk where attribute operations read
`nonce[identity]` rather than the owner's nonce.

> **Two meta-transaction hazards inherent to ERC-1056**, both verified against real registry
> bytecode:
>
> 1. **Legacy registries lose replay protection after an ownership transfer.** The v0.0.3
>    contract increments `nonce[identity]` but its `changeOwner` / `addDelegate` /
>    `revokeDelegate` preimages read `nonce[identityOwner]`. Once those diverge, the preimage
>    nonce never moves and the signed calldata replays *forever* — anyone who observed it can
>    resurrect a revoked delegate. NetDid **refuses** to sign those operations in that state
>    (submit them directly instead); attribute operations are unaffected, since they read the
>    slot that does get incremented.
> 2. **Signatures replay across chains.** The ERC-1056 preimage binds the registry address
>    but **not** a chain id, and `KnownNetworks` maps one registry address to several chains
>    (`0xdCa7EF03…` → mainnet/polygon/…, `0x03d5003b…` → sepolia/gnosis/…). A meta-transaction
>    authorized on one of them is valid on the others whenever that identity's nonce there
>    matches. NetDid cannot fix this — the contract has no chain binding. If the same key
>    controls the same identity on more than one chain sharing a registry, prefer direct
>    submission.

### Deactivate a did:ethr

```csharp
var deactivated = await method.DeactivateAsync(did, new DidEthrDeactivateOptions
{
    ControllerKey = controller,          // UseMetaTransaction + Relayer also supported
});
// deactivated.Success == true; the DID now resolves with deactivated: true
```

Deactivation is `changeOwner` to `0x000…000`; resolution then returns a stripped document
with `deactivated: true`, and historical resolution (`?versionId`) still reaches
pre-deactivation states.

> **Deactivation is not a lock.** The `did:ethr` spec calls this "irreversible", but the
> deployed registry does not enforce that: `identityOwner()` is
> `owner != 0 ? owner : identity`, so zeroing the owner slot returns control **to the
> identity address itself**. If the identity is an EOA whose key you still hold, that key can
> write again — and a later non-zero `DIDOwnerChanged` clears the `deactivated` flag.
> Verified against the real registry bytecode (`DeactivationRealityTests`). Deactivation is
> permanent only when nobody can act as the identity address (e.g. a contract identity, or a
> discarded key). To make it stick, transfer ownership to an address that provably cannot
> sign before zeroing it, or treat key destruction as part of the procedure.

### Deploy the registry on a private chain

Public networks never need this — the registry is already deployed at the `KnownNetworks`
addresses. For a private/consortium EVM chain, deploy the vendored official bytecode
(embedded from the MIT-licensed `ethr-did-registry` npm artifacts, keccak-pinned by tests)
through the same transaction pipeline:

```csharp
const ulong chainId = 1234;
var registryAddress = await Erc1056Registry.DeployAsync(
    rpcClient, fundedDeployerKey, chainId);

var network = new EthereumNetworkConfig
{
    Name = "mychain", RpcUrl = "https://rpc.internal", ChainId = "0x4d2",
    RegistryAddress = registryAddress,
};
```

The chain ID is required because it is the EIP-155 replay binding in the deployment
signature. `DeployAsync` cross-checks it against the node's `eth_chainId` and aborts before
signing on disagreement, so the RPC endpoint cannot choose which chain the key authorizes.
Ambiguous deployment failures use the same
`DidEthrMethod.LandedTransactionsKey`/`InFlightTransactionsKey` evidence contract as updates,
so callers can query a possibly accepted deployment before retrying at a different nonce.

### Known networks

`KnownNetworks` mirrors the [`deployments.ts`](https://github.com/decentralized-identity/ethr-did-resolver/blob/master/src/config/deployments.ts) catalogue from the JS reference resolver — correct registry addresses and `legacyNonce` flags pre-populated:

| Property | Network | Chain ID | Registry |
|---|---|---|---|
| `KnownNetworks.Mainnet` | mainnet | 1 | `0xdCa7EF03…` |
| `KnownNetworks.Sepolia` | sepolia | 11155111 | `0x03d5003b…` |
| `KnownNetworks.Holesky` | holesky | 17000 | `0x03d5003b…` |
| `KnownNetworks.Gnosis` | gno | 100 | `0x03d5003b…` |
| `KnownNetworks.Polygon` | polygon | 137 | `0xdCa7EF03…` |
| `KnownNetworks.Aurora` | aurora | 1313161554 | `0x63eD58B6…` |
| + 6 more | … | … | … |

All entries have `RpcUrl = ""`. Supply the endpoint with a `with` expression — the endpoint
must serve historical `eth_getLogs` (see the next section), or let `EthrRpcAutoConfig`
pick one for you:

```csharp
var cfg = KnownNetworks.Mainnet with { RpcUrl = "https://mainnet.gateway.tenderly.co" };
```

`EthrIdentifier.ChainId` resolves named built-ins through this same catalogue, so network
metadata has one source of truth. The deprecated `goerli` identifier alias still resolves to
chain ID 5 without being advertised in `KnownNetworks.All`. Consumers can supply arbitrary
networks with `EthereumNetworkConfig`; the library does not attempt to enumerate every
EVM-compatible chain.

### Archive nodes and endpoint auto-configuration

**did:ethr resolution requires an RPC endpoint that serves historical `eth_getLogs`
(archive-grade).** Resolution replays the identity's full ERC-1056 event history, and those
events can be years old. Many free public endpoints answer `eth_chainId` and current-state
calls fine but refuse or empty-answer old-range `eth_getLogs` — for example,
`ethereum-rpc.publicnode.com` rejects them with *"Archive requests require a personal
token"*. Against such an endpoint, resolution fails closed with
`resolutionMetadata.error = "internalError"` and a message naming the pruned/non-archive
cause — never a silently truncated document — but only at resolve time, per DID.

To get working endpoints without hand-curating URLs, use the opt-in
`EthrRpcAutoConfig` bootstrap (no extra package, no new dependencies). It probes candidate
public endpoints the way the reference resolver maintainer recommends — an `eth_getLogs`
query with the resolver's own request shape (exact block, ERC-1056 event-signature topic
filter, identity topic; so neither provider range caps nor wildcard-scan restrictions can
cause a false reject) for the **earliest on-chain-verified registry event** on each
network — and discards any endpoint that returns no log matching the probe (registry,
event signature, identity, exact block — so a provider that silently clamps the queried
range cannot pass), logging the reason. Probing to the earliest event matters: mainnet has real registry events
back to block 7,049,729 (January 2019), and an endpoint pruned anywhere above that would
pass a shallower probe yet fail those DIDs.

```csharp
// Probe the built-in candidate endpoints
// (mainnet, sepolia, gnosis, polygon, aurora, ewc) …
IReadOnlyList<EthereumNetworkConfig> networks =
    await EthrRpcAutoConfig.ConfigureAsync(logger: logger);

// … or your own candidates, keyed by KnownNetworks name or hex chain ID:
networks = await EthrRpcAutoConfig.ConfigureAsync(new Dictionary<string, IReadOnlyList<string>>
{
    ["mainnet"] = ["https://eth.drpc.org", "https://my-fallback.example"],
    ["sepolia"] = ["https://sepolia.drpc.org"],
});

var method = new DidEthrMethod(factory, networks, keyGenerator);   // or builder.AddDidEthr(networks)
```

Per network, candidates are tried in order and the first one passing both checks wins:
`eth_chainId` must match the catalogue entry, and the earliest-event probe must return a
matching log. Endpoints that fail transport, time out (default 10 s per endpoint, tune with
`perEndpointTimeout`), or answer with an empty log set are discarded with an actionable
log message; a network with no passing candidate is omitted from the result. Networks
without hard-coded probe data pass on the chain-ID check alone and are logged as
unverified for archive depth.

Built-in defaults and probe data cover the six official deployments that are live and
verifiable today: mainnet, Sepolia, Gnosis, Polygon, Aurora, and Energy Web Chain. The
remaining catalogue entries (ARTIS, Polygon Mumbai, Linea Goerli — deprecated or defunct —
plus Holesky and Volta, which expose no verifiable probe data) take caller-supplied
candidates and the unverified-depth handling above; this scoping of issue #119's
batteries-included criterion is recorded on the issue, each exclusion carries a documented
reason in code, and a test pins that every catalogue entry is in exactly one of the two
sets.

Log output identifies endpoints by scheme + host only — RPC URLs routinely embed
credentials (userinfo, provider keys in the path, query tokens), and none of that, nor any
endpoint response content, ever reaches the log sink. Caller input is snapshotted once at
entry under documented bounds (64 network entries, 16 candidates per network; excess is
truncated with a logged count).

Probing is a **quality filter, not an integrity guarantee**: a passing endpoint is still a
single untrusted RPC node that could forge a self-consistent event history. The probe data
lives in the library and will be aligned with the reference resolver's companion
auto-configuration list when it is published (issue #119).

### Runnable examples and tests

```bash
dotnet run --project samples/NetDid.Samples.DidEthr              # offline full CRUD, no network
dotnet run --project samples/NetDid.Samples.DidEthr -- --live    # resolve a real Sepolia DID
NETDID_ETHR_INTEGRATION=1 dotnet test tests/NetDid.Method.Ethr.IntegrationTests  # real EVM (Docker)
```

The sample runs against an in-memory ERC-1056 chain emulator that accepts genuinely signed
transactions (strict RLP decoding, real `ecrecover` sender recovery, the verified contract
semantics of both registry generations), so every section — create, update, meta-transactions,
historical replay, expiry vs revocation, owner rotation, deactivation, registry deployment,
error handling, dereferencing, DI — runs the real public API deterministically and offline.

The integration suite is the real-EVM oracle: gated by `NETDID_ETHR_INTEGRATION=1`, it starts
an Anvil (Foundry) container via Testcontainers, deploys the vendored registry bytecode of
both generations, and proves the full lifecycle — including meta-transaction preimages and
the legacy-nonce divergence — against actual contract execution. The variable alone decides
skipping; once it is set, Docker must be reachable — the suite fails with one actionable
message rather than silently skipping, so a green opted-in run always means the real-EVM
tests actually executed.

## did:webvh

`did:webvh` (DID Web with Verifiable History) combines web-based hosting with a cryptographically verifiable log of all changes. Full CRUD with hash chain integrity, pre-rotation, and witness validation.

### Create a did:webvh

```csharp
using NetCrypto;
using NetDid.Core.Model;
using NetDid.Method.WebVh;

var keyGen = new DefaultKeyGenerator();
var crypto = new DefaultCryptoProvider();
var updateKey = keyGen.Generate(KeyType.Ed25519);
var signer = new KeyPairSigner(updateKey, crypto);

var httpClient = new DefaultWebVhHttpClient();
var didWebVh = new DidWebVhMethod(httpClient);

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

The result includes `Artifacts["did.jsonl"]` (the verifiable log) and `Artifacts["did.json"]` (did:web backwards-compatible document). Host these at `https://example.com/.well-known/did.jsonl` and `did.json`. The parallel `did.json` includes the derived `#files` and Linked-VP `#whois` services when the controller has not explicitly overridden them; those services are not written into the signed log state. When `WitnessProofs` are provided, a `did-witness.json` artifact is also produced.

### Resolve a did:webvh

```csharp
var resolved = await didWebVh.ResolveAsync("did:webvh:z6Rk8Rx...:example.com");
var doc = resolved.DidDocument!;

Console.WriteLine(doc.Service![0].Type);  // "TurtleShellPds"
Console.WriteLine(resolved.DocumentMetadata!.VersionId);  // "1-z6Rk8Rx..."
```

Resolution fetches the `did.jsonl` log over HTTPS, validates the hash chain and Data Integrity Proofs, and returns the latest DID Document. The resolved view materializes did:webvh's implicit `#files` (`relativeRef`) and `#whois` (`LinkedVerifiablePresentation`) services when absent; controller-defined relative or absolute service ids take precedence. For a root DID their default endpoints are `https://example.com/` and `https://example.com/whois.vp`; deployment-path DIDs place them beside `did.jsonl`, without a `.well-known` segment.

`DefaultDidUrlDereferencer` uses those services for bare paths. It returns the constructed external URL as `text/uri-list` for the caller to retrieve; Core does not fetch or validate external resource bytes:

```csharp
var dereferencer = new DefaultDidUrlDereferencer(didWebVh);
var resource = await dereferencer.DereferenceAsync(
    $"{resolved.DidDocument!.Id.Value}/governance/issuers.json");
// resource.ContentStream == "https://example.com/governance/issuers.json"

var whois = await dereferencer.DereferenceAsync(
    $"{resolved.DidDocument.Id.Value}/whois");
// whois.ContentStream == "https://example.com/whois.vp"
```

Bare-path dispatch is specific to `did:webvh`; other DID methods keep their existing DID Core
behavior. Controller-defined `#files` and `#whois` endpoints override the defaults, but the selected
HTTP(S) authority and deployment resource base remain the redirect boundary. URI-set endpoints
produce a CRLF-separated URI list. The special service match is the exact path `/whois`; a query
does not change that match, while `/whois/` remains an ordinary path beneath `#files`.

Every supplied controller proof on an entry is processed by DataProofsDotnet's Data Integrity pipeline and authorized against the active `updateKeys`: NetDid requires an anti-spoofed `did:key` verification method, Ed25519 `eddsa-jcs-2022`, `assertionMethod`, a valid signature, and an active update key. One authorized signer authorizes the entry, but any invalid or unauthorized extra proof rejects the log as `invalidDidLog`; controller proofs have no threshold semantics. NetDid applies a conservative `System.Uri`-compatible absolute-URI check to a present proof `id` (without surrounding whitespace), rejects duplicate proof ids, resolves `previousProof` references, and treats `expires` at or before the entry's `versionTime` as expired. This accepts the DID, URN, and HTTPS forms used by the SDK, but it is not full WHATWG valid-URL-string conformance and can reject other standards-valid forms. Unknown proof members remain signature-bound and their proof-object JSON is preserved, but NetDid does not claim application semantics for every extension. In particular, array-valued `domain` is not supported by the pinned DataProofsDotnet model. A wire `proof` may be a single object or an array and `created` is optional; reserialization preserves each parsed proof object but normalizes a single-object container to an array. Duplicate JSON members, invalid UTF-8, and malformed content are rejected as `invalidDidLog`.

Fetched entry hashing and controller verification retain every JSON member under `parameters` and `state`, including nested extensions that the typed DID model does not surface. This prevents a post-sign extension injection from disappearing during model reconstruction. Witness proofs sign the `{"versionId": "..."}` input document per did:webvh v1.0 (issue #135); the `versionId` embeds the entry hash recomputed by chain validation, so a witness approval binds those same members transitively. Update and Deactivate also preserve those members in prior fetched entries; deliberate public-model mutations fall back to modeled serialization instead of stale wire data. An update that preserves the document (`NewDocument == null`) likewise carries the previous state's signed nested members into the new signed entry rather than dropping them in a modeled rewrite. A supplied `NewDocument` is deep-copied once at the start of the update, so hashing, signing, the published log, and the returned document all reflect a single snapshot — a caller collection that changes contents between reads cannot publish bytes that differ from what was signed.

Resolution enforces did:webvh's per-entry SCID identity: the SCID segment of every validated entry's `state.id` must match the DID's SCID (only host/path may differ under portability). A signed log whose genesis or an intermediate entry claims a foreign SCID, or omits `state.id`, is rejected as `invalidDidLog`; historical resolution validates only the prefix through the selected version.

Verification work per entry is bounded by a controller-proof limit (default 8). Direct consumers can set it with `new DidWebVhMethod(client, logger: null, maxControllerProofsPerEntry: 16)` and DI consumers with `builder.AddDidWebVh(httpClientOptions: null, maxControllerProofsPerEntry: 16)`; raising it increases attacker-controlled canonicalization and signature work. The existing two-argument constructor and one-argument registration call remain source- and binary-compatible. With `DidResolutionOptions.IncludeLog`, latest resolution exposes the fully validated log, while historical resolution exposes only the validated prefix through the selected version.

NetDid authors whole-second `versionTime`s and never authors future time (a conservative writer policy that guarantees did:webvh's requirement that the entry timestamp be the retrieval time or before): Create truncates the current UTC instant, and a same-second Update/Deactivate *waits* for the next whole second after the previous entry to arrive before stamping it (~1 write/second sustained). One monotonic deadline bounds the aggregate authoring wait at 2 seconds even if UTC stalls or moves backward. If the next strictly increasing whole-second timestamp cannot be reached within that aggregate budget, Update and Deactivate fail with `ArgumentException`; retry after the local clock advances — appending past a future-dated head without authoring future time is impossible, so an honest failure replaces a false success. For NetDid-authored logs the DID Core-mandated whole-second `created`/`updated` metadata coincides exactly with `versionTime`. Logs imported from implementations that author fractional `versionTime`s keep full-precision reading and selection; for those logs `created`/`updated` are informational only — use `versionTime`/`versionId` as version selectors, and never feed a serialized `updated` back as a `?versionTime=` query.

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
    CurrentLogContent = Encoding.UTF8.GetBytes((string)result.Artifacts!["did.jsonl"]),
    SigningKey = signer,
    NewDocument = updatedDoc
});
// Re-host the updated did.jsonl
```

The result carries authorization-change evidence for method-agnostic callers.
`AuthorizationChange` reports whether *any* authorization material changed
(`updateKeys` / `nextKeyHashes` / witness config); `UpdateKeyChange`
reports whether the effective `updateKeys` set itself changed, including while the
resulting state keeps pre-rotation active. `RevealedUpdateKeys` is the complete set
eligible to authorize the entry just appended: the prior effective keys when prior
commitments did not govern that entry (including an entry that activates pre-rotation
for its successor), or the current entry's explicit keys when prior commitments did
govern it and every member passed commitment validation. Eligibility does not mean
every listed key signed; one eligible update key can authorize the proof.
`EffectiveUpdateKeys` is forward-looking and lists the keys authorized to sign the
*next* log entry. Do not coalesce the two nullable key properties into a generic
post-change key set; they answer different current-entry and next-entry questions.

For an exclusive rotation or authorization postcondition, require the expected status
and compare the applicable complete key set for equality; membership checks alone
would accept unexpected extra keys. Both statuses and nullable key sets fail closed for
methods that report no evidence. The did:webvh driver reports
`UpdateKeyChange == Changed` or `Unchanged` and `RevealedUpdateKeys` even during
continuous pre-rotation, but keeps `EffectiveUpdateKeys` null when the resulting state
has non-empty `nextKeyHashes`: commitments are hashes, so they cannot reveal the keys
that will authorize the next entry. An entry that sets `nextKeyHashes: []` ends
pre-rotation after that entry and restores concrete next-entry evidence.

### Pre-rotation (key commitment)

```csharp
var nextKey = keyGen.Generate(KeyType.Ed25519);
var commitment = PreRotationManager.ComputeKeyCommitment(nextKey.MultibasePublicKey);

var result = await didWebVh.CreateAsync(new DidWebVhCreateOptions
{
    Domain = "example.com",
    UpdateKey = signer,
    PreRotationCommitments = [commitment]
});
```

Pre-rotation commits to the next update key hash at creation time. The next entry must explicitly
place the committed key in `updateKeys`, carry `nextKeyHashes`, and be signed by that committed key.
This prevents a compromised current key from rotating control to an uncommitted key. Commitments
are did:webvh v1.0 bare-base58btc encodings of complete SHA-256 multihashes (`Qm...`, with no
multibase `z` prefix).

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
using NetCrypto;

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
    builder.AddDidEthr(new Dictionary<string, string>
    {
        // Endpoints must serve historical eth_getLogs (archive-grade) — see the
        // did:ethr "Archive nodes and endpoint auto-configuration" section. To skip
        // hand-curation, await EthrRpcAutoConfig.ConfigureAsync() before building the
        // container and pass its result to AddDidEthr(IEnumerable<EthereumNetworkConfig>).
        ["mainnet"] = "https://mainnet.gateway.tenderly.co",
        ["sepolia"] = "https://sepolia.drpc.org",
    });
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

NetDid is built around a small set of core interfaces (in `NetDid.Core`):

| Interface | Purpose |
|-----------|---------|
| `IDidManager` | Unified DID lifecycle manager — routes CRUD operations across registered methods |
| `IDidMethod` | Single DID method implementation (create, resolve, update, deactivate) |
| `IDidResolver` | Standalone DID resolution (for consumers who only need to resolve) |

The cryptographic interfaces are provided by **NetCrypto** (the `NetCrypto` namespace):

| Interface | Purpose |
|-----------|---------|
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
│   ├── NetDid.Core/                         # Core abstractions, DID model, encoding, serialization
│   ├── NetDid.Method.Key/                   # did:key method
│   ├── NetDid.Method.Peer/                  # did:peer method (numalgo 0, 2, 4)
│   ├── NetDid.Method.WebVh/                 # did:webvh method (full CRUD)
│   ├── NetDid.Method.Ethr/                  # did:ethr method (full CRUD, ERC-1056)
│   └── NetDid.Extensions.DependencyInjection/  # Microsoft DI integration
├── tests/
│   ├── NetDid.Core.Tests/                   # 377 unit tests
│   ├── NetDid.Method.Key.Tests/             # 52 tests
│   ├── NetDid.Method.Peer.Tests/            # 48 tests
│   ├── NetDid.Method.WebVh.Tests/           # 420 tests
│   ├── NetDid.Method.Ethr.Tests/            # 382 tests
│   ├── NetDid.Method.Ethr.IntegrationTests/ # 18 tests (7 real-EVM, opt-in via NETDID_ETHR_INTEGRATION)
│   ├── NetDid.Tests.W3CConformance/         # 233 W3C conformance tests
│   └── NetDid.Extensions.DependencyInjection.Tests/  # 18 tests
├── samples/
│   ├── NetDid.Samples.DidKey/               # did:key usage examples
│   ├── NetDid.Samples.DidPeer/              # did:peer usage examples
│   ├── NetDid.Samples.DidWebVh/             # did:webvh CRUD examples
│   ├── NetDid.Samples.DidEthr/              # did:ethr full CRUD (offline chain emulator)
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
dotnet run --project samples/NetDid.Samples.DidEthr
dotnet run --project samples/NetDid.Samples.DependencyInjection
```

All samples run offline — no network access, no external services.

## Roadmap

NetDid is developed in four phases (see [NetDidPRD.md](NetDidPRD.md) for full details):

| Phase | Scope | Status |
|-------|-------|--------|
| **I** | Core Foundation — DID Document model, crypto primitives, encoding, serialization, resolver infrastructure | Complete |
| **II** | `did:key` and `did:peer` method implementations | Complete |
| **III** | `did:webvh` method implementation | Complete |
| **IV** | `did:ethr` method implementation | Complete (full CRUD incl. meta-transactions) |

## Specifications

NetDid targets the following specifications:

| Specification | Version  | Status | Reference |
|---|----------|---|---|
| **W3C Decentralized Identifiers (DIDs)** | v1.0     | W3C Recommendation (2022-07-19) | [w3.org/TR/did-core](https://www.w3.org/TR/did-core/) |
| **did:key** | Latest   | W3C CCG Final | [w3c-ccg.github.io/did-method-key](https://w3c-ccg.github.io/did-method-key/) |
| **did:peer** | 2.0      | DIF Spec | [identity.foundation/peer-did-method-spec](https://identity.foundation/peer-did-method-spec/) |
| **did:webvh** | 1.0      | DIF Recommended | [identity.foundation/didwebvh](https://identity.foundation/didwebvh/) |
| **did:ethr** | 13.0.0   | DIF Spec | [github.com/decentralized-identity/ethr-did-resolver](https://github.com/decentralized-identity/ethr-did-resolver/blob/master/doc/did-method-spec.md) |
| **Data Integrity (eddsa-jcs-2022)** | —        | W3C Candidate Recommendation | [w3.org/TR/vc-di-eddsa](https://www.w3.org/TR/vc-di-eddsa/) |
| **BBS Signatures** | draft-10 | IETF CFRG Draft | [draft-irtf-cfrg-bbs-signatures](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-signatures/) |
| **JSON Canonicalization (JCS)** | RFC 8785 | IETF Proposed Standard | [rfc-editor.org/rfc/rfc8785](https://www.rfc-editor.org/rfc/rfc8785) |

## W3C Conformance

NetDid is fully conformant with [W3C Decentralized Identifiers (DIDs) v1.0](https://www.w3.org/TR/did-core/) (W3C Recommendation, 2022-07-19). All 255 conformance statements pass across the four implemented methods:

| Method | Tests |
|---|---|
| did:ethr | 66/66 |
| did:key | 57/57 |
| did:peer | 67/67 |
| did:webvh | 65/65 |

See [w3c-conformance-report.md](w3c-conformance-report.md) for the full report.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup instructions, code conventions, and how to add new DID methods or key types.

## Security

See [SECURITY.md](SECURITY.md) for the security policy and how to report vulnerabilities.

## License

Licensed under the [Apache License 2.0](LICENSE).
