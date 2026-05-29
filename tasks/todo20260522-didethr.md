# Plan: did:ethr Implementation (Phase 1 — Create + Resolve)

## Status: Ready to implement

---

## Scope

Phase 1 delivers `Create` and `Resolve` for the `did:ethr` method. No on-chain write
operations (Update / Deactivate require RLP encoding + EIP-155 transaction signing —
deferred to Phase 2).

Capabilities advertised: `Create | Resolve | ServiceEndpoints`

---

## Dependency changes

### `Directory.Packages.props`
Add under `<!-- Cryptography -->`:
```xml
<PackageVersion Include="acryptohashnet" Version="3.1.0" />
```

**Why `acryptohashnet`:** Zero dependencies on net10, 104 KB, pure C#, inherits
`System.Security.Cryptography.HashAlgorithm`, and correctly implements Ethereum
Keccak-256 (padding byte `0x01`) — not NIST SHA3-256. Confirmed correct against
known Ethereum test vectors.

### `netdid.sln`
Add three new projects:
- `src\NetDid.Method.Ethr\NetDid.Method.Ethr.csproj`
- `tests\NetDid.Method.Ethr.Tests\NetDid.Method.Ethr.Tests.csproj`
- `samples\NetDid.Samples.DidEthr\NetDid.Samples.DidEthr.csproj`

---

## New project: `src/NetDid.Method.Ethr/`

### `NetDid.Method.Ethr.csproj`
```xml
<PackageId>NetDid.Method.Ethr</PackageId>
```
Project references: `NetDid.Core`  
Package references: `acryptohashnet`, `Microsoft.Extensions.Logging.Abstractions`,
`Microsoft.Extensions.Http`

### File tree

```
src/NetDid.Method.Ethr/
├── NetDid.Method.Ethr.csproj
├── DidEthrMethod.cs
├── DidEthrCreateOptions.cs
├── DidEthrResolveOptions.cs
├── DidEthrUpdateOptions.cs              (stub — throws OperationNotSupportedException)
├── DidEthrDeactivateOptions.cs          (stub — throws OperationNotSupportedException)
│
├── Rpc/
│   ├── IEthereumRpcClient.cs
│   ├── DefaultEthereumRpcClient.cs
│   ├── EthereumNetworkConfig.cs
│   ├── EthereumLogEntry.cs
│   └── EthereumLogFilter.cs
│
├── Abi/
│   ├── AbiEncoder.cs
│   └── AbiDecoder.cs
│
├── Erc1056/
│   ├── Erc1056Calls.cs
│   ├── Erc1056Topics.cs
│   ├── Erc1056EventParser.cs
│   └── Erc1056Events.cs
│
├── Crypto/
│   ├── EthereumAddress.cs
│   └── EthereumIdentifier.cs
│
└── Resolution/
    └── EthrDocumentBuilder.cs
```

---

## File responsibilities

### `DidEthrCreateOptions.cs`
```csharp
public sealed record DidEthrCreateOptions : DidCreateOptions
{
    public override string MethodName => "ethr";
    public required string Network { get; init; }  // "mainnet", "sepolia", "0xaa36a7", etc.
    public ISigner? ExistingKey { get; init; }      // must be Secp256k1 if provided
}
```

### `DidEthrResolveOptions.cs`
```csharp
public sealed record DidEthrResolveOptions : DidResolutionOptions;
// VersionId (block number string) and VersionTime (ISO-8601) inherited from base.
// VersionId → resolve document state at that block; VersionTime → walk collected
// event history and trim to events whose block timestamp ≤ VersionTime.
```

### `DidEthrUpdateOptions.cs`
Carries the full PRD §8.6 property shape so Phase 2 is purely filling in `UpdateCoreAsync`
without a breaking API change. Phase 1 body: `throw new OperationNotSupportedException("ethr", "Update")`.
```csharp
public sealed record DidEthrUpdateOptions : DidUpdateOptions
{
    public IReadOnlyList<DidEthrServiceAttribute>? AddServices { get; init; }
    public IReadOnlyList<DidEthrServiceAttribute>? RemoveServices { get; init; }
    public IReadOnlyList<DidEthrDelegate>? AddDelegates { get; init; }
    public IReadOnlyList<DidEthrDelegate>? RevokeDelegates { get; init; }
    public string? NewOwnerAddress { get; init; }
    public required ISigner ControllerKey { get; init; }
    public bool UseMetaTransaction { get; init; } = false;
}

public sealed record DidEthrDelegate
{
    public required string DelegateType { get; init; }     // e.g. "veriKey", "sigAuth"
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

### `DidEthrDeactivateOptions.cs`
Carries the full PRD §8.7 property shape. Phase 1 body: `throw new OperationNotSupportedException("ethr", "Deactivate")`.
```csharp
public sealed record DidEthrDeactivateOptions : DidDeactivateOptions
{
    public required ISigner ControllerKey { get; init; }
    public bool UseMetaTransaction { get; init; } = false;
}
```

### `Rpc/IEthereumRpcClient.cs`
Matches PRD §8.8 exactly. `GetBlockTimestampAsync` is a deliberate extension to the PRD
interface needed for `VersionId`/`VersionTime` resolution. Phase 2 methods
(`SendRawTransactionAsync`, `GetTransactionCountAsync`, `GetGasPriceAsync`) are declared
now so the interface is complete; `DefaultEthereumRpcClient` throws `NotImplementedException`
for them in Phase 1.
```csharp
// Phase 1 — used by Create + Resolve
Task<string>  CallAsync(string to, string data, CancellationToken ct);
Task<IReadOnlyList<EthereumLogEntry>> GetLogsAsync(EthereumLogFilter filter, CancellationToken ct);
Task<ulong>   GetBlockNumberAsync(CancellationToken ct);
Task<ulong>   GetChainIdAsync(CancellationToken ct);                              // returns ulong per PRD §8.8

// Deliberate extension to PRD — required for VersionId and VersionTime resolution:
Task<ulong>   GetBlockTimestampAsync(ulong blockNumber, CancellationToken ct);

// Phase 2 — declared now, throw NotImplementedException in DefaultEthereumRpcClient
Task<string>  SendRawTransactionAsync(byte[] signedTransaction, CancellationToken ct);
Task<ulong>   GetTransactionCountAsync(string address, CancellationToken ct);
Task<ulong>   GetGasPriceAsync(CancellationToken ct);
```

### `Rpc/DefaultEthereumRpcClient.cs`
- `HttpClient` + `System.Text.Json`
- JSON-RPC 2.0 envelope: `{"jsonrpc":"2.0","method":"...","params":[...],"id":1}`
- Constructed with a single `EthereumNetworkConfig` (RPC URL)
- Throws `EthereumInteractionException` on HTTP errors or JSON-RPC error responses

### `Rpc/EthereumNetworkConfig.cs`
```csharp
public sealed record EthereumNetworkConfig
{
    public required string Name { get; init; }    // "mainnet", "sepolia", etc.
    public required string RpcUrl { get; init; }
    public string? ChainId { get; init; }         // hex string e.g. "0x1"; auto-detected if null
    public string RegistryAddress { get; init; } = "0xdCa7EF03e98e0DC2B855bE647C39ABe984fcF21B";
}
```

### `Rpc/EthereumLogEntry.cs`
```csharp
public sealed record EthereumLogEntry
{
    public required string Address { get; init; }
    public required IReadOnlyList<string> Topics { get; init; }  // hex strings, topics[0] = event sig
    public required string Data { get; init; }                   // hex string
    public required string BlockNumber { get; init; }            // hex string
    public string? TransactionHash { get; init; }
}
```

### `Rpc/EthereumLogFilter.cs`
```csharp
public sealed record EthereumLogFilter
{
    public required string Address { get; init; }        // contract address
    public required ulong FromBlock { get; init; }
    public required ulong ToBlock { get; init; }
    public IReadOnlyList<string[]>? Topics { get; init; } // topics[0] = OR-list of event sigs
}
```

### `Abi/AbiEncoder.cs`
Encodes calldata for the two read-only ERC-1056 calls:

- `changed(address identity)` → selector `0x4b0bebeb` + address zero-padded to 32 bytes
- `identityOwner(address identity)` → selector `0x8733d4e8` + address zero-padded to 32 bytes

Function selectors are computed once at class init via Keccak256 of the canonical
signature string (`acryptohashnet`), then cached as constants.

### `Abi/AbiDecoder.cs`
Decodes `eth_call` return values and event `data` fields.

Supports: `address` (32-byte, take last 20), `uint256` (32-byte big-endian), `bytes32`
(32-byte, trim trailing nulls for string interpretation), and `bytes` (dynamic: follows
ABI offset pointer, reads length prefix, then raw bytes).

All three ERC-1056 event data layouts:

| Event | data layout |
|---|---|
| `DIDOwnerChanged` | `owner/32` + `previousChange/32` |
| `DIDDelegateChanged` | `delegateType/32` + `delegate/32` + `validTo/32` + `previousChange/32` |
| `DIDAttributeChanged` | `name/32` + `valueOffset/32` + `validTo/32` + `previousChange/32` + `valueLength/32` + `valueBytes/padded` |

### `Erc1056/Erc1056Topics.cs`
Three `static readonly string` topic constants (hex), computed once at startup:
```
keccak256("DIDOwnerChanged(address,address,uint256)")
keccak256("DIDDelegateChanged(address,bytes32,address,uint256,uint256)")
keccak256("DIDAttributeChanged(address,bytes32,bytes,uint256,uint256)")
```

### `Erc1056/Erc1056Calls.cs`
Static helpers that return hex calldata strings for `changed(address)` and
`identityOwner(address)` using `AbiEncoder`.

### `Erc1056/Erc1056Events.cs`
Typed event structs (records):
```csharp
record OwnerChangedEvent(string Identity, string NewOwner, ulong PreviousChange, ulong BlockNumber);
record DelegateChangedEvent(string Identity, string DelegateType, string Delegate,
    ulong ValidTo, ulong PreviousChange, ulong BlockNumber);
record AttributeChangedEvent(string Identity, string Name, byte[] Value,
    ulong ValidTo, ulong PreviousChange, ulong BlockNumber);
```
All addresses stored as lowercase hex with `0x` prefix. `BlockNumber` carried through
for `DocumentMetadata.VersionId` population.

### `Erc1056/Erc1056EventParser.cs`
`EthereumLogEntry → Erc1056Event`. Dispatches on `topics[0]` against the three
`Erc1056Topics` constants. Identity address extracted from `topics[1]`. Remaining
fields decoded from `data` via `AbiDecoder`.

### `Crypto/EthereumAddress.cs`
Two static methods:

**`FromCompressedPublicKey(byte[] compressed33) → string`**
1. `ECPubKey.TryCreate(compressed)` (NBitcoin.Secp256k1)
2. `pubKey.WriteToSpan(compressed: false, buf65, out _)` → uncompressed
3. `new Keccak256().ComputeHash(buf65[1..])` → 32-byte hash (acryptohashnet)
4. Take last 20 bytes → `ToChecksumAddress`

**`ToChecksumAddress(byte[] address20) → string`**
1. Lowercase hex string (no `0x` prefix)
2. `new Keccak256().ComputeHash(Encoding.ASCII.GetBytes(lowercaseHex))` → hash
3. For each hex char at position i: uppercase if `hash[i/2]` nibble (high or low) ≥ 8
4. Prepend `0x`

### `Crypto/EthereumIdentifier.cs`
Parses the method-specific-id portion of a `did:ethr` DID:

```
Format: [network ":"] (ethereum-address | compressed-public-key)
  ethereum-address    = "0x" 40*HEXDIG   (20 bytes)
  public-key-hex      = "0x" 66*HEXDIG   (33 bytes compressed)
  network             = "mainnet" | "goerli" | "sepolia" | "0x" *HEXDIG
```

Returns a parsed record:
```csharp
record EthrIdentifier(
    string Network,          // resolved name or chain ID hex
    string IdentityAddress,  // always the 20-byte Ethereum address (derived if pubkey input)
    bool IsPublicKey,
    byte[]? PublicKeyBytes   // only set when IsPublicKey == true
)
```

Named network → chain ID mapping (used for `blockchainAccountId` CAIP-10 format):
- `mainnet` / no network → `1`
- `sepolia` → `11155111`
- `goerli` → `5`
- `polygon` → `137`
- Hex chain ID → parsed as-is

### `Resolution/EthrDocumentBuilder.cs`
Takes:
- `string did`
- `EthrIdentifier identifier` (network, address, isPublicKey, pubKeyBytes)
- `string chainId` (numeric string, for CAIP-10 `eip155:{chainId}:{address}`)
- `IReadOnlyList<Erc1056Event> events` (oldest → newest)
- `DateTimeOffset referenceTime` (current time, or block timestamp when `versionId` used)
- `bool isDeactivated`

**Algorithm:**

```
eventCounter = 0
currentOwner = identityAddress
delegates    = {}   // eventCounter → DelegateEntry
attributes   = {}   // eventCounter → AttributeEntry (pub keys)
services     = {}   // eventCounter → ServiceEntry

for each event (oldest first):
  eventCounter++
  if OwnerChanged:
    currentOwner = event.NewOwner
  if DelegateChanged:
    delegates[eventCounter] = { event.Delegate, event.DelegateType, event.ValidTo }
  if AttributeChanged and name starts with "did/pub/":
    attributes[eventCounter] = { event.Name, event.Value, event.ValidTo }
  if AttributeChanged and name starts with "did/svc/":
    services[eventCounter] = { serviceName, event.Value, event.ValidTo }

filter delegates where validTo >= referenceTime (unix seconds)
filter attributes where validTo >= referenceTime
filter services    where validTo >= referenceTime

if currentOwner == "0x0000000000000000000000000000000000000000":
  return deactivated document

build verificationMethods[]:
  always add #controller:
    id         = "{did}#controller"
    type       = "EcdsaSecp256k1RecoveryMethod2020"
    controller = did
    blockchainAccountId = "eip155:{chainId}:{checksumOwner}"

  if isPublicKey AND currentOwner == derivedAddress:
    add #controllerKey:
      id        = "{did}#controllerKey"
      type      = "EcdsaSecp256k1VerificationKey2019"
      publicKeyJwk = JwkConverter.ToPublicJwk(Secp256k1, pubKeyBytes)

  for each valid delegate (index i):
    add #delegate-{i}: EcdsaSecp256k1RecoveryMethod2020, blockchainAccountId = delegate address

  for each valid attribute (index i):
    parse "did/pub/{algorithm}/{purpose}/{encoding?}"
    add #delegate-{i} with type/encoding per key algorithm table (see below)

build authentication[]    = [#controller ref] + [#controllerKey ref if present]
                          + [#delegate-{i} refs where delegateType == "sigAuth"]
                          + [#delegate-{i} refs for sigAuth attributes]

build assertionMethod[]   = [#controller ref] + [#controllerKey ref if present]
                          + [#delegate-{i} refs where delegateType == "veriKey"]
                          + [#delegate-{i} refs for veriKey attributes]

build keyAgreement[]      = [#delegate-{i} refs for enc attributes]

build service[]           = [#service-{i} entries from valid services]

build @context dynamically:
  always: "https://www.w3.org/ns/did/v1"
          "https://w3id.org/security/suites/secp256k1recovery-2020/v2"
  if EcdsaSecp256k1VerificationKey2019 present:
          "https://w3id.org/security/v2"
          {"publicKeyJwk": {"@id": "https://w3id.org/security#publicKeyJwk", "@type": "@json"}}
  if Ed25519VerificationKey2020:    "https://w3id.org/security/suites/ed25519-2020/v1"
  if X25519KeyAgreementKey2020:     "https://w3id.org/security/suites/x25519-2020/v1"
  if Multikey:                      "https://w3id.org/security/multikey/v1"
  if publicKeyHex (unknown type):   {"publicKeyHex": "https://w3id.org/security#publicKeyHex"}
```

**Key algorithm → VM type mapping** (from spec):

| Attribute name segment | VM Type | Key encoding |
|---|---|---|
| `Secp256k1` | `EcdsaSecp256k1VerificationKey2019` | `publicKeyJwk` (EC, crv: secp256k1) via existing `JwkConverter` |
| `Ed25519` | `Ed25519VerificationKey2020` | `publicKeyMultibase` — prepend `0xed01`, base58btc |
| `X25519` | `X25519KeyAgreementKey2020` | `publicKeyMultibase` — prepend `0xec01`, base58btc |
| `Multikey` | `Multikey` | `publicKeyMultibase` — value already has multicodec prefix, base58btc |
| unknown | verbatim type string | `publicKeyHex` (raw hex, encoding hint from attribute name) |

Note: `Ed25519` and `X25519` multibase encoding reuses the existing `NetCid.Multicodec`
+ `NetCid.Multibase` utilities already used throughout the project.

### `DidEthrMethod.cs`

```csharp
public sealed class DidEthrMethod : DidMethodBase
{
    private readonly IEthereumRpcClient _rpc;
    private readonly IReadOnlyList<EthereumNetworkConfig> _networks;
    private readonly IKeyGenerator _keyGenerator;
    private readonly ILogger<DidEthrMethod> _logger;

    public DidEthrMethod(
        IEthereumRpcClient rpc,
        IEnumerable<EthereumNetworkConfig> networks,
        IKeyGenerator keyGenerator,
        ILogger<DidEthrMethod>? logger = null)
    {
        _rpc = rpc;
        _networks = networks.ToList();
        _keyGenerator = keyGenerator;
        _logger = logger ?? NullLogger<DidEthrMethod>.Instance;
    }

    public override string MethodName => "ethr";
    public override DidMethodCapabilities Capabilities =>
        DidMethodCapabilities.Create |
        DidMethodCapabilities.Resolve |
        DidMethodCapabilities.ServiceEndpoints;
}
```

**`CreateCoreAsync`:**
1. Validate options type → `DidEthrCreateOptions`
2. If `ExistingKey` provided: validate `KeyType == Secp256k1`; use `ExistingKey.PublicKey`
3. Else: `_keyGenerator.Generate(KeyType.Secp256k1)`
4. `EthereumAddress.FromCompressedPublicKey(pubKey)` → address
5. Find network config; resolve `chainId` (from config, or `GetChainIdAsync` if not set)
6. DID = `did:ethr:{network}:{checksumAddress}`
7. Build default document (no event history): single `#controller` VM
8. Return `DidCreateResult`

**`ResolveCoreAsync`:**
1. Parse DID → `EthrIdentifier` (network, address, isPublicKey, pubKeyBytes)
2. Find matching `EthereumNetworkConfig` by name or chain ID
3. Determine `versionBlockNumber` from `options.VersionId` (if set)
4. `eth_call changed(identityAddress)` → `latestChangeBlock`
5. If `latestChangeBlock == 0` AND no versionId: build and return default document
6. Walk the event chain backwards from `min(latestChangeBlock, versionBlockNumber)`:
   - Fetch logs at block for all 3 event topic signatures, filtered to `identityAddress`
   - Parse events via `Erc1056EventParser`
   - Extract `previousChange` from each event
   - Continue until `previousChange == 0`
7. Reverse collected events → oldest-first list
8. If `versionId` set:
   - `referenceTime` = block timestamp of `versionBlockNumber`
   - Scan for next change block > versionBlockNumber for `nextVersionId` / `nextUpdate`
9. Else if `versionTime` set:
   - `referenceTime` = `VersionTime` parsed as `DateTimeOffset`
   - For each collected event fetch its block timestamp via `GetBlockTimestampAsync` (cache
     results by block number to avoid redundant RPC calls)
   - Trim event list to those whose block timestamp ≤ `referenceTime`
   - `versionBlockNumber` = block number of the last retained event (0 if none retained)
   - `nextVersionId` = block number of the first trimmed-off event (for DocumentMetadata)
10. Else: `referenceTime = DateTimeOffset.UtcNow`
11. Detect deactivation: last `OwnerChangedEvent.NewOwner == 0x000...000`
12. `EthrDocumentBuilder.Build(...)` → `DidDocument`
13. Build `DocumentMetadata` (versionId, updated, nextVersionId if applicable, deactivated)
14. Return `DidResolutionResult`

---

## Changes to existing files

### `Directory.Packages.props`
- Add `<PackageVersion Include="acryptohashnet" Version="3.1.0" />`

### `src/NetDid.Extensions.DependencyInjection/NetDidBuilder.cs`
Add method:
```csharp
public NetDidBuilder AddDidEthr(IEnumerable<EthereumNetworkConfig> networks)
{
    Services.AddHttpClient<DefaultEthereumRpcClient>();
    Services.AddSingleton<IEthereumRpcClient>(
        sp => sp.GetRequiredService<DefaultEthereumRpcClient>());
    Services.AddSingleton<IDidMethod>(sp =>
        new DidEthrMethod(
            sp.GetRequiredService<IEthereumRpcClient>(),
            networks,
            sp.GetRequiredService<IKeyGenerator>(),
            sp.GetService<ILogger<DidEthrMethod>>()));
    return this;
}
```

### `src/NetDid.Extensions.DependencyInjection/NetDid.Extensions.DependencyInjection.csproj`
Add:
```xml
<ProjectReference Include="../NetDid.Method.Ethr/NetDid.Method.Ethr.csproj" />
```

---

## New test project: `tests/NetDid.Method.Ethr.Tests/`

All tests use mocked `IEthereumRpcClient` (NSubstitute) and hardcoded hex fixtures — no live network calls.

| File | Tests |
|---|---|
| `EthereumAddressTests.cs` | Address from known pubkeys; EIP-55 checksum spec vectors |
| `AbiDecoderTests.cs` | Decode raw hex for all 3 event data layouts; `bytes` dynamic type |
| `Erc1056EventParserTests.cs` | Full `EthereumLogEntry` → typed event; all 3 event types |
| `EthrDocumentBuilderTests.cs` | Default doc (no events); owner changed; veriKey + sigAuth delegates; attributes (all key types); expired entries excluded; deactivation; pubkey identifier with/without owner change; `#delegate-N` index stability across revocations |
| `DidEthrMethodTests.cs` | Create (key gen + address); Create with ExistingKey; Resolve no-op (changed=0); Resolve with mocked event chain; Resolve with versionId; Resolve with versionTime; Resolve deactivated |

---

## New sample: `samples/NetDid.Samples.DidEthr/`

```csharp
// 1. Create a did:ethr (no network call needed)
var result = await method.CreateAsync(new DidEthrCreateOptions { Network = "sepolia" });
Console.WriteLine(result.Did);

// 2. Resolve against Sepolia RPC
var resolved = await method.ResolveAsync(result.Did.Value);
Console.WriteLine(DidDocumentSerializer.Serialize(resolved.DidDocument!));
```

---

## Out of scope (Phase 2)

- `UpdateAsync` — ABI-encode write calls, RLP transaction encoding, EIP-155 signing, gas estimation
- `DeactivateAsync` — same infrastructure as Update
- `DidEthrUpdateOptions`, `DidEthrDeactivateOptions` — carry full PRD §8.6–8.7 property shapes so Phase 2 is purely filling in `UpdateCoreAsync`/`DeactivateCoreAsync` without breaking API changes; both throw `OperationNotSupportedException` in Phase 1
- Meta-transactions (`changeOwnerSigned`, `setAttributeSigned`, etc.)

---

## Implementation order

- [x] 1. Add `acryptohashnet` to `Directory.Packages.props`; scaffold three sln entries: `src\NetDid.Method.Ethr`, `tests\NetDid.Method.Ethr.Tests`, `samples\NetDid.Samples.DidEthr`
- [x] 2. `Crypto/EthereumAddress.cs` + `EthereumAddressTests.cs`
- [x] 3. `Abi/AbiEncoder.cs` + `Abi/AbiDecoder.cs` + `AbiDecoderTests.cs`
- [x] 4. `Erc1056/Erc1056Topics.cs` + `Erc1056Events.cs` + `Erc1056Calls.cs` + `Erc1056EventParser.cs` + `Erc1056EventParserTests.cs`
- [x] 5. `Crypto/EthereumIdentifier.cs`
- [x] 6. `Rpc/IEthereumRpcClient.cs` + `DefaultEthereumRpcClient.cs` + supporting models
- [x] 7. `Resolution/EthrDocumentBuilder.cs` + `EthrDocumentBuilderTests.cs`
- [x] 8. `DidEthrMethod.cs` + options types + `DidEthrMethodTests.cs`
- [x] 9. `NetDidBuilder.AddDidEthr(...)` + DI project reference
- [x] 10. Sample project
- [x] 11. `CHANGELOG.md` update
- [x] 12. Full `dotnet test` green; `dotnet build` clean

---

## Review

### Result: ✅ Complete — all 657 tests green, 0 warnings

**Delivered (Phase 1):**
- `NetDid.Method.Ethr` package: Create + Resolve for `did:ethr` with full ERC-1056 event chain walking
- 39 new tests covering Keccak-256 / EIP-55, ABI encode/decode, event parsing, document building, and method-level Create/Resolve/Version scenarios
- `VerificationMethod.AdditionalProperties` added to Core for `publicKeyHex` extension property
- `NetDidBuilder.AddDidEthr(networks)` DI extension
- `NetDid.Samples.DidEthr` sample
- Branch: `feat/did-ethr-resolver`
- CHANGELOG updated under `[Unreleased]`
