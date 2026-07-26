using System.Text;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using NetCrypto;
using NetDid.Core;
using NetDid.Core.Exceptions;
using NetDid.Core.Model;
using NetDid.Core.Resolution;
using NetDid.Core.Serialization;
using NetDid.Extensions.DependencyInjection;
using NetDid.Method.Ethr;
using NetDid.Method.Ethr.Crypto;
using NetDid.Method.Ethr.Erc1056;
using NetDid.Method.Ethr.Rpc;

// ============================================================
// NetDid Samples — did:ethr (ERC-1056, Create + Resolve)
// ============================================================
//
// Runs OFFLINE by default: an in-memory ERC-1056 registry (see the helpers at the
// bottom of this file) replays a scripted on-chain history through the real
// IEthereumRpcClient interface, so every branch of the resolver — delegates,
// attribute keys, services, owner change, expiry, revocation, deactivation and
// historical replay — is demonstrated deterministically with no network access.
//
// To resolve a REAL DID from a live endpoint instead:
//     dotnet run -- --live [rpcUrl]
//     NETDID_ETHR_RPC_URL=https://sepolia.drpc.org dotnet run -- --live

var keyGen = new DefaultKeyGenerator();
var crypto = new DefaultCryptoProvider();

// A network config is (name, RPC URL, chain ID, ERC-1056 registry address). KnownNetworks
// carries every field except the endpoint, which you supply with a `with` expression.
var sepolia = KnownNetworks.Sepolia with { RpcUrl = "https://sepolia.example/offline" };

// ---------------------------------------------------------------
// 1. Create — derive a did:ethr from a fresh secp256k1 key
// ---------------------------------------------------------------
Console.WriteLine("=== did:ethr — Create ===");

// Create needs no chain history, so an empty registry is enough here.
var emptyChain = new InMemoryEthereumRegistry(sepolia.RegistryAddress);
var createOnly = new DidEthrMethod(
    InMemoryEthereumRegistry.FactoryFor(sepolia, emptyChain), [sepolia], keyGen);

var created = await createOnly.CreateAsync(new DidEthrCreateOptions { Network = "sepolia" });

Console.WriteLine($"  DID:        {created.Did}");
Console.WriteLine($"  VM id:      {created.DidDocument.VerificationMethod![0].Id}");
Console.WriteLine($"  VM type:    {created.DidDocument.VerificationMethod[0].Type}");
Console.WriteLine($"  CAIP-10:    {created.DidDocument.VerificationMethod[0].BlockchainAccountId}");
Console.WriteLine("  No on-chain transaction is needed — the DID is derived from the key pair.");
Console.WriteLine();

// ---------------------------------------------------------------
// 2. Create from an existing signer (HSM / key-store friendly)
// ---------------------------------------------------------------
Console.WriteLine("=== did:ethr — Create from an existing key ===");

using var ownerKey = keyGen.Generate(KeyType.Secp256k1);
var ownerSigner = new KeyPairSigner(ownerKey, crypto);

var fromExisting = await createOnly.CreateAsync(new DidEthrCreateOptions
{
    Network     = "sepolia",
    ExistingKey = ownerSigner,   // must be Secp256k1; any ISigner implementation works
});
var again = await createOnly.CreateAsync(new DidEthrCreateOptions
{
    Network     = "sepolia",
    ExistingKey = ownerSigner,
});

Console.WriteLine($"  DID:            {fromExisting.Did}");
Console.WriteLine($"  Deterministic:  {fromExisting.Did.Value == again.Did.Value} (same key ⇒ same DID)");
Console.WriteLine($"  Supported keys: {string.Join(", ", createOnly.SupportedKeyTypes)}");
Console.WriteLine();

// ---------------------------------------------------------------
// 3. Identifier forms accepted by did:ethr
// ---------------------------------------------------------------
Console.WriteLine("=== did:ethr — Identifier forms ===");

foreach (var candidate in new[]
{
    "did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a",          // bare address ⇒ mainnet
    "did:ethr:sepolia:0xb9c5714089478a327f09197987f16f9e5d936e8a",  // named network
    "did:ethr:0xaa36a7:0xb9c5714089478a327f09197987f16f9e5d936e8a", // network by hex chain ID
    $"did:ethr:sepolia:0x{Convert.ToHexString(ownerKey.PublicKey).ToLowerInvariant()}", // compressed pubkey
})
{
    var id = EthrIdentifier.Parse(candidate);
    Console.WriteLine($"  {candidate[..Math.Min(candidate.Length, 46)]}…");
    Console.WriteLine($"    network={id.Network,-10} chainId={id.ChainId,-9} " +
                      $"address={id.IdentityAddress} publicKey={id.IsPublicKey}");
}

// A public-key DID additionally publishes #controllerKey with full key material,
// which the address-only form cannot (an address is a hash, not a key).
var pubKeyDid = $"did:ethr:sepolia:0x{Convert.ToHexString(ownerKey.PublicKey).ToLowerInvariant()}";
var pubKeyDoc = (await createOnly.ResolveAsync(pubKeyDid)).DidDocument!;
Console.WriteLine($"  Public-key DID VMs: {string.Join(", ",
    pubKeyDoc.VerificationMethod!.Select(v => v.Id[(v.Id.IndexOf('#') + 1)..]))}");

// Address derivation is available on its own: keccak256(uncompressed key)[12..], EIP-55 cased.
Console.WriteLine($"  EthereumAddress.FromCompressedPublicKey → " +
                  $"{EthereumAddress.FromCompressedPublicKey(ownerKey.PublicKey)}");
Console.WriteLine();

// ---------------------------------------------------------------
// 4. Known networks
// ---------------------------------------------------------------
Console.WriteLine("=== did:ethr — Known networks ===");
Console.WriteLine($"  {KnownNetworks.All.Count} built-in deployments (registry + chain ID pre-populated):");
foreach (var n in KnownNetworks.All.Take(4))
    Console.WriteLine($"    {n.Name,-14} chainId={n.ChainId,-12} registry={n.RegistryAddress[..10]}…" +
                      $" legacyNonce={n.LegacyNonce}");
Console.WriteLine($"    … and {KnownNetworks.All.Count - 4} more");
Console.WriteLine($"  Lookup by name or chain ID: KnownNetworks.Find(\"0xaa36a7\")?.Name = " +
                  $"{KnownNetworks.Find("0xaa36a7")?.Name}");
Console.WriteLine("  Any other EVM chain works via `new EthereumNetworkConfig { … }`.");
Console.WriteLine();

// ---------------------------------------------------------------
// 5. Resolve — replay a full ERC-1056 history
// ---------------------------------------------------------------
Console.WriteLine("=== did:ethr — Resolve (scripted on-chain history) ===");

const string Alice     = "0xf61c81096c96f97e95ac52a570966195ad6c90dd";
const string SigAuthor  = "0xa11ce00000000000000000000000000000000001";
const string VeriKeyDel = "0xb0b0000000000000000000000000000000000002";
const string NewOwner   = "0xd00d000000000000000000000000000000000003";

var now       = DateTimeOffset.UtcNow;
var forever   = (ulong)now.AddYears(10).ToUnixTimeSeconds();
using var ed25519 = keyGen.Generate(KeyType.Ed25519);
using var x25519  = keyGen.Generate(KeyType.X25519);

// Block timestamps for the scripted history (used by ?versionId / ?versionTime replay).
var blockTimes = new Dictionary<ulong, DateTimeOffset>
{
    [0]   = now.AddDays(-50),
    [100] = now.AddDays(-40),
    [200] = now.AddDays(-30),
    [300] = now.AddDays(-20),
    [400] = now.AddDays(-10),
    [500] = now.AddDays(-1),
};

var registry = new InMemoryEthereumRegistry(sepolia.RegistryAddress, blockTimes);
registry.AddBlock(100,
    // A time-limited sigAuth delegate ⇒ authentication + assertionMethod.
    Erc1056Log.Delegate(Alice, "sigAuth", SigAuthor, validTo: forever));
registry.AddBlock(200,
    // did/pub/<algorithm>/<purpose>/<encoding> publishes full key material.
    Erc1056Log.Attribute(Alice, "did/pub/Ed25519/veriKey/base64", ed25519.PublicKey, validTo: forever),
    // did/svc/<type> publishes a service endpoint.
    Erc1056Log.Attribute(Alice, "did/svc/MessagingService",
        Encoding.UTF8.GetBytes("https://example.com/messages"), validTo: forever));
registry.AddBlock(300,
    // Expires between block 300 and "now" — live in a historical resolution, gone today.
    Erc1056Log.Delegate(Alice, "veriKey", VeriKeyDel,
        validTo: (ulong)now.AddDays(-15).ToUnixTimeSeconds()));
registry.AddBlock(400,
    Erc1056Log.Attribute(Alice, "did/pub/X25519/enc/base64", x25519.PublicKey, validTo: forever),
    // changeOwner: the controller is no longer the identity address.
    Erc1056Log.OwnerChanged(Alice, NewOwner));
registry.AddBlock(500,
    // ERC-1056 revocation = the same attribute re-emitted with an elapsed validTo.
    Erc1056Log.Attribute(Alice, "did/pub/Ed25519/veriKey/base64", ed25519.PublicKey, validTo: 0));

var ethr         = new DidEthrMethod(InMemoryEthereumRegistry.FactoryFor(sepolia, registry), [sepolia], keyGen);
var resolver     = new CompositeDidResolver([ethr]);
var dereferencer = new DefaultDidUrlDereferencer(resolver);

var aliceDid = $"did:ethr:sepolia:{Alice}";
var latest   = await ethr.ResolveAsync(aliceDid);

Console.WriteLine($"  {aliceDid}");
Console.WriteLine(Indent(PrettyJson(DidDocumentSerializer.Serialize(latest.DidDocument!))));
Console.WriteLine($"  versionId={latest.DocumentMetadata!.VersionId} " +
                  $"deactivated={latest.DocumentMetadata.Deactivated?.ToString() ?? "(null)"}");
Console.WriteLine("  #delegate-N numbering follows the on-chain event counter, so revoked and");
Console.WriteLine("  expired entries leave gaps — matching the JS reference resolver.");
Console.WriteLine();

// ---------------------------------------------------------------
// 6. Historical resolution — ?versionId and ?versionTime
// ---------------------------------------------------------------
Console.WriteLine("=== did:ethr — Historical resolution ===");

foreach (var block in new ulong[] { 0, 100, 200, 300, 400, 500 })
{
    var at = await ethr.ResolveAsync(aliceDid, new DidEthrResolveOptions
    {
        VersionId = block.ToString(),
    });
    Console.WriteLine($"  ?versionId={block,-4} → {Summarize(at)}");
}

// versionTime selects the same prefix by wall-clock instead of block number.
var atTime = await ethr.ResolveAsync(aliceDid, new DidEthrResolveOptions
{
    VersionTime = now.AddDays(-25).UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'"),
});
Console.WriteLine($"  ?versionTime=-25d → {Summarize(atTime)}");
Console.WriteLine();

// ---------------------------------------------------------------
// 7. Expiry and revocation
// ---------------------------------------------------------------
Console.WriteLine("=== did:ethr — Expiry and revocation ===");

var atBlock300 = await ethr.ResolveAsync(aliceDid, new DidEthrResolveOptions { VersionId = "300" });
var atBlock400 = await ethr.ResolveAsync(aliceDid, new DidEthrResolveOptions { VersionId = "400" });

Console.WriteLine($"  veriKey delegate (validTo = now-15d)");
Console.WriteLine($"    at block 300: {HasVm(atBlock300, "delegate-3")}  (block timestamp precedes validTo)");
Console.WriteLine($"    today:        {HasVm(latest, "delegate-3")}  (expired)");
Console.WriteLine($"  Ed25519 attribute key (re-emitted at block 500 with validTo = 0)");
Console.WriteLine($"    at block 400: {HasVm(atBlock400, "delegate-2")}");
Console.WriteLine($"    today:        {HasVm(latest, "delegate-2")}  (revoked)");
Console.WriteLine($"  Controller after the block-400 changeOwner: " +
                  $"{latest.DidDocument!.VerificationMethod!.First(v => v.Id.EndsWith("#controller")).BlockchainAccountId}");
Console.WriteLine();

// ---------------------------------------------------------------
// 8. Deactivation
// ---------------------------------------------------------------
Console.WriteLine("=== did:ethr — Deactivation ===");

const string Bob = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
var bobRegistry = new InMemoryEthereumRegistry(sepolia.RegistryAddress, blockTimes);
bobRegistry.AddBlock(100, Erc1056Log.Delegate(Bob, "sigAuth", SigAuthor, validTo: forever));
// Transferring ownership to the null address makes the identity uncontrollable.
bobRegistry.AddBlock(200, Erc1056Log.OwnerChanged(Bob, "0x0000000000000000000000000000000000000000"));

var bobMethod = new DidEthrMethod(
    InMemoryEthereumRegistry.FactoryFor(sepolia, bobRegistry), [sepolia], keyGen);
var bobDid      = $"did:ethr:sepolia:{Bob}";
var bobLatest   = await bobMethod.ResolveAsync(bobDid);
var bobAt100    = await bobMethod.ResolveAsync(bobDid, new DidEthrResolveOptions { VersionId = "100" });

Console.WriteLine($"  before (?versionId=100): {Summarize(bobAt100)}");
Console.WriteLine($"  after changeOwner(0x0):  deactivated={bobLatest.DocumentMetadata!.Deactivated}, " +
                  $"verificationMethod={bobLatest.DidDocument!.VerificationMethod?.Count.ToString() ?? "(none)"}");
Console.WriteLine();

// ---------------------------------------------------------------
// 9. Error handling — resolvers report errors, they do not throw
// ---------------------------------------------------------------
Console.WriteLine("=== did:ethr — Resolution errors ===");

var errorCases = new (string Label, string Did, DidEthrResolveOptions? Options)[]
{
    ("malformed identifier",        "did:ethr:sepolia:0xnothexnothexnothexnothexnothexnothexnot", null),
    ("wrong identifier length",     "did:ethr:sepolia:0xdeadbeef",                                 null),
    ("non-canonical versionId",     aliceDid, new DidEthrResolveOptions { VersionId    = "007" }),
    ("versionTime with an offset",  aliceDid, new DidEthrResolveOptions { VersionTime  = "2026-07-24T12:34:56+02:00" }),
    ("both version selectors",      aliceDid, new DidEthrResolveOptions { VersionId = "100", VersionTime = "2026-07-24T12:34:56Z" }),
    ("unconfigured network",        $"did:ethr:polygon:{Alice}",                                   null),
};

foreach (var (label, did, options) in errorCases)
{
    var failed = await ethr.ResolveAsync(did, options);
    Console.WriteLine($"  {label,-28} → error = {failed.ResolutionMetadata.Error}");
}

// The RPC endpoint is untrusted, so replay is fail-closed: here the node asserts a change at
// block 900 but serves no matching event for it (a pruned non-archive node, or a hostile one
// hiding a revocation). Rather than return the events it did serve, resolution fails.
var truncated = new InMemoryEthereumRegistry(
    sepolia.RegistryAddress, blockTimes, assertedLatestBlock: 900);
truncated.AddBlock(100, Erc1056Log.Delegate(Alice, "sigAuth", SigAuthor, validTo: forever));

var truncatedResult = await new DidEthrMethod(
        InMemoryEthereumRegistry.FactoryFor(sepolia, truncated), [sepolia], keyGen)
    .ResolveAsync(aliceDid);

Console.WriteLine($"  {"incomplete event history",-28} → error = {truncatedResult.ResolutionMetadata.Error}" +
                  $" (no partial document)");
Console.WriteLine("  The resolver applies the same treatment to foreign-registry or foreign-identity");
Console.WriteLine("  logs, duplicate logIndex values, forward-pointing previousChange, and");
Console.WriteLine("  decreasing block timestamps.");
Console.WriteLine();

// ---------------------------------------------------------------
// 10. DID URL dereferencing
// ---------------------------------------------------------------
Console.WriteLine("=== did:ethr — DID URL dereferencing ===");

var vmRef = await dereferencer.DereferenceAsync($"{aliceDid}#controller");
Console.WriteLine($"  {aliceDid[..24]}…#controller → {((VerificationMethod)vmRef.ContentStream!).Type}");

var svcRef = await dereferencer.DereferenceAsync($"{aliceDid}?serviceType=MessagingService");
var svcDoc = (DidDocument)svcRef.ContentStream!;
Console.WriteLine($"  ?serviceType=MessagingService → {svcDoc.Service![0].Id} " +
                  $"({svcDoc.Service[0].ServiceEndpoint.Uri})");

var uriList = await dereferencer.DereferenceAsync(
    $"{aliceDid}?serviceType=MessagingService",
    new DidUrlDereferencingOptions { Accept = "text/uri-list" });
Console.WriteLine($"  … as text/uri-list → {uriList.ContentStream}");

// versionId / versionTime pass straight through the dereferencer to the resolver.
var genesis = await dereferencer.DereferenceAsync($"{aliceDid}?versionId=0");
Console.WriteLine($"  ?versionId=0 → nextVersionId = {genesis.ContentMetadata!["nextVersionId"]}");
Console.WriteLine();

// ---------------------------------------------------------------
// 11. Capabilities — what did:ethr supports today
// ---------------------------------------------------------------
Console.WriteLine("=== did:ethr — Capabilities ===");
Console.WriteLine($"  Capabilities: {ethr.Capabilities}");

// Update and Deactivate require signed on-chain transactions and are not yet
// implemented; the option types exist so the API is stable for that work.
try
{
    await ethr.UpdateAsync(aliceDid, new DidEthrUpdateOptions
    {
        ControllerKey = ownerSigner,
        AddServices   = [new DidEthrServiceAttribute
        {
            ServiceType     = "MessagingService",
            ServiceEndpoint = "https://example.com/messages",
        }],
        AddDelegates  = [new DidEthrDelegate
        {
            DelegateType    = "sigAuth",
            DelegateAddress = SigAuthor,
            Validity        = TimeSpan.FromDays(90),
        }],
        RevokeDelegates    = [],
        NewOwnerAddress    = null,
        UseMetaTransaction = false,   // true ⇒ signed by the controller, relayed by a third party
    });
}
catch (OperationNotSupportedException ex)
{
    Console.WriteLine($"  UpdateAsync     → {ex.GetType().Name}: {ex.Message}");
}

try
{
    await ethr.DeactivateAsync(aliceDid, new DidEthrDeactivateOptions { ControllerKey = ownerSigner });
}
catch (OperationNotSupportedException ex)
{
    Console.WriteLine($"  DeactivateAsync → {ex.GetType().Name}: {ex.Message}");
}
Console.WriteLine();

// ---------------------------------------------------------------
// 12. Dependency-injection registration
// ---------------------------------------------------------------
Console.WriteLine("=== did:ethr — Dependency injection ===");

var services = new ServiceCollection();
services.AddNetDid(b => b
    .AddDidKey()
    // AddDidEthr(Dictionary) looks registry addresses and chain IDs up in KnownNetworks;
    // you supply only the RPC endpoints. AddDidEthr(IEnumerable<EthereumNetworkConfig>)
    // takes fully custom configurations.
    .AddDidEthr(new Dictionary<string, string>
    {
        ["mainnet"] = "https://mainnet.example/rpc",
        ["sepolia"] = "https://sepolia.example/rpc",
    }));

using var provider = services.BuildServiceProvider();
var injected = provider.GetRequiredService<IDidResolver>();
Console.WriteLine($"  IDidResolver → {injected.GetType().Name}");
Console.WriteLine($"  Registered methods: {string.Join(", ",
    provider.GetServices<IDidMethod>().Select(m => $"did:{m.MethodName}"))}");
Console.WriteLine("  Each network gets its own named HttpClient (\"ethr-{name}\"), so a multi-network");
Console.WriteLine("  configuration can never query the wrong chain.");
Console.WriteLine();

// ---------------------------------------------------------------
// 13. Optional: resolve a real DID from a live endpoint
// ---------------------------------------------------------------
var liveRequested = args.Contains("--live", StringComparer.OrdinalIgnoreCase);
var liveRpcUrl    = args.SkipWhile(a => !a.Equals("--live", StringComparison.OrdinalIgnoreCase))
                        .Skip(1).FirstOrDefault()
                    ?? Environment.GetEnvironmentVariable("NETDID_ETHR_RPC_URL")
                    ?? "https://sepolia.drpc.org";

if (liveRequested)
{
    Console.WriteLine("=== did:ethr — Live resolution ===");
    Console.WriteLine($"  Endpoint: {liveRpcUrl}");

    var liveNetwork = KnownNetworks.Sepolia with { RpcUrl = liveRpcUrl };
    var liveMethod  = new DidEthrMethod(
        DefaultEthereumRpcClientFactory.CreateDirect([liveNetwork]), [liveNetwork], keyGen);

    var live = await liveMethod.ResolveAsync(
        "did:ethr:sepolia:0xf61c81096c96f97e95ac52a570966195ad6c90dd");

    if (live.ResolutionMetadata.Error is { } liveError)
        Console.WriteLine($"  error = {liveError}");
    else
        Console.WriteLine(Indent(PrettyJson(DidDocumentSerializer.Serialize(live.DidDocument!))));
    Console.WriteLine();
}
else
{
    Console.WriteLine("Tip: `dotnet run -- --live [rpcUrl]` resolves a real Sepolia DID over JSON-RPC.");
    Console.WriteLine();
}

Console.WriteLine("Done! All did:ethr examples completed successfully.");

// ============================================================
// Output helpers
// ============================================================

static string PrettyJson(string json)
    => JsonSerializer.Serialize(
        JsonSerializer.Deserialize<JsonElement>(json),
        new JsonSerializerOptions { WriteIndented = true });

static string Indent(string text)
    => string.Join(Environment.NewLine,
        text.Split(Environment.NewLine).Select(l => "    " + l));

static string HasVm(DidResolutionResult result, string fragment)
    => result.DidDocument?.VerificationMethod?.Any(v => v.Id.EndsWith('#' + fragment)) == true
        ? "present" : "absent ";

static string Summarize(DidResolutionResult result)
{
    if (result.ResolutionMetadata.Error is { } error)
        return $"error = {error}";

    var doc = result.DidDocument!;
    var vms = doc.VerificationMethod is null
        ? "(none)"
        : string.Join(",", doc.VerificationMethod.Select(v => v.Id[(v.Id.IndexOf('#') + 1)..]));

    return $"vm=[{vms}] services={doc.Service?.Count ?? 0} " +
           $"versionId={result.DocumentMetadata?.VersionId ?? "-"} " +
           $"nextVersionId={result.DocumentMetadata?.NextVersionId ?? "-"}";
}

// ============================================================
// Helper: in-memory ERC-1056 registry
// ============================================================
//
// Implements the same IEthereumRpcClient contract as DefaultEthereumRpcClient, so the
// resolver under test is the real one — none of its fail-closed validation is bypassed.
// The scripted history therefore has to be internally consistent exactly as a genuine
// chain is: every asserted block carries at least one matching event, all logs come from
// the configured registry and identity, logIndex values are unique within a block, and
// the ERC-1056 previousChange pointers link each block back to the previous one.

/// <summary>A single ERC-1056 event, pre-encoded except for its block linkage.</summary>
sealed record Erc1056Log(string Identity, string Topic, Func<ulong, string> EncodeData)
{
    /// <summary>DIDOwnerChanged(identity, owner, previousChange).</summary>
    public static Erc1056Log OwnerChanged(string identity, string newOwner) => new(
        identity, Erc1056Topics.DIDOwnerChanged,
        prev => "0x" + Word(newOwner) + Hex(prev));

    /// <summary>DIDDelegateChanged(identity, delegateType, delegate, validTo, previousChange).</summary>
    public static Erc1056Log Delegate(
        string identity, string delegateType, string delegateAddress, ulong validTo) => new(
        identity, Erc1056Topics.DIDDelegateChanged,
        prev => "0x" + Bytes32(delegateType) + Word(delegateAddress) + Hex(validTo) + Hex(prev));

    /// <summary>DIDAttributeChanged(identity, name, value, validTo, previousChange).</summary>
    public static Erc1056Log Attribute(
        string identity, string name, byte[] value, ulong validTo) => new(
        identity, Erc1056Topics.DIDAttributeChanged,
        prev => "0x" + Bytes32(name)
                     + Hex(128)                      // ABI offset of the dynamic `value`
                     + Hex(validTo) + Hex(prev)
                     + Hex((ulong)value.Length)      // length prefix
                     + PadRight(value));

    // ── ABI encoding primitives ──────────────────────────────────────────────
    private static string Hex(ulong value) => value.ToString("x64");

    private static string Word(string address)
        => "000000000000000000000000" + Strip(address);

    private static string Bytes32(string ascii)
    {
        var word = new byte[32];
        Encoding.ASCII.GetBytes(ascii).CopyTo(word, 0);
        return Convert.ToHexString(word).ToLowerInvariant();
    }

    private static string PadRight(byte[] value)
    {
        var padded = new byte[(value.Length + 31) / 32 * 32];
        value.CopyTo(padded, 0);
        return Convert.ToHexString(padded).ToLowerInvariant();
    }

    private static string Strip(string hex)
        => (hex.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? hex[2..] : hex)
            .ToLowerInvariant();

    internal string PaddedIdentity => "0x" + Strip(Identity).PadLeft(64, '0');
}

sealed class InMemoryEthereumRegistry : IEthereumRpcClient
{
    private readonly string _registryAddress;
    private readonly IReadOnlyDictionary<ulong, DateTimeOffset> _blockTimes;
    private readonly ulong? _assertedLatestBlock;
    private readonly SortedDictionary<ulong, List<Erc1056Log>> _blocks = new();

    // assertedLatestBlock overrides what changed(identity) reports, so the registry can assert
    // a change at a block it will not serve — the "incomplete history" case a resolver must
    // fail closed on.
    public InMemoryEthereumRegistry(
        string registryAddress,
        IReadOnlyDictionary<ulong, DateTimeOffset>? blockTimes = null,
        ulong? assertedLatestBlock = null)
    {
        _registryAddress     = registryAddress;
        _blockTimes          = blockTimes ?? new Dictionary<ulong, DateTimeOffset>();
        _assertedLatestBlock = assertedLatestBlock;
    }

    /// <summary>Appends one block of events. Blocks must be added in ascending order.</summary>
    public void AddBlock(ulong blockNumber, params Erc1056Log[] logs)
        => _blocks.Add(blockNumber, [.. logs]);

    /// <summary>Wraps this registry in an <see cref="IEthereumRpcClientFactory"/>.</summary>
    public static IEthereumRpcClientFactory FactoryFor(
        EthereumNetworkConfig network, InMemoryEthereumRegistry registry)
        => new SingleNetworkFactory(network.Name, registry);

    // ── IEthereumRpcClient ───────────────────────────────────────────────────

    /// <summary>
    /// eth_call — resolution only ever issues ERC-1056 <c>changed(identity)</c>, and each
    /// registry instance here scripts a single identity, so the calldata needs no dispatch.
    /// </summary>
    public Task<string> CallAsync(string to, string data, CancellationToken ct = default)
    {
        var latest = _assertedLatestBlock
            ?? (_blocks.Count == 0 ? 0UL : _blocks.Keys.Max());
        return Task.FromResult("0x" + latest.ToString("x64"));
    }

    /// <summary>eth_getLogs — the resolver queries exactly one block per hop.</summary>
    public Task<IReadOnlyList<EthereumLogEntry>> GetLogsAsync(
        EthereumLogFilter filter, CancellationToken ct = default)
    {
        if (!_blocks.TryGetValue(filter.FromBlock, out var logs))
            return Task.FromResult<IReadOnlyList<EthereumLogEntry>>([]);

        // ERC-1056 sets changed[identity] = block.number on every mutation, so the first
        // event in a block points at the previous change and every later event in the same
        // block points at this block. The resolver enforces exactly that.
        var previousBlock = _blocks.Keys.LastOrDefault(b => b < filter.FromBlock);

        return Task.FromResult<IReadOnlyList<EthereumLogEntry>>(
        [
            .. logs.Select((log, index) => new EthereumLogEntry
            {
                Address     = _registryAddress,
                Topics      = [log.Topic, log.PaddedIdentity],
                Data        = log.EncodeData(index == 0 ? previousBlock : filter.FromBlock),
                BlockNumber = "0x" + filter.FromBlock.ToString("x"),
                LogIndex    = (ulong)index,
            })
        ]);
    }

    public Task<ulong> GetBlockNumberAsync(CancellationToken ct = default)
        => Task.FromResult(_blocks.Count == 0 ? 0UL : _blocks.Keys.Max());

    public Task<ulong> GetChainIdAsync(CancellationToken ct = default)
        => Task.FromResult(11155111UL);

    public Task<ulong> GetBlockTimestampAsync(ulong blockNumber, CancellationToken ct = default)
        => Task.FromResult(_blockTimes.TryGetValue(blockNumber, out var at)
            ? (ulong)at.ToUnixTimeSeconds()
            : (ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds());

    // Write methods are part of the interface for the (not yet implemented) Update /
    // Deactivate operations; resolution never calls them.
    public Task<string> SendRawTransactionAsync(byte[] signedTransaction, CancellationToken ct = default)
        => throw new NotSupportedException("The sample registry is read-only.");

    public Task<ulong> GetTransactionCountAsync(string address, CancellationToken ct = default)
        => throw new NotSupportedException("The sample registry is read-only.");

    public Task<ulong> GetGasPriceAsync(CancellationToken ct = default)
        => throw new NotSupportedException("The sample registry is read-only.");

    private sealed class SingleNetworkFactory(string networkName, IEthereumRpcClient client)
        : IEthereumRpcClientFactory
    {
        public IEthereumRpcClient GetOrCreate(EthereumNetworkConfig network)
            => string.Equals(network.Name, networkName, StringComparison.OrdinalIgnoreCase)
                ? client
                : throw new InvalidOperationException(
                    $"No RPC client configured for network '{network.Name}'.");
    }
}
