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
using NetDid.Method.Ethr.Deployment;
using NetDid.Method.Ethr.Emulator;
using NetDid.Method.Ethr.Erc1056;
using NetDid.Method.Ethr.Rpc;

// ============================================================
// NetDid Samples — did:ethr (ERC-1056, full CRUD)
// ============================================================
//
// Runs OFFLINE by default against an in-memory ERC-1056 chain (EmulatedEthereumChain,
// from the non-shipped emulator project). The emulator is honest at the protocol
// boundary — every write below is genuinely RLP-encoded, EIP-155-signed, and
// sender-recovered with real ecrecover before the transcribed registry semantics run —
// so the code you see here is exactly the code you would run against a live network.
//
// To resolve a REAL DID from a live endpoint:  dotnet run -- --live [rpcUrl]

var keyGen = new DefaultKeyGenerator();
var crypto = new DefaultCryptoProvider();

// A network config is (name, RPC URL, chain ID, ERC-1056 registry address). KnownNetworks
// carries every field except the endpoint; the emulator stands in for that endpoint here.
var sepolia = KnownNetworks.Sepolia with { RpcUrl = "http://emulated.local" };
var chain   = new EmulatedEthereumChain(sepolia.RegistryAddress);
var ethr    = new DidEthrMethod(
    new SingleNetworkRpcFactory("sepolia", chain), [sepolia], keyGen);

var resolver     = new CompositeDidResolver([ethr]);
var dereferencer = new DefaultDidUrlDereferencer(resolver);

// The cast of keys. KeyPairSigner (NetCrypto) implements IRecoverableDigestSigner, the
// seam did:ethr transactions are signed through — an HSM/key-store signer works the same.
var alice    = NewActor();  // identity owner
var newOwner = NewActor();  // takes over Alice's identity later
var relayer  = NewActor();  // pays gas for meta-transactions
var bob      = NewActor();  // sigAuth delegate
var carol    = NewActor();  // short-lived veriKey delegate
var dave     = NewActor();  // revoked veriKey delegate

var aliceDid = $"did:ethr:sepolia:{alice.Address}";

// ---------------------------------------------------------------
// 1. Create — derive a did:ethr from a fresh secp256k1 key
// ---------------------------------------------------------------
Console.WriteLine("=== did:ethr — Create ===");

var created = await ethr.CreateAsync(new DidEthrCreateOptions { Network = "sepolia" });
Console.WriteLine($"  DID:      {created.Did}");
Console.WriteLine($"  VM type:  {created.DidDocument.VerificationMethod![0].Type}");
Console.WriteLine($"  CAIP-10:  {created.DidDocument.VerificationMethod[0].BlockchainAccountId}");
Console.WriteLine("  No transaction needed — any secp256k1 key pair already IS a did:ethr.");
Console.WriteLine();

// ---------------------------------------------------------------
// 2. Identifier forms and existing keys
// ---------------------------------------------------------------
Console.WriteLine("=== did:ethr — Identifier forms ===");

var fromExisting = await ethr.CreateAsync(new DidEthrCreateOptions
{
    Network     = "sepolia",
    ExistingKey = alice.IsigSigner, // ISigner is enough here: Create only reads the public key
});
Console.WriteLine($"  From existing key: {fromExisting.Did}  (deterministic: same key ⇒ same DID)");

foreach (var candidate in new[]
{
    "did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a",          // bare address ⇒ mainnet
    "did:ethr:sepolia:0xb9c5714089478a327f09197987f16f9e5d936e8a",  // named network
    "did:ethr:0xaa36a7:0xb9c5714089478a327f09197987f16f9e5d936e8a", // hex chain ID
    $"did:ethr:sepolia:0x{Convert.ToHexString(alice.KeyPair.PublicKey).ToLowerInvariant()}", // compressed pubkey
})
{
    var id = EthrIdentifier.Parse(candidate);
    Console.WriteLine($"  network={id.Network,-10} chainId={id.ChainId,-9} " +
                      $"address={id.IdentityAddress} publicKey={id.IsPublicKey}");
}
Console.WriteLine($"  Address derivation: EthereumAddress.FromCompressedPublicKey → " +
                  $"{EthereumAddress.FromCompressedPublicKey(alice.KeyPair.PublicKey)}");
Console.WriteLine();

// ---------------------------------------------------------------
// 3. Known networks
// ---------------------------------------------------------------
Console.WriteLine("=== did:ethr — Known networks ===");
Console.WriteLine($"  {KnownNetworks.All.Count} built-in deployments (registry + chain ID pre-populated):");
foreach (var n in KnownNetworks.All.Take(3))
    Console.WriteLine($"    {n.Name,-10} chainId={n.ChainId,-10} registry={n.RegistryAddress[..10]}… legacyNonce={n.LegacyNonce}");
Console.WriteLine($"    … and {KnownNetworks.All.Count - 3} more; " +
                  $"KnownNetworks.Find(\"0xaa36a7\")?.Name = {KnownNetworks.Find("0xaa36a7")?.Name}");
Console.WriteLine();

// ---------------------------------------------------------------
// 4. Update — write to the registry through the public API
// ---------------------------------------------------------------
Console.WriteLine("=== did:ethr — Update (services, delegates, key attributes) ===");

using var edKey = keyGen.Generate(KeyType.Ed25519);

var update1 = await ethr.UpdateAsync(aliceDid, new DidEthrUpdateOptions
{
    ControllerKey = alice.Signer,
    AddServices   =
    [
        new DidEthrServiceAttribute
        {
            ServiceType     = "MessagingService",
            ServiceEndpoint = "https://hub.example.com/messages",
        },
    ],
    AddDelegates =
    [
        // sigAuth ⇒ authentication + assertionMethod
        new DidEthrDelegate
        {
            DelegateType = "sigAuth", DelegateAddress = bob.Address,
            Validity = TimeSpan.FromDays(30),
        },
    ],
});
var version1 = (await ethr.ResolveAsync(aliceDid)).DocumentMetadata!.VersionId!;
Console.WriteLine($"  Update 1: +MessagingService, +sigAuth delegate  " +
                  $"→ {((IReadOnlyList<string>)update1.Artifacts!["transactions"]).Count} txs, versionId {version1}");

chain.AdvanceTime(TimeSpan.FromMinutes(20)); // let the chain clock move between versions

var update2 = await ethr.UpdateAsync(aliceDid, new DidEthrUpdateOptions
{
    ControllerKey = alice.Signer,
    // Raw did/pub attributes publish FULL key material — something the implicit
    // blockchainAccountId controller VM cannot do (an address is a hash, not a key).
    AddAttributes =
    [
        new DidEthrAttribute
        {
            Name  = "did/pub/Ed25519/veriKey/base64",
            Value = edKey.PublicKey,
        },
    ],
    AddDelegates =
    [
        // Expires ~30 minutes after a block minted ~40 minutes ago ⇒ already expired "now".
        new DidEthrDelegate
        {
            DelegateType = "veriKey", DelegateAddress = carol.Address,
            Validity = TimeSpan.FromMinutes(30),
        },
        new DidEthrDelegate
        {
            DelegateType = "veriKey", DelegateAddress = dave.Address,
            Validity = TimeSpan.FromDays(30),
        },
    ],
});
var version2 = (await ethr.ResolveAsync(aliceDid)).DocumentMetadata!.VersionId!;
Console.WriteLine($"  Update 2: +Ed25519 key attribute, +2 veriKey delegates → versionId {version2}");
Console.WriteLine($"  Update authority evidence: AuthorizationChange={update2.AuthorizationChange} " +
                  $"(only an owner change flips it)");
Console.WriteLine();

// ---------------------------------------------------------------
// 5. Resolve — the reconstructed DID Document
// ---------------------------------------------------------------
Console.WriteLine("=== did:ethr — Resolve ===");

var latest = await ethr.ResolveAsync(aliceDid);
Console.WriteLine(Indent(PrettyJson(DidDocumentSerializer.Serialize(latest.DidDocument!))));
Console.WriteLine($"  versionId={latest.DocumentMetadata!.VersionId}");
Console.WriteLine("  #delegate-N numbering follows the on-chain event counter, so expired");
Console.WriteLine("  entries leave gaps — matching the JS reference resolver.");
Console.WriteLine();

// ---------------------------------------------------------------
// 6. Historical resolution — ?versionId and ?versionTime
// ---------------------------------------------------------------
Console.WriteLine("=== did:ethr — Historical resolution ===");

foreach (var block in new[] { "0", version1, version2 })
{
    var at = await ethr.ResolveAsync(aliceDid, new DidEthrResolveOptions { VersionId = block });
    Console.WriteLine($"  ?versionId={block,-4} → {Summarize(at)}");
}

var betweenUpdates = DateTimeOffset.UtcNow.AddMinutes(-50); // after update 1, before update 2
var atTime = await ethr.ResolveAsync(aliceDid, new DidEthrResolveOptions
{
    VersionTime = betweenUpdates.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'"),
});
Console.WriteLine($"  ?versionTime=-50m  → {Summarize(atTime)}");
Console.WriteLine();

// ---------------------------------------------------------------
// 7. Expiry and revocation
// ---------------------------------------------------------------
Console.WriteLine("=== did:ethr — Expiry and revocation ===");

Console.WriteLine($"  Carol's 30-minute veriKey delegate:");
Console.WriteLine($"    at versionId={version2}: {Presence(await ResolveAt(version2), carol.Address)} (block time precedes validTo)");
Console.WriteLine($"    now:                {Presence(latest, carol.Address)} (expired)");

// ERC-1056 revocation: the same entry re-emitted with an elapsed validTo.
await ethr.UpdateAsync(aliceDid, new DidEthrUpdateOptions
{
    ControllerKey   = alice.Signer,
    RevokeDelegates =
    [
        new DidEthrDelegate { DelegateType = "veriKey", DelegateAddress = dave.Address },
    ],
});
chain.AdvanceTime(TimeSpan.FromSeconds(2)); // a revocation takes effect the next second
Console.WriteLine($"  Dave's 30-day delegate after RevokeDelegates: " +
                  $"{Presence(await ethr.ResolveAsync(aliceDid), dave.Address)} (revoked, not expired)");
Console.WriteLine();

// ---------------------------------------------------------------
// 8. Owner change — rotating the update authority
// ---------------------------------------------------------------
Console.WriteLine("=== did:ethr — Owner change ===");

var rotation = await ethr.UpdateAsync(aliceDid, new DidEthrUpdateOptions
{
    ControllerKey   = alice.Signer,
    NewOwnerAddress = newOwner.Address,
});
Console.WriteLine($"  changeOwner → controller VM now {rotation.DidDocument.VerificationMethod!
    .Single(v => v.Id.EndsWith("#controller")).BlockchainAccountId}");
Console.WriteLine($"  Evidence: UpdateKeyChange={rotation.UpdateKeyChange}, " +
                  $"EffectiveUpdateKeys=[{string.Join(", ", rotation.EffectiveUpdateKeys!)}]");

try
{
    await ethr.UpdateAsync(aliceDid, new DidEthrUpdateOptions
    {
        ControllerKey = alice.Signer, // the OLD key
        AddServices   = [new DidEthrServiceAttribute { ServiceType = "X", ServiceEndpoint = "https://x" }],
    });
}
catch (EthereumInteractionException ex)
{
    Console.WriteLine($"  Old key rejected pre-flight (nothing broadcast): {FirstSentence(ex.Message)}");
}
Console.WriteLine();

// ---------------------------------------------------------------
// 9. Meta-transactions — the identity owner never needs ETH
// ---------------------------------------------------------------
Console.WriteLine("=== did:ethr — Meta-transactions ===");

await ethr.UpdateAsync(aliceDid, new DidEthrUpdateOptions
{
    ControllerKey      = newOwner.Signer,  // signs the ERC-1056 0x19 0x00 payload
    UseMetaTransaction = true,
    Relayer            = relayer.Signer,   // pays gas and signs the wrapping transaction
    AddServices        =
    [
        new DidEthrServiceAttribute { ServiceType = "Inbox", ServiceEndpoint = "https://inbox.example.com" },
    ],
});

Console.WriteLine($"  Relayer account nonce:     {await chain.GetTransactionCountAsync(relayer.Address)} (paid for the tx)");
Console.WriteLine($"  Controller account nonce:  {await chain.GetTransactionCountAsync(newOwner.Address)} (never funded, never sent)");
Console.WriteLine("  The contract's own nonce mapping makes each signed payload single-use —");
Console.WriteLine("  a replayed meta-transaction reverts. Legacy (pre-0.0.3) registries track");
Console.WriteLine("  that nonce differently; EthereumNetworkConfig.LegacyNonce handles both.");
Console.WriteLine();

// ---------------------------------------------------------------
// 10. DID URL dereferencing
// ---------------------------------------------------------------
Console.WriteLine("=== did:ethr — DID URL dereferencing ===");

var vmRef = await dereferencer.DereferenceAsync($"{aliceDid}#controller");
Console.WriteLine($"  …#controller                  → {((VerificationMethod)vmRef.ContentStream!).Type}");
var svcRef = await dereferencer.DereferenceAsync($"{aliceDid}?serviceType=Inbox");
Console.WriteLine($"  …?serviceType=Inbox           → {((DidDocument)svcRef.ContentStream!).Service![0].ServiceEndpoint.Uri}");
var genesis = await dereferencer.DereferenceAsync($"{aliceDid}?versionId=0");
Console.WriteLine($"  …?versionId=0                 → nextVersionId = {genesis.ContentMetadata!["nextVersionId"]}");
Console.WriteLine();

// ---------------------------------------------------------------
// 11. Resolution errors — resolvers report, they do not throw
// ---------------------------------------------------------------
Console.WriteLine("=== did:ethr — Resolution errors ===");

foreach (var (label, did, options) in new (string, string, DidEthrResolveOptions?)[]
{
    ("malformed identifier",       "did:ethr:sepolia:0xnothex",  null),
    ("non-canonical versionId",    aliceDid, new DidEthrResolveOptions { VersionId = "007" }),
    ("both version selectors",     aliceDid, new DidEthrResolveOptions { VersionId = "1", VersionTime = "2026-07-26T00:00:00Z" }),
    ("unconfigured network",       $"did:ethr:polygon:{alice.Address}", null),
})
{
    var failed = await ethr.ResolveAsync(did, options);
    Console.WriteLine($"  {label,-26} → error = {failed.ResolutionMetadata.Error}");
}

// Fail-closed replay: a node asserting a change it never serves gets internalError
// (an infrastructure failure, not a statement about the DID — issue #116), never a
// partial document that could hide a revocation.
chain.AssertedChangedBlockOverride = 999_999;
var truncated = await ethr.ResolveAsync(aliceDid);
Console.WriteLine($"  {"incomplete event history",-26} → error = {truncated.ResolutionMetadata.Error} (no partial document)");
chain.AssertedChangedBlockOverride = null;
Console.WriteLine();

// ---------------------------------------------------------------
// 12. Deactivate — and what it does NOT guarantee
// ---------------------------------------------------------------
Console.WriteLine("=== did:ethr — Deactivate ===");

var deactivation = await ethr.DeactivateAsync(aliceDid, new DidEthrDeactivateOptions
{
    ControllerKey = newOwner.Signer,
});
var afterDeactivation = await ethr.ResolveAsync(aliceDid);
Console.WriteLine($"  changeOwner(0x0) → Success={deactivation.Success}, " +
                  $"deactivated={afterDeactivation.DocumentMetadata!.Deactivated}, " +
                  $"document stripped={afterDeactivation.DidDocument!.VerificationMethod is null}");
var beforeDeactivation = await ethr.ResolveAsync(aliceDid, new DidEthrResolveOptions
{
    VersionId = (ulong.Parse(afterDeactivation.DocumentMetadata.VersionId!) - 1).ToString(),
});
Console.WriteLine($"  History survives: ?versionId={beforeDeactivation.DocumentMetadata!.VersionId} " +
                  $"still shows {beforeDeactivation.DidDocument!.VerificationMethod!.Count} VMs");

// The spec calls this irreversible; the deployed contract does not enforce that.
// identityOwner() is `owner != 0 ? owner : identity`, so zeroing the owner hands control
// back to the identity address — an EOA identity whose key survives can write again.
var ownerAfterDeactivation = await chain.CallAsync(
    sepolia.RegistryAddress, Erc1056Calls.IdentityOwner(alice.Address));
Console.WriteLine($"  identityOwner() afterwards: 0x{ownerAfterDeactivation[^40..]}");
Console.WriteLine("  ^ the identity itself, NOT 0x0 — deactivation is a resolution state, not a");
Console.WriteLine("    lock. It is terminal only when nobody can act as the identity address.");
Console.WriteLine();

// ---------------------------------------------------------------
// 13. Deploy your own registry (private / consortium chains)
// ---------------------------------------------------------------
Console.WriteLine("=== did:ethr — Registry deployment ===");

// Public networks never need this — KnownNetworks carries the existing deployments.
// For a private EVM chain, deploy the vendored official bytecode once:
chain.RecognizeDeployableRegistry(Erc1056Registry.ModernCreationBytecode.ToArray(), legacyNonce: false);
var deployed = await Erc1056Registry.DeployAsync(chain, NewActor().Signer, chainId: 11155111);
Console.WriteLine($"  Erc1056Registry.DeployAsync → {deployed}");
Console.WriteLine("  Then: new EthereumNetworkConfig { Name, RpcUrl, ChainId, RegistryAddress = … }");
Console.WriteLine();

// ---------------------------------------------------------------
// 14. Dependency-injection registration
// ---------------------------------------------------------------
Console.WriteLine("=== did:ethr — Dependency injection ===");

var services = new ServiceCollection();
services.AddNetDid(b => b
    .AddDidKey()
    .AddDidEthr(new Dictionary<string, string>
    {
        ["mainnet"] = "https://mainnet.example/rpc",
        ["sepolia"] = "https://sepolia.example/rpc",
    }));
using var provider = services.BuildServiceProvider();
Console.WriteLine($"  Registered methods: {string.Join(", ",
    provider.GetServices<IDidMethod>().Select(m => $"did:{m.MethodName}"))}");
Console.WriteLine("  Each network gets its own named HttpClient, so multi-network setups");
Console.WriteLine("  can never query the wrong chain.");
Console.WriteLine();

// ---------------------------------------------------------------
// 15. Optional: resolve a real DID from a live endpoint
// ---------------------------------------------------------------
if (args.Contains("--live", StringComparer.OrdinalIgnoreCase))
{
    var liveRpcUrl = args.SkipWhile(a => !a.Equals("--live", StringComparison.OrdinalIgnoreCase))
                         .Skip(1).FirstOrDefault()
                     ?? Environment.GetEnvironmentVariable("NETDID_ETHR_RPC_URL")
                     ?? "https://sepolia.drpc.org";
    Console.WriteLine($"=== did:ethr — Live resolution ({liveRpcUrl}) ===");

    var liveNetwork = KnownNetworks.Sepolia with { RpcUrl = liveRpcUrl };
    var liveMethod  = new DidEthrMethod(
        DefaultEthereumRpcClientFactory.CreateDirect([liveNetwork]), [liveNetwork], keyGen);
    var live = await liveMethod.ResolveAsync(
        "did:ethr:sepolia:0xf61c81096c96f97e95ac52a570966195ad6c90dd");

    Console.WriteLine(live.ResolutionMetadata.Error is { } liveError
        ? $"  error = {liveError}"
        : Indent(PrettyJson(DidDocumentSerializer.Serialize(live.DidDocument!))));
    Console.WriteLine("  (On-chain writes against a live network work exactly like sections 4-12;");
    Console.WriteLine("   they need a funded key, so this sample keeps live mode read-only. The");
    Console.WriteLine("   Anvil integration tests run the full lifecycle against a real EVM.)");
    Console.WriteLine();
}
else
{
    Console.WriteLine("Tip: `dotnet run -- --live [rpcUrl]` resolves a real Sepolia DID over JSON-RPC.");
    Console.WriteLine();
}

Console.WriteLine("Done! All did:ethr examples completed successfully.");

// ============================================================
// Helpers
// ============================================================

Actor NewActor()
{
    var pair = keyGen.Generate(KeyType.Secp256k1);
    return new Actor(
        pair,
        new KeyPairSigner(pair, crypto, ownsKeyPair: false),
        new KeyPairSigner(pair, crypto, ownsKeyPair: false),
        EthereumAddress.FromCompressedPublicKey(pair.PublicKey).ToLowerInvariant());
}

async Task<DidResolutionResult> ResolveAt(string versionId)
    => await ethr.ResolveAsync(aliceDid, new DidEthrResolveOptions { VersionId = versionId });

static string Presence(DidResolutionResult result, string delegateAddress)
    => result.DidDocument?.VerificationMethod?.Any(v =>
           v.BlockchainAccountId?.Contains(delegateAddress[2..], StringComparison.OrdinalIgnoreCase) == true)
       == true ? "present" : "absent ";

static string Summarize(DidResolutionResult result)
{
    if (result.ResolutionMetadata.Error is { } error)
        return $"error = {error}";
    var doc = result.DidDocument!;
    return $"VMs={doc.VerificationMethod?.Count ?? 0} services={doc.Service?.Count ?? 0} " +
           $"versionId={result.DocumentMetadata?.VersionId ?? "-"} " +
           $"nextVersionId={result.DocumentMetadata?.NextVersionId ?? "-"}";
}

static string PrettyJson(string json)
    => JsonSerializer.Serialize(
        JsonSerializer.Deserialize<JsonElement>(json),
        new JsonSerializerOptions { WriteIndented = true });

static string Indent(string text)
    => string.Join(Environment.NewLine, text.Split(Environment.NewLine).Select(l => "    " + l));

static string FirstSentence(string message)
{
    var stop = message.IndexOf(';');
    return stop > 0 ? message[..stop] : message;
}

/// <summary>A key pair with both signer facets: ISigner (Create) and IRecoverableDigestSigner (writes).</summary>
sealed record Actor(KeyPair KeyPair, KeyPairSigner Signer, ISigner IsigSigner, string Address);
