using System.Text.Json;
using NetDid.Core.Crypto;
using NetDid.Core.Serialization;
using NetDid.Method.Ethr;
using NetDid.Method.Ethr.Rpc;

// ── Option A: use KnownNetworks with record `with` (recommended) ──────────────
var config = KnownNetworks.Sepolia with { RpcUrl = "https://sepolia.drpc.org" };

var http   = new HttpClient { BaseAddress = new Uri(config.RpcUrl) };
var rpc    = new DefaultEthereumRpcClient(http);
var method = new DidEthrMethod(rpc, [config], new DefaultKeyGenerator());

// ── Option B (DI): builder.AddDidEthr(new Dictionary<string,string> { ["sepolia"] = "..." })
// See NetDidBuilder.AddDidEthr overloads.

var did    = "did:ethr:sepolia:0xf61c81096c96f97e95ac52a570966195ad6c90dd";
Console.WriteLine($"Resolving: {did}");
Console.WriteLine();

var result = await method.ResolveAsync(did);

if (result.ResolutionMetadata.Error is string err)
{
    Console.Error.WriteLine($"Resolution error: {err}");
    return;
}

var json = DidDocumentSerializer.Serialize(result.DidDocument!);
Console.WriteLine("=== DID Document ===");
Console.WriteLine(JsonSerializer.Serialize(
    JsonSerializer.Deserialize<JsonElement>(json),
    new JsonSerializerOptions { WriteIndented = true }));

Console.WriteLine();
Console.WriteLine("=== Document Metadata ===");
var meta = result.DocumentMetadata;
if (meta != null)
{
    if (meta.VersionId   != null) Console.WriteLine($"  versionId  : {meta.VersionId}");
    if (meta.Deactivated == true) Console.WriteLine($"  deactivated: true");
}
