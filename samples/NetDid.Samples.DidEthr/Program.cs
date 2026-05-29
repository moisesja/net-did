using System.Text.Json;
using NetDid.Core.Crypto;
using NetDid.Core.Model;
using NetDid.Core.Resolution;
using NetDid.Core.Serialization;
using NetDid.Method.Ethr;
using NetDid.Method.Ethr.Rpc;

var config = KnownNetworks.Sepolia with { RpcUrl = "https://sepolia.drpc.org" };

var factory = DefaultEthereumRpcClientFactory.CreateDirect([config]);
var method  = new DidEthrMethod(factory, [config], new DefaultKeyGenerator());

var resolver     = new CompositeDidResolver([method]);
var dereferencer = new DefaultDidUrlDereferencer(resolver);

const string did = "did:ethr:sepolia:0xf61c81096c96f97e95ac52a570966195ad6c90dd";

// ── 1. Current document ───────────────────────────────────────────────────────
Console.WriteLine("=== Current document ===");
await PrintDereferencedDoc(dereferencer, did);

// ── 2. Genesis document (state before any events, via ?versionId=0) ───────────
Console.WriteLine("=== Genesis document (?versionId=0) ===");
await PrintDereferencedDoc(dereferencer, $"{did}?versionId=0");

// ── helpers ───────────────────────────────────────────────────────────────────

static async Task PrintDereferencedDoc(DefaultDidUrlDereferencer dereferencer, string url)
{
    Console.WriteLine($"Dereferencing: {url}");

    var result = await dereferencer.DereferenceAsync(url);

    if (result.DereferencingMetadata.Error is string err)
    {
        Console.Error.WriteLine($"  Error: {err}");
        Console.WriteLine();
        return;
    }

    if (result.ContentStream is not DidDocument doc)
    {
        Console.Error.WriteLine($"  Unexpected content type: {result.ContentStream?.GetType().Name}");
        Console.WriteLine();
        return;
    }

    var json = DidDocumentSerializer.Serialize(doc);
    Console.WriteLine(JsonSerializer.Serialize(
        JsonSerializer.Deserialize<JsonElement>(json),
        new JsonSerializerOptions { WriteIndented = true }));

    if (result.ContentMetadata is { Count: > 0 } meta)
    {
        Console.WriteLine("Metadata:");
        foreach (var (k, v) in meta)
            Console.WriteLine($"  {k}: {v}");
    }

    Console.WriteLine();
}
