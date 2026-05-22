using NetDid.Core;
using NetDid.Core.Crypto;
using NetDid.Method.Ethr;
using NetDid.Method.Ethr.Rpc;

// ── Configure ─────────────────────────────────────────────────────────────────
var rpcClient = new DefaultEthereumRpcClient(new HttpClient
{
    BaseAddress = new Uri("https://rpc.sepolia.org"),
});

var networks = new[]
{
    new EthereumNetworkConfig
    {
        Name     = "sepolia",
        RpcUrl   = "https://rpc.sepolia.org",
        ChainId  = "0xaa36a7",
    }
};

var method = new DidEthrMethod(rpcClient, networks, new DefaultKeyGenerator());

// ── 1. Create a did:ethr (derives address from new key; no on-chain transaction) ──
Console.WriteLine("=== Creating did:ethr ===");
var createResult = await method.CreateAsync(new DidEthrCreateOptions { Network = "sepolia" });
Console.WriteLine($"DID: {createResult.Did}");
Console.WriteLine();

// ── 2. Resolve a well-known did:ethr (requires live RPC — will fail offline) ──
Console.WriteLine("=== Resolving did:ethr ===");
var testDid = createResult.Did.Value!;
try
{
    var resolved = await method.ResolveAsync(testDid);
    if (resolved.ResolutionMetadata.Error is string err)
    {
        Console.WriteLine($"Resolution error: {err}");
    }
    else
    {
        Console.WriteLine($"Resolved: {testDid}");
        Console.WriteLine($"VMs: {resolved.DidDocument!.VerificationMethod?.Count ?? 0}");
        foreach (var vm in resolved.DidDocument.VerificationMethod ?? [])
            Console.WriteLine($"  {vm.Id} ({vm.Type})");
    }
}
catch (Exception ex)
{
    Console.WriteLine($"RPC unavailable in offline mode: {ex.Message}");
}
