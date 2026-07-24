using Microsoft.Extensions.DependencyInjection;
using NetDid.Core;
using NetCrypto;
using NetDid.Core.Model;
using NetDid.Extensions.DependencyInjection;
using NetDid.Method.Key;
using NetDid.Method.Peer;

// ============================================================
// NetDid Samples — Dependency Injection (Veramo-inspired)
// ============================================================
// This sample demonstrates the DI-based composition pattern,
// similar to Veramo's createAgent({ plugins: [...] }) approach.
// ============================================================

Console.WriteLine("=== DI Registration ===");

// Step 1: Register services — one line to compose all methods
var services = new ServiceCollection();
services.AddNetDid(builder =>
{
    builder.AddDidKey();
    builder.AddDidPeer();
    builder.AddCaching(TimeSpan.FromMinutes(15));
});

var provider = services.BuildServiceProvider();

// Step 2: Resolve IDidManager — the unified entry point for all DID operations
var manager = provider.GetRequiredService<IDidManager>();
Console.WriteLine($"  Registered methods: {string.Join(", ", manager.RegisteredMethods)}");
Console.WriteLine();

// -------------------------------------------------------
// 1. Create via IDidManager (routes to correct method)
// -------------------------------------------------------
Console.WriteLine("=== Create via IDidManager ===");

var keyResult = await manager.CreateAsync(new DidKeyCreateOptions
{
    KeyType = KeyType.Ed25519
});
Console.WriteLine($"  did:key created: {keyResult.Did}");

var peerResult = await manager.CreateAsync(new DidPeerCreateOptions
{
    Numalgo = PeerNumalgo.Zero,
    InceptionKeyType = KeyType.Ed25519
});
Console.WriteLine($"  did:peer created: {peerResult.Did}");
Console.WriteLine();

// -------------------------------------------------------
// 2. Resolve via IDidManager (auto-routes by DID method)
// -------------------------------------------------------
Console.WriteLine("=== Resolve via IDidManager ===");

var keyResolved = await manager.ResolveAsync(keyResult.Did.Value);
Console.WriteLine($"  Resolved did:key:  {keyResolved.DidDocument!.Id}");

var peerResolved = await manager.ResolveAsync(peerResult.Did.Value);
Console.WriteLine($"  Resolved did:peer: {peerResolved.DidDocument!.Id}");
Console.WriteLine();

// -------------------------------------------------------
// 3. Resolve via IDidResolver (lighter interface)
// -------------------------------------------------------
Console.WriteLine("=== Resolve via IDidResolver ===");

var resolver = provider.GetRequiredService<IDidResolver>();
Console.WriteLine($"  Can resolve did:key?  {resolver.CanResolve(keyResult.Did.Value)}");
Console.WriteLine($"  Can resolve did:ethr? {resolver.CanResolve("did:ethr:0x123")}");

// Caching in action — second resolve hits cache
var _ = await resolver.ResolveAsync(keyResult.Did.Value);
var cached = await resolver.ResolveAsync(keyResult.Did.Value);
Console.WriteLine($"  Cached resolve: {cached.DidDocument!.Id}");
Console.WriteLine();

// -------------------------------------------------------
// 4. Access specific method via GetMethod
// -------------------------------------------------------
Console.WriteLine("=== GetMethod ===");

var keyMethod = manager.GetMethod("key");
Console.WriteLine($"  Method: {keyMethod!.MethodName}");
Console.WriteLine($"  Capabilities: {keyMethod.Capabilities}");
Console.WriteLine();

// -------------------------------------------------------
// 5. Discovery surface — what does each method accept? (issue #36)
// -------------------------------------------------------
// Wallets and tooling can interrogate IDidMethod without constructing options
// or hardcoding a switch on MethodName.
Console.WriteLine("=== Method Discovery Surface ===");

foreach (var name in manager.RegisteredMethods)
{
    var method = manager.GetMethod(name)!;
    Console.WriteLine($"  did:{method.MethodName}");
    Console.WriteLine($"    SupportedKeyTypes:    [{string.Join(", ", method.SupportedKeyTypes)}]");
    Console.WriteLine($"    SupportsRecovery:     {method.SupportsRecovery}");
    Console.WriteLine($"    RecoveryMaterialSpec: {method.RecoveryMaterialSpec?.ToString() ?? "<null>"}");
}
Console.WriteLine();

// Example: pick a method that accepts P-256 before constructing options
var p256Capable = manager.RegisteredMethods
    .Select(n => manager.GetMethod(n)!)
    .Where(m => m.SupportedKeyTypes.Contains(KeyType.P256))
    .Select(m => m.MethodName)
    .ToList();
Console.WriteLine($"  Methods that accept P-256: [{string.Join(", ", p256Capable)}]");
Console.WriteLine();

Console.WriteLine("Done! DI integration examples completed successfully.");
