using System.Text;
using NetDid.Core;
using NetDid.Core.Crypto;
using NetDid.Core.Model;
using NetDid.Method.Key;
using NetDid.Method.WebVh;

// ============================================================
// NetDid Samples — did:webvh (Verifiable History, Full CRUD)
// ============================================================

var keyGen = new DefaultKeyGenerator();
var crypto = new DefaultCryptoProvider();

// In-memory HTTP client for samples (in production, use DefaultWebVhHttpClient)
var webVhHttpClient = new InMemoryWebVhHttpClient();
var didWebVh = new DidWebVhMethod(webVhHttpClient, crypto);

// -------------------------------------------------------
// 1. Create a DID with services
// -------------------------------------------------------
Console.WriteLine("=== did:webvh — Create ===");

var webVhKey = keyGen.Generate(KeyType.Ed25519);
var webVhSigner = new KeyPairSigner(webVhKey, crypto);

var webVhResult = await didWebVh.CreateAsync(new DidWebVhCreateOptions
{
    Domain = "example.com",
    UpdateKey = webVhSigner,
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

Console.WriteLine($"  Created: {webVhResult.Did}");
Console.WriteLine($"  VMs:     {webVhResult.DidDocument.VerificationMethod!.Count}");
Console.WriteLine($"  Service: {webVhResult.DidDocument.Service![0].Type}");
Console.WriteLine($"  AKA:     {webVhResult.DidDocument.AlsoKnownAs![0]}");
Console.WriteLine();

// -------------------------------------------------------
// 2. Show generated artifacts
// -------------------------------------------------------
Console.WriteLine("=== did:webvh — Artifacts ===");

var logContent = (byte[])webVhResult.Artifacts!["did.jsonl"];
var didJsonContent = (byte[])webVhResult.Artifacts["did.json"];

Console.WriteLine($"  did.jsonl ({logContent.Length} bytes):");
var logText = Encoding.UTF8.GetString(logContent);
Console.WriteLine($"    {logText[..Math.Min(logText.Length, 120)]}...");

Console.WriteLine($"  did.json ({didJsonContent.Length} bytes):");
var didJsonText = Encoding.UTF8.GetString(didJsonContent);
Console.WriteLine($"    {didJsonText[..Math.Min(didJsonText.Length, 120)]}...");
Console.WriteLine();

// -------------------------------------------------------
// 3. Resolve (mock HTTP)
// -------------------------------------------------------
Console.WriteLine("=== did:webvh — Resolve ===");

// In production, did.jsonl is served via HTTPS. Here we mock it:
var logUrl = DidUrlMapper.MapToLogUrl(webVhResult.Did.Value);
webVhHttpClient.SetLogResponse(logUrl, logContent);

var webVhResolved = await didWebVh.ResolveAsync(webVhResult.Did.Value);
Console.WriteLine($"  Resolved: {webVhResolved.DidDocument!.Id}");
Console.WriteLine($"  Version:  {webVhResolved.DocumentMetadata!.VersionId}");
Console.WriteLine($"  Service:  {webVhResolved.DidDocument.Service![0].Type}");
Console.WriteLine();

// -------------------------------------------------------
// 4. Update (add a service endpoint)
// -------------------------------------------------------
Console.WriteLine("=== did:webvh — Update ===");

var updatedDoc = webVhResult.DidDocument with
{
    Service =
    [
        webVhResult.DidDocument.Service![0],
        new Service
        {
            Id = $"{webVhResult.Did}#api",
            Type = "ApiEndpoint",
            ServiceEndpoint = ServiceEndpointValue.FromUri("https://api.example.com/v1")
        }
    ]
};

var updateResult = await didWebVh.UpdateAsync(webVhResult.Did.Value, new DidWebVhUpdateOptions
{
    CurrentLogContent = logContent,
    SigningKey = webVhSigner,
    NewDocument = updatedDoc
});

var updatedLog = (byte[])updateResult.Artifacts!["did.jsonl"];
var entries = LogEntrySerializer.ParseJsonLines(updatedLog);
Console.WriteLine($"  Updated log: {entries.Count} entries");
Console.WriteLine($"  Version 2:   {entries[1].VersionId}");
Console.WriteLine($"  Services:    {updateResult.DidDocument.Service!.Count}");

// Verify updated resolve
webVhHttpClient.SetLogResponse(logUrl, updatedLog);
var updatedResolved = await didWebVh.ResolveAsync(webVhResult.Did.Value);
Console.WriteLine($"  Resolved v2: {updatedResolved.DocumentMetadata!.VersionId}");
Console.WriteLine();

// -------------------------------------------------------
// 5. Key rotation with pre-rotation
// -------------------------------------------------------
Console.WriteLine("=== did:webvh — Key Rotation with Pre-Rotation ===");

var rotationKey1 = keyGen.Generate(KeyType.Ed25519);
var rotationSigner1 = new KeyPairSigner(rotationKey1, crypto);
var rotationKey2 = keyGen.Generate(KeyType.Ed25519);
var commitment2 = PreRotationManager.ComputeKeyCommitment(rotationKey2.MultibasePublicKey);

// Create with pre-rotation enabled
var preRotResult = await didWebVh.CreateAsync(new DidWebVhCreateOptions
{
    Domain = "example.com",
    Path = "users/alice",
    UpdateKey = rotationSigner1,
    EnablePreRotation = true,
    PreRotationCommitments = [commitment2]
});

Console.WriteLine($"  Created: {preRotResult.Did}");
var preRotLog = (byte[])preRotResult.Artifacts!["did.jsonl"];
var preRotEntries = LogEntrySerializer.ParseJsonLines(preRotLog);
Console.WriteLine($"  Pre-rotation: {preRotEntries[0].Parameters.Prerotation}");
Console.WriteLine($"  Committed next key hash: {preRotEntries[0].Parameters.NextKeyHashes![0][..20]}...");

// Rotate to key2 (signed by key1, which is still the authorized key)
var rotationKey3 = keyGen.Generate(KeyType.Ed25519);
var commitment3 = PreRotationManager.ComputeKeyCommitment(rotationKey3.MultibasePublicKey);

var rotateResult = await didWebVh.UpdateAsync(preRotResult.Did.Value, new DidWebVhUpdateOptions
{
    CurrentLogContent = preRotLog,
    SigningKey = rotationSigner1,
    ParameterUpdates = new DidWebVhParameterUpdates
    {
        UpdateKeys = [rotationKey2.MultibasePublicKey],
        Prerotation = true,
        NextKeyHashes = [commitment3]
    }
});

var rotatedLog = (byte[])rotateResult.Artifacts!["did.jsonl"];
var rotatedEntries = LogEntrySerializer.ParseJsonLines(rotatedLog);
Console.WriteLine($"  Rotated to key2 at version {rotatedEntries[1].VersionNumber}");
Console.WriteLine($"  New update key: {rotatedEntries[1].Parameters.UpdateKeys![0][..20]}...");
Console.WriteLine();

// -------------------------------------------------------
// 6. Deactivate
// -------------------------------------------------------
Console.WriteLine("=== did:webvh — Deactivate ===");

var deactivateResult = await didWebVh.DeactivateAsync(
    webVhResult.Did.Value,
    new DidWebVhDeactivateOptions
    {
        CurrentLogContent = updatedLog,
        SigningKey = webVhSigner
    });

Console.WriteLine($"  Deactivated: {deactivateResult.Success}");

var deactivatedLog = (byte[])deactivateResult.Artifacts!["did.jsonl"];
webVhHttpClient.SetLogResponse(logUrl, deactivatedLog);

var deactivatedResolved = await didWebVh.ResolveAsync(webVhResult.Did.Value);
Console.WriteLine($"  Resolved deactivated: {deactivatedResolved.DocumentMetadata!.Deactivated}");
Console.WriteLine();

// -------------------------------------------------------
// 7. Dual-identity pattern (did:key + did:webvh, same key)
// -------------------------------------------------------
Console.WriteLine("=== Dual-identity pattern ===");

var didKey = new DidKeyMethod(keyGen);
var sharedKey = keyGen.Generate(KeyType.Ed25519);
var sharedSigner = new KeyPairSigner(sharedKey, crypto);

var keyDid = await didKey.CreateAsync(new DidKeyCreateOptions
{
    KeyType = KeyType.Ed25519,
    ExistingKey = sharedSigner
});

var webDid = await didWebVh.CreateAsync(new DidWebVhCreateOptions
{
    Domain = "example.com",
    Path = "id",
    UpdateKey = sharedSigner
});

Console.WriteLine($"  did:key  = {keyDid.Did}");
Console.WriteLine($"  did:webvh = {webDid.Did}");
Console.WriteLine($"  Same key:  {keyDid.DidDocument.VerificationMethod![0].PublicKeyMultibase == webDid.DidDocument.VerificationMethod![0].PublicKeyMultibase}");
Console.WriteLine();

Console.WriteLine("Done! All did:webvh examples completed successfully.");

// ============================================================
// Helper: In-memory HTTP client for samples
// ============================================================
class InMemoryWebVhHttpClient : IWebVhHttpClient
{
    private readonly Dictionary<string, byte[]> _logs = new();

    public void SetLogResponse(Uri url, byte[] content)
        => _logs[url.ToString()] = content;

    public Task<byte[]?> FetchDidLogAsync(Uri url, CancellationToken ct = default)
        => Task.FromResult(_logs.GetValueOrDefault(url.ToString()));

    public Task<byte[]?> FetchWitnessFileAsync(Uri url, CancellationToken ct = default)
        => Task.FromResult<byte[]?>(null);
}
