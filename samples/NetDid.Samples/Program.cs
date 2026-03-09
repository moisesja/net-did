using System.Text;
using NetDid.Core;
using NetDid.Core.Crypto;
using NetDid.Core.Model;
using NetDid.Core.Serialization;
using NetDid.Method.Key;
using NetDid.Method.Peer;
using NetDid.Method.WebVh;
using NetDid.Method.WebVh.Model;

// ============================================================
// NetDid Samples — did:key, did:peer, and did:webvh examples
// ============================================================

var keyGen = new DefaultKeyGenerator();
var crypto = new DefaultCryptoProvider();

// -------------------------------------------------------
// 1. did:key — Create with Ed25519 (most common)
// -------------------------------------------------------
Console.WriteLine("=== did:key — Ed25519 ===");

var didKey = new DidKeyMethod(keyGen);

var keyResult = await didKey.CreateAsync(new DidKeyCreateOptions
{
    KeyType = KeyType.Ed25519
});

Console.WriteLine($"  Created: {keyResult.Did}");
Console.WriteLine($"  VMs:     {keyResult.DidDocument.VerificationMethod!.Count}");
Console.WriteLine($"  (Ed25519 signing key + derived X25519 key agreement key)");
Console.WriteLine();

// -------------------------------------------------------
// 2. did:key — Resolve (deterministic, no network)
// -------------------------------------------------------
Console.WriteLine("=== did:key — Resolve ===");

var resolved = await didKey.ResolveAsync(keyResult.Did.Value);
Console.WriteLine($"  Resolved: {resolved.DidDocument!.Id}");
Console.WriteLine($"  VMs:      {resolved.DidDocument.VerificationMethod!.Count}");
Console.WriteLine($"  Auth:     {resolved.DidDocument.Authentication?.Count ?? 0}");
Console.WriteLine($"  KeyAgree: {resolved.DidDocument.KeyAgreement?.Count ?? 0}");
Console.WriteLine();

// -------------------------------------------------------
// 3. did:key — Use an existing key (e.g., from HSM/vault)
// -------------------------------------------------------
Console.WriteLine("=== did:key — Existing P-256 Key ===");

var p256KeyPair = keyGen.Generate(KeyType.P256);
var p256Signer = new KeyPairSigner(p256KeyPair, crypto);

var p256Result = await didKey.CreateAsync(new DidKeyCreateOptions
{
    KeyType = KeyType.P256,
    ExistingKey = p256Signer
});

Console.WriteLine($"  Created: {p256Result.Did}");
Console.WriteLine($"  VM type: {p256Result.DidDocument.VerificationMethod![0].Type}");
Console.WriteLine();

// -------------------------------------------------------
// 4. did:key — JsonWebKey2020 representation
// -------------------------------------------------------
Console.WriteLine("=== did:key — JWK Representation ===");

var jwkResult = await didKey.CreateAsync(new DidKeyCreateOptions
{
    KeyType = KeyType.Ed25519,
    Representation = VerificationMethodRepresentation.JsonWebKey2020
});

var jwkVm = jwkResult.DidDocument.VerificationMethod![0];
Console.WriteLine($"  Created: {jwkResult.Did}");
Console.WriteLine($"  VM type: {jwkVm.Type}");
Console.WriteLine($"  JWK kty: {jwkVm.PublicKeyJwk!.Kty}, crv: {jwkVm.PublicKeyJwk.Crv}");
Console.WriteLine();

// -------------------------------------------------------
// 5. did:key — BLS12-381 G2 (for selective disclosure)
// -------------------------------------------------------
Console.WriteLine("=== did:key — BLS12-381 G2 ===");

var blsResult = await didKey.CreateAsync(new DidKeyCreateOptions
{
    KeyType = KeyType.Bls12381G2
});

Console.WriteLine($"  Created: {blsResult.Did}");
Console.WriteLine($"  Auth:    {blsResult.DidDocument.Authentication?.Count ?? 0} (none — BBS+ not for auth)");
Console.WriteLine($"  Assert:  {blsResult.DidDocument.AssertionMethod?.Count ?? 0} (credential issuance)");
Console.WriteLine();

// -------------------------------------------------------
// 6. did:peer numalgo 0 — Simple inception key
// -------------------------------------------------------
Console.WriteLine("=== did:peer — Numalgo 0 ===");

var didPeer = new DidPeerMethod(keyGen);

var peer0 = await didPeer.CreateAsync(new DidPeerCreateOptions
{
    Numalgo = PeerNumalgo.Zero,
    InceptionKeyType = KeyType.Ed25519
});

Console.WriteLine($"  Created: {peer0.Did}");
Console.WriteLine($"  VMs:     {peer0.DidDocument.VerificationMethod!.Count}");
Console.WriteLine();

// -------------------------------------------------------
// 7. did:peer numalgo 2 — Inline keys + DIDComm service
//    Purpose codes per DIF spec: A=assertion, E=encryption
//    (key agreement), V=verification (auth), I=invocation,
//    D=delegation, S=service
// -------------------------------------------------------
Console.WriteLine("=== did:peer — Numalgo 2 (DIDComm) ===");

var authKey = keyGen.Generate(KeyType.Ed25519);
var agreeKey = keyGen.Generate(KeyType.X25519);
var assertKey = keyGen.Generate(KeyType.Ed25519);

var peer2 = await didPeer.CreateAsync(new DidPeerCreateOptions
{
    Numalgo = PeerNumalgo.Two,
    Keys =
    [
        new PeerKeyPurpose(new KeyPairSigner(authKey, crypto), PeerPurpose.Authentication),
        new PeerKeyPurpose(new KeyPairSigner(agreeKey, crypto), PeerPurpose.KeyAgreement),
        new PeerKeyPurpose(new KeyPairSigner(assertKey, crypto), PeerPurpose.Assertion)
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

Console.WriteLine($"  Created:  {peer2.Did}");
Console.WriteLine($"  VMs:      {peer2.DidDocument.VerificationMethod!.Count}");
Console.WriteLine($"  Auth:     {peer2.DidDocument.Authentication!.Count}");
Console.WriteLine($"  KeyAgree: {peer2.DidDocument.KeyAgreement!.Count}");
Console.WriteLine($"  Assert:   {peer2.DidDocument.AssertionMethod!.Count}");
Console.WriteLine($"  Services: {peer2.DidDocument.Service!.Count}");
Console.WriteLine($"  (Purpose codes: V=auth, E=keyAgreement, A=assertion)");

// Resolve the numalgo 2 DID
var peer2Resolved = await didPeer.ResolveAsync(peer2.Did.Value);
Console.WriteLine($"  Resolved service type: {peer2Resolved.DidDocument!.Service![0].Type}");
Console.WriteLine($"  Resolved service URI:  {peer2Resolved.DidDocument.Service[0].ServiceEndpoint.Uri}");
Console.WriteLine();

// -------------------------------------------------------
// 8. did:peer numalgo 4 — Hash-based short/long form
// -------------------------------------------------------
Console.WriteLine("=== did:peer — Numalgo 4 ===");

var peer4Key = keyGen.Generate(KeyType.Ed25519);
var inputDoc = new DidDocument
{
    Id = new Did("did:peer:placeholder"),
    VerificationMethod =
    [
        new VerificationMethod
        {
            Id = "#key-0",
            Type = "Multikey",
            Controller = new Did("did:peer:placeholder"),
            PublicKeyMultibase = peer4Key.MultibasePublicKey
        }
    ],
    Authentication =
    [
        VerificationRelationshipEntry.FromReference("#key-0")
    ]
};

var peer4 = await didPeer.CreateAsync(new DidPeerCreateOptions
{
    Numalgo = PeerNumalgo.Four,
    InputDocument = inputDoc
});

Console.WriteLine($"  Created (long-form): {peer4.Did.Value[..60]}...");

var peer4Resolved = await didPeer.ResolveAsync(peer4.Did.Value);
Console.WriteLine($"  Resolved VMs: {peer4Resolved.DidDocument!.VerificationMethod!.Count}");
Console.WriteLine();

// -------------------------------------------------------
// 9. Serialize a DID Document to JSON-LD
// -------------------------------------------------------
Console.WriteLine("=== Serialization ===");

var jsonLd = DidDocumentSerializer.Serialize(resolved.DidDocument!, DidContentTypes.JsonLd);
Console.WriteLine($"  JSON-LD ({jsonLd.Length} chars):");
Console.WriteLine($"  {jsonLd[..Math.Min(jsonLd.Length, 120)]}...");
Console.WriteLine();

// ============================================================
// did:webvh — Verifiable History (Full CRUD)
// ============================================================

// In-memory HTTP client for samples (in production, use DefaultWebVhHttpClient)
var webVhHttpClient = new InMemoryWebVhHttpClient();
var didWebVh = new DidWebVhMethod(webVhHttpClient, crypto);

// -------------------------------------------------------
// 10. did:webvh — Create a DID with services
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
// 11. did:webvh — Show generated artifacts
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
// 12. did:webvh — Resolve (mock HTTP)
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
// 13. did:webvh — Update (add a service endpoint)
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
// 14. did:webvh — Key rotation with pre-rotation
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
// 15. did:webvh — Deactivate
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
// 16. Dual-identity pattern (did:key + did:webvh, same key)
// -------------------------------------------------------
Console.WriteLine("=== Dual-identity pattern ===");

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

Console.WriteLine("Done! All examples completed successfully.");

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
