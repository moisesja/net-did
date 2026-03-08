using NetDid.Core;
using NetDid.Core.Crypto;
using NetDid.Core.Model;
using NetDid.Core.Serialization;
using NetDid.Method.Key;
using NetDid.Method.Peer;

// ============================================================
// NetDid Samples — did:key and did:peer usage examples
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

Console.WriteLine("Done! All examples completed successfully.");
