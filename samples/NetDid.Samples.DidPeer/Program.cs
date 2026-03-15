using NetDid.Core;
using NetDid.Core.Crypto;
using NetDid.Core.Model;
using NetDid.Method.Peer;

// ============================================================
// NetDid Samples — did:peer
// ============================================================

var keyGen = new DefaultKeyGenerator();
var crypto = new DefaultCryptoProvider();
var didPeer = new DidPeerMethod(keyGen);

// -------------------------------------------------------
// 1. Numalgo 0 — Simple inception key
// -------------------------------------------------------
Console.WriteLine("=== did:peer — Numalgo 0 ===");

var peer0 = await didPeer.CreateAsync(new DidPeerCreateOptions
{
    Numalgo = PeerNumalgo.Zero,
    InceptionKeyType = KeyType.Ed25519
});

Console.WriteLine($"  Created: {peer0.Did}");
Console.WriteLine($"  VMs:     {peer0.DidDocument.VerificationMethod!.Count}");
Console.WriteLine();

// -------------------------------------------------------
// 2. Numalgo 2 — Inline keys + DIDComm service
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
// 3. Numalgo 4 — Hash-based short/long form
// -------------------------------------------------------
Console.WriteLine("=== did:peer — Numalgo 4 ===");

var peer4Key = keyGen.Generate(KeyType.Ed25519);
var inputDoc = new DidDocument
{
    // Per spec: input document MUST NOT include id — it's assigned during creation
    VerificationMethod =
    [
        new VerificationMethod
        {
            Id = "#key-0",
            Type = "Multikey",
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

Console.WriteLine("Done! All did:peer examples completed successfully.");
