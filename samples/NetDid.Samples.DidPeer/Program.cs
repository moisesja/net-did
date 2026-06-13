using System.Text;
using NetCid;
using NetDid.Core;
using NetCrypto;
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

// -------------------------------------------------------
// 4. End-to-end ECDH between two did:peer:2 identities
//    Each side publishes a did:peer:2 with an X25519 key marked
//    KeyAgreement (purpose 'E'). To establish a shared secret —
//    e.g. as the base "Z" for a DIDComm anoncrypt JWE — each side
//    resolves the other's DID, extracts the X25519 key from the
//    resolved Document, and pairs it with its own private key
//    via DeriveSharedSecret. No HKDF / Concat KDF is applied; the
//    caller is responsible for running Z through the JOSE KDF
//    appropriate to its envelope.
// -------------------------------------------------------
Console.WriteLine("=== did:peer — ECDH between two peers (DIDComm setup) ===");

// Alice's identity. She holds the X25519 private key locally; only the
// public key is published via her did:peer DID Document.
var aliceX25519 = keyGen.Generate(KeyType.X25519);
var aliceAuth = keyGen.Generate(KeyType.Ed25519);
var alicePeer = await didPeer.CreateAsync(new DidPeerCreateOptions
{
    Numalgo = PeerNumalgo.Two,
    Keys =
    [
        new PeerKeyPurpose(new KeyPairSigner(aliceAuth, crypto), PeerPurpose.Authentication),
        new PeerKeyPurpose(new KeyPairSigner(aliceX25519, crypto), PeerPurpose.KeyAgreement)
    ]
});

// Bob's identity, same shape.
var bobX25519 = keyGen.Generate(KeyType.X25519);
var bobAuth = keyGen.Generate(KeyType.Ed25519);
var bobPeer = await didPeer.CreateAsync(new DidPeerCreateOptions
{
    Numalgo = PeerNumalgo.Two,
    Keys =
    [
        new PeerKeyPurpose(new KeyPairSigner(bobAuth, crypto), PeerPurpose.Authentication),
        new PeerKeyPurpose(new KeyPairSigner(bobX25519, crypto), PeerPurpose.KeyAgreement)
    ]
});

Console.WriteLine($"  Alice DID: {alicePeer.Did.Value[..40]}…");
Console.WriteLine($"  Bob   DID: {bobPeer.Did.Value[..40]}…");

// Bob's side: resolve Alice's DID, pull the X25519 keyAgreement key
// out of the resolved Document, and use his own X25519 private key
// to derive Z = ECDH(bobPriv, alicePub).
var aliceResolved = await didPeer.ResolveAsync(alicePeer.Did.Value);
var aliceKeyAgreementPubKey = ExtractX25519PublicKey(aliceResolved.DidDocument!);
var bobSideZ = crypto.DeriveSharedSecret(
    KeyType.X25519, bobX25519.PrivateKey, aliceKeyAgreementPubKey);

// Alice's side: symmetric — resolve Bob's DID and derive against his
// published X25519 key. Both parties must compute the same Z.
var bobResolved = await didPeer.ResolveAsync(bobPeer.Did.Value);
var bobKeyAgreementPubKey = ExtractX25519PublicKey(bobResolved.DidDocument!);
var aliceSideZ = crypto.DeriveSharedSecret(
    KeyType.X25519, aliceX25519.PrivateKey, bobKeyAgreementPubKey);

Console.WriteLine($"  Shared Z length:  {aliceSideZ.Length} bytes (raw — feed to JOSE Concat KDF)");
Console.WriteLine($"  Both sides agree: {aliceSideZ.AsSpan().SequenceEqual(bobSideZ)}");
Console.WriteLine();

// -------------------------------------------------------
// 5. Concat KDF (RFC 7518 §4.6 / NIST SP 800-56A §5.8.1)
//    Pair DeriveSharedSecret (raw Z) with ConcatKdf to derive a JOSE-compatible
//    content encryption key. This is the canonical ECDH-ES key-derivation pipeline.
// -------------------------------------------------------
Console.WriteLine("=== ECDH-ES key derivation (raw Z + Concat KDF) ===");

// Reuse the raw Z both parties derived above via the did:peer ECDH flow.
var z = aliceSideZ;
var contentEncryptionKey = ConcatKdf.DeriveKey(
    sharedSecret: z,
    algorithmId: Encoding.UTF8.GetBytes("A128GCM"),
    partyUInfo: Encoding.UTF8.GetBytes("Alice"),
    partyVInfo: Encoding.UTF8.GetBytes("Bob"),
    suppPubInfo: [0x00, 0x00, 0x00, 0x80],   // 128 bits as 32-bit BE
    suppPrivInfo: ReadOnlySpan<byte>.Empty,
    keyDataLen: 16);

Console.WriteLine($"  Z (raw ECDH):        {z.Length} bytes");
Console.WriteLine($"  CEK (Concat KDF):    {contentEncryptionKey.Length} bytes — feed to AES-GCM");
Console.WriteLine();

Console.WriteLine("Done! All did:peer examples completed successfully.");

// Pulls the first KeyAgreement verification method out of a resolved
// DID Document and decodes its publicKeyMultibase back to raw X25519
// bytes. Real DIDComm code would also assert keyType == X25519 and
// handle the case of multiple keyAgreement entries.
static byte[] ExtractX25519PublicKey(DidDocument doc)
{
    var kaRef = doc.KeyAgreement![0];
    var kaVm = kaRef.IsReference
        ? doc.VerificationMethod!.Single(v => v.Id == kaRef.Reference)
        : kaRef.EmbeddedMethod!;

    var multicodecPrefixed = Multibase.Decode(kaVm.PublicKeyMultibase!);
    var (_, rawKey) = Multicodec.Decode(multicodecPrefixed);
    return rawKey;
}
