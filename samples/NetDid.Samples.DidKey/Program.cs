using NetDid.Core;
using NetCrypto;
using NetDid.Core.Model;
using NetDid.Core.Serialization;
using NetDid.Method.Key;

// ============================================================
// NetDid Samples — did:key
// ============================================================

var keyGen = new DefaultKeyGenerator();
var crypto = new DefaultCryptoProvider();
var didKey = new DidKeyMethod(keyGen);

// -------------------------------------------------------
// 1. Create with Ed25519 (most common)
// -------------------------------------------------------
Console.WriteLine("=== did:key — Ed25519 ===");

var keyResult = await didKey.CreateAsync(new DidKeyCreateOptions
{
    KeyType = KeyType.Ed25519
});

Console.WriteLine($"  Created: {keyResult.Did}");
Console.WriteLine($"  VMs:     {keyResult.DidDocument.VerificationMethod!.Count}");
Console.WriteLine($"  (Ed25519 signing key + derived X25519 key agreement key)");
Console.WriteLine();

// -------------------------------------------------------
// 2. Resolve (deterministic, no network)
// -------------------------------------------------------
Console.WriteLine("=== did:key — Resolve ===");

var resolved = await didKey.ResolveAsync(keyResult.Did.Value);
Console.WriteLine($"  Resolved: {resolved.DidDocument!.Id}");
Console.WriteLine($"  VMs:      {resolved.DidDocument.VerificationMethod!.Count}");
Console.WriteLine($"  Auth:     {resolved.DidDocument.Authentication?.Count ?? 0}");
Console.WriteLine($"  KeyAgree: {resolved.DidDocument.KeyAgreement?.Count ?? 0}");
Console.WriteLine();

// -------------------------------------------------------
// 3. Use an existing key (e.g., from HSM/vault)
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
// 4. JsonWebKey2020 representation
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
// 5. P-521 (ES512) — high-strength NIST curve
// -------------------------------------------------------
Console.WriteLine("=== did:key — P-521 (ES512) ===");

var p521Result = await didKey.CreateAsync(new DidKeyCreateOptions
{
    KeyType = KeyType.P521
});

var p521Vm = p521Result.DidDocument.VerificationMethod![0];
Console.WriteLine($"  Created: {p521Result.Did}");
Console.WriteLine($"  VM type: {p521Vm.Type}");
Console.WriteLine($"  PubKey:  compressed SEC1 (1 prefix + 66 X coord = 67 bytes)");
Console.WriteLine($"  Signs with SHA-512 (JOSE alg \"ES512\")");
Console.WriteLine();

// -------------------------------------------------------
// 6. BLS12-381 G2 (for selective disclosure)
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
// 7. ECDSA signature format — DER (default) vs IEEE P1363 (JOSE)
//    The same key produces a 70-72 byte DER signature or a fixed
//    64/96/132 byte P1363 (R‖S) signature, on demand.
// -------------------------------------------------------
Console.WriteLine("=== Signature format — DER vs IEEE P1363 ===");

var ecKey = keyGen.Generate(KeyType.P256);
var msg = "JOSE wire format"u8.ToArray();

var derSig = crypto.Sign(KeyType.P256, ecKey.PrivateKey, msg, EcdsaSignatureFormat.Der);
var p1363Sig = crypto.Sign(KeyType.P256, ecKey.PrivateKey, msg, EcdsaSignatureFormat.IeeeP1363);

Console.WriteLine($"  P-256 DER       length: {derSig.Length} bytes (variable, ASN.1)");
Console.WriteLine($"  P-256 IEEE P1363 length: {p1363Sig.Length} bytes (fixed 64 = 2 * field byte length)");
Console.WriteLine($"  Both verify with matching format: {crypto.Verify(KeyType.P256, ecKey.PublicKey, msg, p1363Sig, EcdsaSignatureFormat.IeeeP1363)}");
Console.WriteLine($"  Mismatched format returns false  : {crypto.Verify(KeyType.P256, ecKey.PublicKey, msg, p1363Sig, EcdsaSignatureFormat.Der)}");
Console.WriteLine();

// -------------------------------------------------------
// 8. Serialize to JSON-LD
// -------------------------------------------------------
Console.WriteLine("=== Serialization ===");

var jsonLd = DidDocumentSerializer.Serialize(resolved.DidDocument!, DidContentTypes.JsonLd);
Console.WriteLine($"  JSON-LD ({jsonLd.Length} chars):");
Console.WriteLine($"  {jsonLd[..Math.Min(jsonLd.Length, 120)]}...");
Console.WriteLine();

Console.WriteLine("Done! All did:key examples completed successfully.");
