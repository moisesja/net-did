using NetDid.Core;
using NetDid.Core.Crypto;
using NetDid.Core.Model;

namespace NetDid.Method.Key;

/// <summary>
/// Options for creating a did:key DID.
/// </summary>
public sealed record DidKeyCreateOptions : DidCreateOptions
{
    /// <inheritdoc />
    public override string MethodName => "key";

    /// <summary>The cryptographic key type to use.</summary>
    public required KeyType KeyType { get; init; }

    /// <summary>
    /// Optional: wrap an existing key instead of generating a new one.
    /// When provided, the did:key is derived from ExistingKey.PublicKey.
    /// ExistingKey.KeyType must match KeyType (validated at creation time).
    /// Accepts any ISigner — works with both in-memory KeyPairSigner and
    /// HSM-backed signers where the private key never leaves the enclave.
    /// </summary>
    public ISigner? ExistingKey { get; init; }

    /// <summary>
    /// When true and KeyType is Ed25519, derives an X25519 key agreement key
    /// and adds it to the keyAgreement relationship. Default: true.
    /// </summary>
    public bool EnableEncryptionKeyDerivation { get; init; } = true;

    /// <summary>
    /// Controls how verification methods are represented in the DID Document.
    /// Default: Multikey (publicKeyMultibase).
    /// </summary>
    public VerificationMethodRepresentation Representation { get; init; } = VerificationMethodRepresentation.Multikey;
}
