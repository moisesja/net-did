using NetDid.Core.Crypto;

namespace NetDid.Core;

/// <summary>
/// Low-level cryptographic operations. Application code should use <see cref="ISigner"/> instead.
/// </summary>
public interface ICryptoProvider
{
    byte[] Sign(KeyType keyType, ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> data);
    bool Verify(KeyType keyType, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature);
    byte[] KeyAgreement(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> publicKey);
}

/// <summary>
/// BBS+ signature operations (multi-message, selective disclosure, ZKPs).
/// Separated from <see cref="ICryptoProvider"/> because BBS+ operates over an ordered
/// set of messages rather than a single byte span.
/// </summary>
public interface IBbsCryptoProvider
{
    /// <summary>Sign an ordered set of messages using a BLS12-381 G2 private key.</summary>
    byte[] Sign(ReadOnlySpan<byte> privateKey, IReadOnlyList<byte[]> messages);

    /// <summary>Verify a BBS+ signature against the full set of messages.</summary>
    bool Verify(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> signature, IReadOnlyList<byte[]> messages);

    /// <summary>
    /// Derive a zero-knowledge proof that selectively discloses only the messages
    /// at the specified indices, without revealing the original signature.
    /// </summary>
    byte[] DeriveProof(
        ReadOnlySpan<byte> publicKey,
        byte[] signature,
        IReadOnlyList<byte[]> messages,
        IReadOnlyList<int> revealedIndices,
        ReadOnlySpan<byte> nonce);

    /// <summary>Verify a derived proof against the revealed messages.</summary>
    bool VerifyProof(
        ReadOnlySpan<byte> publicKey,
        byte[] proof,
        IReadOnlyList<byte[]> revealedMessages,
        IReadOnlyList<int> revealedIndices,
        ReadOnlySpan<byte> nonce);
}
