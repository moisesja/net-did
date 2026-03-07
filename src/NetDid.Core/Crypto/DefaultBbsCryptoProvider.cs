namespace NetDid.Core.Crypto;

/// <summary>
/// BBS+ signature operations using BLS12-381 G2.
/// Follows IETF draft-irtf-cfrg-bbs-signatures.
/// </summary>
/// <remarks>
/// This implementation requires the Nethermind.Crypto.Bls pairing operations.
/// Currently stubbed — full implementation pending BLS library integration.
/// </remarks>
public sealed class DefaultBbsCryptoProvider : IBbsCryptoProvider
{
    public byte[] Sign(ReadOnlySpan<byte> privateKey, IReadOnlyList<byte[]> messages)
    {
        // TODO: Implement BBS+ multi-message signing
        throw new NotImplementedException("BBS+ signing is not yet implemented. Requires BLS12-381 pairing operations.");
    }

    public bool Verify(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> signature, IReadOnlyList<byte[]> messages)
    {
        // TODO: Implement BBS+ signature verification
        throw new NotImplementedException("BBS+ verification is not yet implemented.");
    }

    public byte[] DeriveProof(
        ReadOnlySpan<byte> publicKey,
        byte[] signature,
        IReadOnlyList<byte[]> messages,
        IReadOnlyList<int> revealedIndices,
        ReadOnlySpan<byte> nonce)
    {
        // TODO: Implement BBS+ selective disclosure proof derivation
        throw new NotImplementedException("BBS+ proof derivation is not yet implemented.");
    }

    public bool VerifyProof(
        ReadOnlySpan<byte> publicKey,
        byte[] proof,
        IReadOnlyList<byte[]> revealedMessages,
        IReadOnlyList<int> revealedIndices,
        int totalMessageCount,
        ReadOnlySpan<byte> nonce)
    {
        // TODO: Implement BBS+ proof verification
        throw new NotImplementedException("BBS+ proof verification is not yet implemented.");
    }
}
