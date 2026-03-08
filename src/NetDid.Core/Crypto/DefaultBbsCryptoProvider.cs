using System.Security.Cryptography;
using NetDid.Core.Crypto.Native;

namespace NetDid.Core.Crypto;

/// <summary>
/// BBS+ signature operations using BLS12-381-SHA-256 (IETF draft-irtf-cfrg-bbs-signatures-10).
/// Delegates to the zkryptium-ffi native library via P/Invoke.
/// </summary>
public sealed class DefaultBbsCryptoProvider : IBbsCryptoProvider
{
    private const int SecretKeySize = 32;
    private const int PublicKeySize = 96;
    private const int SignatureSize = 80;
    private const int MaxProofSize = 4096;

    public byte[] Sign(ReadOnlySpan<byte> privateKey, IReadOnlyList<byte[]> messages)
    {
        if (privateKey.Length != SecretKeySize)
            throw new ArgumentException($"BBS+ secret key must be {SecretKeySize} bytes.", nameof(privateKey));
        if (messages.Count == 0)
            throw new ArgumentException("At least one message is required.", nameof(messages));

        // Derive the public key from the secret key
        Span<byte> pk = stackalloc byte[PublicKeySize];
        var rc = ZkryptiumNative.bbs_sk_to_pk(privateKey, pk);
        if (rc != 0)
            throw new CryptographicException("Failed to derive BBS+ public key from secret key.");

        var encodedMessages = ZkryptiumNative.EncodeMessages(messages);
        Span<byte> signature = stackalloc byte[SignatureSize];

        rc = ZkryptiumNative.bbs_sign(
            privateKey, pk,
            ReadOnlySpan<byte>.Empty, 0,
            encodedMessages, (nuint)encodedMessages.Length,
            signature);

        if (rc != 0)
            throw new CryptographicException("BBS+ signing failed.");

        return signature.ToArray();
    }

    public bool Verify(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> signature, IReadOnlyList<byte[]> messages)
    {
        if (publicKey.Length != PublicKeySize)
            throw new ArgumentException($"BBS+ public key must be {PublicKeySize} bytes.", nameof(publicKey));
        if (signature.Length != SignatureSize)
            return false;

        var encodedMessages = ZkryptiumNative.EncodeMessages(messages);

        var rc = ZkryptiumNative.bbs_verify(
            publicKey,
            ReadOnlySpan<byte>.Empty, 0,
            encodedMessages, (nuint)encodedMessages.Length,
            signature);

        return rc == 0;
    }

    public byte[] DeriveProof(
        ReadOnlySpan<byte> publicKey,
        byte[] signature,
        IReadOnlyList<byte[]> messages,
        IReadOnlyList<int> revealedIndices,
        ReadOnlySpan<byte> nonce)
    {
        if (publicKey.Length != PublicKeySize)
            throw new ArgumentException($"BBS+ public key must be {PublicKeySize} bytes.", nameof(publicKey));
        if (signature.Length != SignatureSize)
            throw new ArgumentException($"BBS+ signature must be {SignatureSize} bytes.", nameof(signature));
        if (revealedIndices.Count == 0)
            throw new ArgumentException("At least one revealed index is required.", nameof(revealedIndices));

        var encodedMessages = ZkryptiumNative.EncodeMessages(messages);
        var encodedIndices = ZkryptiumNative.EncodeIndices(revealedIndices);
        var proofBuf = new byte[MaxProofSize];

        var rc = ZkryptiumNative.bbs_proof_gen(
            publicKey,
            signature,
            ReadOnlySpan<byte>.Empty, 0,
            nonce, (nuint)nonce.Length,
            encodedMessages, (nuint)encodedMessages.Length,
            encodedIndices, (nuint)encodedIndices.Length,
            proofBuf, (nuint)proofBuf.Length,
            out var proofLen);

        if (rc != 0)
            throw new CryptographicException("BBS+ proof generation failed.");

        return proofBuf.AsSpan(0, (int)proofLen).ToArray();
    }

    public bool VerifyProof(
        ReadOnlySpan<byte> publicKey,
        byte[] proof,
        IReadOnlyList<byte[]> revealedMessages,
        IReadOnlyList<int> revealedIndices,
        int totalMessageCount,
        ReadOnlySpan<byte> nonce)
    {
        if (publicKey.Length != PublicKeySize)
            throw new ArgumentException($"BBS+ public key must be {PublicKeySize} bytes.", nameof(publicKey));

        var encodedMessages = ZkryptiumNative.EncodeMessages(revealedMessages);
        var encodedIndices = ZkryptiumNative.EncodeIndices(revealedIndices);

        var rc = ZkryptiumNative.bbs_proof_verify(
            publicKey,
            proof, (nuint)proof.Length,
            ReadOnlySpan<byte>.Empty, 0,
            nonce, (nuint)nonce.Length,
            encodedMessages, (nuint)encodedMessages.Length,
            encodedIndices, (nuint)encodedIndices.Length);

        return rc == 0;
    }
}
