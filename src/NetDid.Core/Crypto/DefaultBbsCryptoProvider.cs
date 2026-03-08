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

    // BLS12-381-SHA-256 proof size formula (IETF draft-10):
    //   proof_len = 3 * point_len + scalar_len * (undisclosed + 1)
    //   where point_len = 48, scalar_len = 32
    private const int ProofPointOverhead = 3 * 48;   // 144
    private const int ProofScalarSize = 32;

    private static readonly bool NativeAvailable;
    private static readonly Exception? NativeLoadError;

    static DefaultBbsCryptoProvider()
    {
        try
        {
            // Probe for the native library by calling a trivial function.
            // bbs_sk_to_pk with empty input will return -1 (error) but that's fine —
            // we only care that the DLL loaded.
            ZkryptiumNative.bbs_sk_to_pk(ReadOnlySpan<byte>.Empty, Span<byte>.Empty);
            NativeAvailable = true;
        }
        catch (DllNotFoundException ex)
        {
            NativeAvailable = false;
            NativeLoadError = ex;
        }
        catch
        {
            // Any other exception means the library loaded but the call failed, which is fine.
            NativeAvailable = true;
        }
    }

    private static void EnsureNativeAvailable()
    {
        if (!NativeAvailable)
            throw new PlatformNotSupportedException(
                "BBS+ native library (zkryptium_ffi) not found for this platform. " +
                "Pre-built binaries are included for osx-arm64 only. " +
                "See native/zkryptium-ffi/README.md for build instructions for other platforms.",
                NativeLoadError);
    }

    public byte[] Sign(ReadOnlySpan<byte> privateKey, IReadOnlyList<byte[]> messages)
    {
        EnsureNativeAvailable();

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
        EnsureNativeAvailable();

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
        EnsureNativeAvailable();

        if (publicKey.Length != PublicKeySize)
            throw new ArgumentException($"BBS+ public key must be {PublicKeySize} bytes.", nameof(publicKey));
        if (signature.Length != SignatureSize)
            throw new ArgumentException($"BBS+ signature must be {SignatureSize} bytes.", nameof(signature));
        if (revealedIndices.Count == 0)
            throw new ArgumentException("At least one revealed index is required.", nameof(revealedIndices));

        var encodedMessages = ZkryptiumNative.EncodeMessages(messages);
        var encodedIndices = ZkryptiumNative.EncodeIndices(revealedIndices);

        // Compute exact proof buffer size from the BLS12-381-SHA-256 formula
        var undisclosed = messages.Count - revealedIndices.Count;
        var proofBufSize = ProofPointOverhead + ProofScalarSize * (undisclosed + 1);
        var proofBuf = new byte[Math.Max(proofBufSize, 512)];

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
        ReadOnlySpan<byte> nonce)
    {
        EnsureNativeAvailable();

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
