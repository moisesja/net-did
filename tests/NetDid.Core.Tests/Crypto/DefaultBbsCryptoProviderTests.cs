using System.Security.Cryptography;
using FluentAssertions;
using NetDid.Core.Crypto;
using NetDid.Core.Crypto.Native;

namespace NetDid.Core.Tests.Crypto;

public class DefaultBbsCryptoProviderTests
{
    private readonly DefaultBbsCryptoProvider _bbs = new();

    /// <summary>
    /// Generate a BBS+ keypair via the native FFI layer.
    /// Returns (secretKey: 32 bytes, publicKey: 96 bytes).
    /// </summary>
    private static (byte[] sk, byte[] pk) GenerateBbsKeyPair()
    {
        var ikm = new byte[32];
        RandomNumberGenerator.Fill(ikm);

        var sk = new byte[32];
        var pk = new byte[96];
        var rc = ZkryptiumNative.bbs_keygen(ikm, (nuint)ikm.Length, sk, pk);
        if (rc != 0)
            throw new CryptographicException("BBS+ key generation failed in test setup.");
        return (sk, pk);
    }

    // --- Sign / Verify ---

    [Fact]
    public void SignVerify_SingleMessage_RoundTrip()
    {
        var (sk, pk) = GenerateBbsKeyPair();
        var messages = new List<byte[]> { "Hello, BBS+"u8.ToArray() };

        var signature = _bbs.Sign(sk, messages);
        var valid = _bbs.Verify(pk, signature, messages);

        signature.Should().HaveCount(80);
        valid.Should().BeTrue();
    }

    [Fact]
    public void SignVerify_MultipleMessages_RoundTrip()
    {
        var (sk, pk) = GenerateBbsKeyPair();
        var messages = new List<byte[]>
        {
            "name: Alice"u8.ToArray(),
            "age: 30"u8.ToArray(),
            "email: alice@example.com"u8.ToArray()
        };

        var signature = _bbs.Sign(sk, messages);
        var valid = _bbs.Verify(pk, signature, messages);

        signature.Should().HaveCount(80);
        valid.Should().BeTrue();
    }

    [Fact]
    public void Verify_WrongMessage_ReturnsFalse()
    {
        var (sk, pk) = GenerateBbsKeyPair();
        var messages = new List<byte[]> { "correct"u8.ToArray() };
        var wrongMessages = new List<byte[]> { "wrong"u8.ToArray() };

        var signature = _bbs.Sign(sk, messages);
        var valid = _bbs.Verify(pk, signature, wrongMessages);

        valid.Should().BeFalse();
    }

    [Fact]
    public void Verify_WrongKey_ReturnsFalse()
    {
        var (sk1, _) = GenerateBbsKeyPair();
        var (_, pk2) = GenerateBbsKeyPair();
        var messages = new List<byte[]> { "test"u8.ToArray() };

        var signature = _bbs.Sign(sk1, messages);
        var valid = _bbs.Verify(pk2, signature, messages);

        valid.Should().BeFalse();
    }

    [Fact]
    public void Verify_TamperedSignature_ReturnsFalse()
    {
        var (sk, pk) = GenerateBbsKeyPair();
        var messages = new List<byte[]> { "test"u8.ToArray() };

        var signature = _bbs.Sign(sk, messages);
        signature[0] ^= 0xFF; // flip bits
        var valid = _bbs.Verify(pk, signature, messages);

        valid.Should().BeFalse();
    }

    // --- Selective Disclosure Proofs ---

    [Fact]
    public void DeriveProof_VerifyProof_RoundTrip()
    {
        var (sk, pk) = GenerateBbsKeyPair();
        var messages = new List<byte[]>
        {
            "name: Alice"u8.ToArray(),
            "age: 30"u8.ToArray(),
            "email: alice@example.com"u8.ToArray()
        };

        var signature = _bbs.Sign(sk, messages);

        // Disclose only message 0 (name) and 2 (email)
        var revealedIndices = new List<int> { 0, 2 };
        var nonce = "verifier-challenge"u8.ToArray();

        var proof = _bbs.DeriveProof(pk, signature, messages, revealedIndices, nonce);
        proof.Should().NotBeEmpty();

        // Verify with only the disclosed messages
        var revealedMessages = new List<byte[]>
        {
            messages[0],
            messages[2]
        };
        var valid = _bbs.VerifyProof(pk, proof, revealedMessages, revealedIndices, messages.Count, nonce);
        valid.Should().BeTrue();
    }

    [Fact]
    public void VerifyProof_WrongNonce_ReturnsFalse()
    {
        var (sk, pk) = GenerateBbsKeyPair();
        var messages = new List<byte[]>
        {
            "msg1"u8.ToArray(),
            "msg2"u8.ToArray()
        };

        var signature = _bbs.Sign(sk, messages);
        var revealedIndices = new List<int> { 0 };
        var nonce = "nonce1"u8.ToArray();

        var proof = _bbs.DeriveProof(pk, signature, messages, revealedIndices, nonce);

        var wrongNonce = "nonce2"u8.ToArray();
        var revealedMessages = new List<byte[]> { messages[0] };
        var valid = _bbs.VerifyProof(pk, proof, revealedMessages, revealedIndices, messages.Count, wrongNonce);
        valid.Should().BeFalse();
    }

    [Fact]
    public void VerifyProof_WrongDisclosedMessage_ReturnsFalse()
    {
        var (sk, pk) = GenerateBbsKeyPair();
        var messages = new List<byte[]>
        {
            "real-name"u8.ToArray(),
            "real-age"u8.ToArray()
        };

        var signature = _bbs.Sign(sk, messages);
        var revealedIndices = new List<int> { 0 };
        var nonce = "nonce"u8.ToArray();

        var proof = _bbs.DeriveProof(pk, signature, messages, revealedIndices, nonce);

        // Try to verify with a different message at the disclosed index
        var fakeMessages = new List<byte[]> { "fake-name"u8.ToArray() };
        var valid = _bbs.VerifyProof(pk, proof, fakeMessages, revealedIndices, messages.Count, nonce);
        valid.Should().BeFalse();
    }

    [Fact]
    public void DeriveProof_DiscloseAllMessages_VerifiesSuccessfully()
    {
        var (sk, pk) = GenerateBbsKeyPair();
        var messages = new List<byte[]>
        {
            "a"u8.ToArray(),
            "b"u8.ToArray(),
            "c"u8.ToArray()
        };

        var signature = _bbs.Sign(sk, messages);
        var allIndices = new List<int> { 0, 1, 2 };
        var nonce = "nonce"u8.ToArray();

        var proof = _bbs.DeriveProof(pk, signature, messages, allIndices, nonce);
        var valid = _bbs.VerifyProof(pk, proof, messages, allIndices, messages.Count, nonce);
        valid.Should().BeTrue();
    }

    // --- Edge cases ---

    [Fact]
    public void Sign_EmptyMessages_ThrowsArgumentException()
    {
        var (sk, _) = GenerateBbsKeyPair();
        var act = () => _bbs.Sign(sk, new List<byte[]>());
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Sign_WrongKeySize_ThrowsArgumentException()
    {
        var act = () => _bbs.Sign(new byte[16], new List<byte[]> { "x"u8.ToArray() });
        act.Should().Throw<ArgumentException>();
    }
}
