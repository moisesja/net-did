using FluentAssertions;
using NetDid.Core.Crypto;

namespace NetDid.Core.Tests.Crypto;

public class DefaultCryptoProviderTests
{
    private readonly DefaultCryptoProvider _crypto = new();
    private readonly DefaultKeyGenerator _keyGen = new();

    [Fact]
    public void SignVerify_Ed25519_RoundTrip()
    {
        var keyPair = _keyGen.Generate(KeyType.Ed25519);
        var data = "Hello, World!"u8.ToArray();

        var signature = _crypto.Sign(KeyType.Ed25519, keyPair.PrivateKey, data);
        var valid = _crypto.Verify(KeyType.Ed25519, keyPair.PublicKey, data, signature);

        signature.Should().HaveCount(64);
        valid.Should().BeTrue();
    }

    [Fact]
    public void Verify_Ed25519_WrongData_ReturnsFalse()
    {
        var keyPair = _keyGen.Generate(KeyType.Ed25519);
        var data = "Hello"u8.ToArray();
        var wrongData = "Wrong"u8.ToArray();

        var signature = _crypto.Sign(KeyType.Ed25519, keyPair.PrivateKey, data);
        var valid = _crypto.Verify(KeyType.Ed25519, keyPair.PublicKey, wrongData, signature);

        valid.Should().BeFalse();
    }

    [Fact]
    public void Verify_Ed25519_WrongKey_ReturnsFalse()
    {
        var keyPair = _keyGen.Generate(KeyType.Ed25519);
        var otherKey = _keyGen.Generate(KeyType.Ed25519);
        var data = "Hello"u8.ToArray();

        var signature = _crypto.Sign(KeyType.Ed25519, keyPair.PrivateKey, data);
        var valid = _crypto.Verify(KeyType.Ed25519, otherKey.PublicKey, data, signature);

        valid.Should().BeFalse();
    }

    [Fact]
    public void SignVerify_P256_RoundTrip()
    {
        var keyPair = _keyGen.Generate(KeyType.P256);
        var data = "Hello, P-256!"u8.ToArray();

        var signature = _crypto.Sign(KeyType.P256, keyPair.PrivateKey, data);
        var valid = _crypto.Verify(KeyType.P256, keyPair.PublicKey, data, signature);

        valid.Should().BeTrue();
    }

    [Fact]
    public void SignVerify_P384_RoundTrip()
    {
        var keyPair = _keyGen.Generate(KeyType.P384);
        var data = "Hello, P-384!"u8.ToArray();

        var signature = _crypto.Sign(KeyType.P384, keyPair.PrivateKey, data);
        var valid = _crypto.Verify(KeyType.P384, keyPair.PublicKey, data, signature);

        valid.Should().BeTrue();
    }

    [Fact]
    public void SignVerify_Secp256k1_RoundTrip()
    {
        var keyPair = _keyGen.Generate(KeyType.Secp256k1);
        var data = "Hello, secp256k1!"u8.ToArray();

        var signature = _crypto.Sign(KeyType.Secp256k1, keyPair.PrivateKey, data);
        var valid = _crypto.Verify(KeyType.Secp256k1, keyPair.PublicKey, data, signature);

        signature.Should().HaveCount(64); // compact format
        valid.Should().BeTrue();
    }

    [Fact]
    public void Sign_X25519_ThrowsArgumentException()
    {
        var keyPair = _keyGen.Generate(KeyType.X25519);
        var data = "Hello"u8.ToArray();

        var act = () => _crypto.Sign(KeyType.X25519, keyPair.PrivateKey, data);
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void KeyAgreement_X25519_ProducesSharedSecret()
    {
        var aliceKey = _keyGen.Generate(KeyType.X25519);
        var bobKey = _keyGen.Generate(KeyType.X25519);

        var aliceShared = _crypto.KeyAgreement(aliceKey.PrivateKey, bobKey.PublicKey);
        var bobShared = _crypto.KeyAgreement(bobKey.PrivateKey, aliceKey.PublicKey);

        aliceShared.Should().NotBeEmpty();
        bobShared.Should().NotBeEmpty();
        aliceShared.Should().Equal(bobShared);
    }

    // --- BLS12-381 G1 (pubkey in G1, signature in G2) ---

    [Fact]
    public void SignVerify_Bls12381G1_RoundTrip()
    {
        var keyPair = _keyGen.Generate(KeyType.Bls12381G1);
        var data = "Hello, BLS G1!"u8.ToArray();

        var signature = _crypto.Sign(KeyType.Bls12381G1, keyPair.PrivateKey, data);
        var valid = _crypto.Verify(KeyType.Bls12381G1, keyPair.PublicKey, data, signature);

        signature.Should().HaveCount(96); // G2 signature compressed
        valid.Should().BeTrue();
    }

    [Fact]
    public void Verify_Bls12381G1_WrongData_ReturnsFalse()
    {
        var keyPair = _keyGen.Generate(KeyType.Bls12381G1);
        var data = "Hello"u8.ToArray();
        var wrongData = "Wrong"u8.ToArray();

        var signature = _crypto.Sign(KeyType.Bls12381G1, keyPair.PrivateKey, data);
        var valid = _crypto.Verify(KeyType.Bls12381G1, keyPair.PublicKey, wrongData, signature);

        valid.Should().BeFalse();
    }

    [Fact]
    public void Verify_Bls12381G1_WrongKey_ReturnsFalse()
    {
        var keyPair = _keyGen.Generate(KeyType.Bls12381G1);
        var otherKey = _keyGen.Generate(KeyType.Bls12381G1);
        var data = "Hello"u8.ToArray();

        var signature = _crypto.Sign(KeyType.Bls12381G1, keyPair.PrivateKey, data);
        var valid = _crypto.Verify(KeyType.Bls12381G1, otherKey.PublicKey, data, signature);

        valid.Should().BeFalse();
    }

    [Fact]
    public void SignVerify_Bls12381G1_RestoredKey_Works()
    {
        var keyPair = _keyGen.Generate(KeyType.Bls12381G1);
        var restored = _keyGen.FromPrivateKey(KeyType.Bls12381G1, keyPair.PrivateKey);
        var data = "Restored key test"u8.ToArray();

        var signature = _crypto.Sign(KeyType.Bls12381G1, restored.PrivateKey, data);
        var valid = _crypto.Verify(KeyType.Bls12381G1, restored.PublicKey, data, signature);

        valid.Should().BeTrue();
    }

    // --- BLS12-381 G2 (pubkey in G2, signature in G1) ---

    [Fact]
    public void SignVerify_Bls12381G2_RoundTrip()
    {
        var keyPair = _keyGen.Generate(KeyType.Bls12381G2);
        var data = "Hello, BLS G2!"u8.ToArray();

        var signature = _crypto.Sign(KeyType.Bls12381G2, keyPair.PrivateKey, data);
        var valid = _crypto.Verify(KeyType.Bls12381G2, keyPair.PublicKey, data, signature);

        signature.Should().HaveCount(48); // G1 signature compressed
        valid.Should().BeTrue();
    }

    [Fact]
    public void Verify_Bls12381G2_WrongData_ReturnsFalse()
    {
        var keyPair = _keyGen.Generate(KeyType.Bls12381G2);
        var data = "Hello"u8.ToArray();
        var wrongData = "Wrong"u8.ToArray();

        var signature = _crypto.Sign(KeyType.Bls12381G2, keyPair.PrivateKey, data);
        var valid = _crypto.Verify(KeyType.Bls12381G2, keyPair.PublicKey, wrongData, signature);

        valid.Should().BeFalse();
    }

    [Fact]
    public void Verify_Bls12381G2_WrongKey_ReturnsFalse()
    {
        var keyPair = _keyGen.Generate(KeyType.Bls12381G2);
        var otherKey = _keyGen.Generate(KeyType.Bls12381G2);
        var data = "Hello"u8.ToArray();

        var signature = _crypto.Sign(KeyType.Bls12381G2, keyPair.PrivateKey, data);
        var valid = _crypto.Verify(KeyType.Bls12381G2, otherKey.PublicKey, data, signature);

        valid.Should().BeFalse();
    }

    [Fact]
    public void SignVerify_Bls12381G2_RestoredKey_Works()
    {
        var keyPair = _keyGen.Generate(KeyType.Bls12381G2);
        var restored = _keyGen.FromPrivateKey(KeyType.Bls12381G2, keyPair.PrivateKey);
        var data = "Restored key test"u8.ToArray();

        var signature = _crypto.Sign(KeyType.Bls12381G2, restored.PrivateKey, data);
        var valid = _crypto.Verify(KeyType.Bls12381G2, restored.PublicKey, data, signature);

        valid.Should().BeTrue();
    }
}
