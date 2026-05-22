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
    public void SignVerify_P521_RoundTrip()
    {
        var keyPair = _keyGen.Generate(KeyType.P521);
        var data = "Hello, P-521!"u8.ToArray();

        var signature = _crypto.Sign(KeyType.P521, keyPair.PrivateKey, data);
        var valid = _crypto.Verify(KeyType.P521, keyPair.PublicKey, data, signature);

        valid.Should().BeTrue();
        keyPair.PublicKey.Length.Should().Be(67); // 1 prefix byte + 66 coordinate bytes
    }

    [Fact]
    public void SignVerify_P521_WrongKey_ReturnsFalse()
    {
        var keyPair = _keyGen.Generate(KeyType.P521);
        var otherKey = _keyGen.Generate(KeyType.P521);
        var data = "Hello, P-521!"u8.ToArray();

        var signature = _crypto.Sign(KeyType.P521, keyPair.PrivateKey, data);
        var valid = _crypto.Verify(KeyType.P521, otherKey.PublicKey, data, signature);

        valid.Should().BeFalse();
    }

    [Fact]
    public void SignVerify_P521_RestoredKey_Works()
    {
        var keyPair = _keyGen.Generate(KeyType.P521);
        var restored = _keyGen.FromPrivateKey(KeyType.P521, keyPair.PrivateKey);
        var data = "Restored P-521 key"u8.ToArray();

        var signature = _crypto.Sign(KeyType.P521, restored.PrivateKey, data);
        var valid = _crypto.Verify(KeyType.P521, restored.PublicKey, data, signature);

        valid.Should().BeTrue();
        restored.PublicKey.Should().Equal(keyPair.PublicKey);
    }

    [Fact]
    public void DeriveSharedSecret_P521_AliceBobAgree()
    {
        var alice = _keyGen.Generate(KeyType.P521);
        var bob = _keyGen.Generate(KeyType.P521);

        var aliceShared = _crypto.DeriveSharedSecret(KeyType.P521, alice.PrivateKey, bob.PublicKey);
        var bobShared = _crypto.DeriveSharedSecret(KeyType.P521, bob.PrivateKey, alice.PublicKey);

        aliceShared.Should().HaveCount(66);
        aliceShared.Should().Equal(bobShared);
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

    // --- DeriveSharedSecret (raw ECDH "Z") — Issue #60 ---

    [Fact]
    public void DeriveSharedSecret_X25519_MatchesRfc7748TestVector()
    {
        // RFC 7748 §6.1 — X25519 Diffie-Hellman test vector.
        var alicePrivate = Convert.FromHexString("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        var bobPublic = Convert.FromHexString("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        var expectedShared = Convert.FromHexString("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

        var shared = _crypto.DeriveSharedSecret(KeyType.X25519, alicePrivate, bobPublic);

        shared.Should().Equal(expectedShared);
    }

    [Fact]
    public void DeriveSharedSecret_X25519_AliceBobAgree()
    {
        var alice = _keyGen.Generate(KeyType.X25519);
        var bob = _keyGen.Generate(KeyType.X25519);

        var aliceShared = _crypto.DeriveSharedSecret(KeyType.X25519, alice.PrivateKey, bob.PublicKey);
        var bobShared = _crypto.DeriveSharedSecret(KeyType.X25519, bob.PrivateKey, alice.PublicKey);

        aliceShared.Should().HaveCount(32);
        aliceShared.Should().Equal(bobShared);
    }

    [Fact]
    public void DeriveSharedSecret_P256_AliceBobAgree()
    {
        var alice = _keyGen.Generate(KeyType.P256);
        var bob = _keyGen.Generate(KeyType.P256);

        var aliceShared = _crypto.DeriveSharedSecret(KeyType.P256, alice.PrivateKey, bob.PublicKey);
        var bobShared = _crypto.DeriveSharedSecret(KeyType.P256, bob.PrivateKey, alice.PublicKey);

        aliceShared.Should().HaveCount(32);
        aliceShared.Should().Equal(bobShared);
    }

    [Fact]
    public void DeriveSharedSecret_P256_MatchesRfc5903KAT()
    {
        // RFC 5903 §8.1 — ECP-256 ECDH known-answer test.
        // Initiator private "i" and responder public point (gr_x, gr_y); expected raw Z.
        var iPrivate = Convert.FromHexString("C88F01F510D9AC3F70A292DAA2316DE544E9AAB8AFE84049C62A9C57862D1433");
        var grX = Convert.FromHexString("D12DFB5289C8D4F81208B70270398C342296970A0BCCB74C736FC7554494BF63");
        var grY = Convert.FromHexString("56FBF3CA366CC23E8157854C13C58D6AAC23F046ADA30F8353E74F33039872AB");
        var expectedZ = Convert.FromHexString("D6840F6B42F6EDAFD13116E0E12565202FEF8E9ECE7DCE03812464D04B9442DE");

        // Build SEC1 uncompressed public key 0x04 || X || Y.
        var grPublic = new byte[1 + grX.Length + grY.Length];
        grPublic[0] = 0x04;
        Buffer.BlockCopy(grX, 0, grPublic, 1, grX.Length);
        Buffer.BlockCopy(grY, 0, grPublic, 1 + grX.Length, grY.Length);

        var z = _crypto.DeriveSharedSecret(KeyType.P256, iPrivate, grPublic);

        z.Should().Equal(expectedZ);
    }

    [Fact]
    public void DeriveSharedSecret_P384_MatchesRfc5903KAT()
    {
        // RFC 5903 §8.2 — ECP-384 ECDH known-answer test.
        var iPrivate = Convert.FromHexString(
            "099F3C7034D4A2C699884D73A375A67F7624EF7C6B3C0F160647B67414DCE655E35B538041E649EE3FAEF896783AB194");
        var grX = Convert.FromHexString(
            "E558DBEF53EECDE3D3FCCFC1AEA08A89A987475D12FD950D83CFA41732BC509D0D1AC43A0336DEF96FDA41D0774A3571");
        var grY = Convert.FromHexString(
            "DCFBEC7AACF3196472169E838430367F66EEBE3C6E70C416DD5F0C68759DD1FFF83FA40142209DFF5EAAD96DB9E6386C");
        var expectedZ = Convert.FromHexString(
            "11187331C279962D93D604243FD592CB9D0A926F422E47187521287E7156C5C4D603135569B9E9D09CF5D4A270F59746");

        var grPublic = new byte[1 + grX.Length + grY.Length];
        grPublic[0] = 0x04;
        Buffer.BlockCopy(grX, 0, grPublic, 1, grX.Length);
        Buffer.BlockCopy(grY, 0, grPublic, 1 + grX.Length, grY.Length);

        var z = _crypto.DeriveSharedSecret(KeyType.P384, iPrivate, grPublic);

        z.Should().Equal(expectedZ);
    }

    [Fact]
    public void DeriveSharedSecret_P384_AliceBobAgree()
    {
        var alice = _keyGen.Generate(KeyType.P384);
        var bob = _keyGen.Generate(KeyType.P384);

        var aliceShared = _crypto.DeriveSharedSecret(KeyType.P384, alice.PrivateKey, bob.PublicKey);
        var bobShared = _crypto.DeriveSharedSecret(KeyType.P384, bob.PrivateKey, alice.PublicKey);

        aliceShared.Should().HaveCount(48);
        aliceShared.Should().Equal(bobShared);
    }

    [Fact]
    public void DeriveSharedSecret_P256_AcceptsUncompressedPublicKey()
    {
        var alice = _keyGen.Generate(KeyType.P256);
        var bob = _keyGen.Generate(KeyType.P256);

        // Decompress Bob's public key to uncompressed SEC1 form (0x04 || X || Y).
        using var ecdsa = System.Security.Cryptography.ECDsa.Create();
        ecdsa.ImportParameters(DefaultCryptoProvider.DecompressEcPoint(bob.PublicKey, System.Security.Cryptography.ECCurve.NamedCurves.nistP256));
        var p = ecdsa.ExportParameters(false);
        var uncompressed = new byte[1 + p.Q.X!.Length + p.Q.Y!.Length];
        uncompressed[0] = 0x04;
        p.Q.X.CopyTo(uncompressed, 1);
        p.Q.Y.CopyTo(uncompressed, 1 + p.Q.X.Length);

        var fromCompressed = _crypto.DeriveSharedSecret(KeyType.P256, alice.PrivateKey, bob.PublicKey);
        var fromUncompressed = _crypto.DeriveSharedSecret(KeyType.P256, alice.PrivateKey, uncompressed);

        fromCompressed.Should().Equal(fromUncompressed);
    }

    [Theory]
    [InlineData(KeyType.Ed25519)]
    [InlineData(KeyType.Secp256k1)]
    [InlineData(KeyType.Bls12381G1)]
    [InlineData(KeyType.Bls12381G2)]
    public void DeriveSharedSecret_NonEcdhKeyType_Throws(KeyType keyType)
    {
        var dummy = new byte[32];
        var act = () => _crypto.DeriveSharedSecret(keyType, dummy, dummy);
        act.Should().Throw<ArgumentException>();
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
