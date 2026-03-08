using FluentAssertions;
using NetCid;
using NetDid.Core.Crypto;

namespace NetDid.Core.Tests.Encoding;

public class MulticodecKeyTypeTests
{
    [Theory]
    [InlineData(KeyType.Ed25519)]
    [InlineData(KeyType.X25519)]
    [InlineData(KeyType.P256)]
    [InlineData(KeyType.P384)]
    [InlineData(KeyType.Secp256k1)]
    [InlineData(KeyType.Bls12381G1)]
    [InlineData(KeyType.Bls12381G2)]
    public void RoundTrip_AllKeyTypes_PreservesData(KeyType keyType)
    {
        var rawKey = new byte[32];
        Random.Shared.NextBytes(rawKey);

        var prefixed = Multicodec.Prefix(keyType.GetMulticodec(), rawKey);
        var (codec, decodedKey) = Multicodec.Decode(prefixed);
        var decodedType = KeyTypeExtensions.ToKeyType(codec);

        decodedType.Should().Be(keyType);
        decodedKey.Should().Equal(rawKey);
    }

    [Fact]
    public void Prefix_Ed25519_StartsWithCorrectVarintBytes()
    {
        var rawKey = new byte[32];
        var prefixed = Multicodec.Prefix(Multicodec.Ed25519Pub, rawKey);

        // Ed25519 multicodec = 0xed, varint = [0xed, 0x01]
        prefixed[0].Should().Be(0xed);
        prefixed[1].Should().Be(0x01);
        prefixed.Length.Should().Be(34); // 2 varint bytes + 32 key bytes
    }

    [Fact]
    public void Prefix_P256_StartsWithCorrectVarintBytes()
    {
        var rawKey = new byte[65]; // uncompressed point
        var prefixed = Multicodec.Prefix(Multicodec.P256Pub, rawKey);

        // P-256 multicodec = 0x1200, varint = [0x80, 0x24]
        prefixed[0].Should().Be(0x80);
        prefixed[1].Should().Be(0x24);
    }

    [Fact]
    public void ToKeyType_UnknownCodec_ThrowsArgumentException()
    {
        var act = () => KeyTypeExtensions.ToKeyType(0xFFFF);
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void GetMulticodec_AllKeyTypes_ReturnExpectedConstants()
    {
        KeyType.Ed25519.GetMulticodec().Should().Be(Multicodec.Ed25519Pub);
        KeyType.X25519.GetMulticodec().Should().Be(Multicodec.X25519Pub);
        KeyType.P256.GetMulticodec().Should().Be(Multicodec.P256Pub);
        KeyType.P384.GetMulticodec().Should().Be(Multicodec.P384Pub);
        KeyType.Secp256k1.GetMulticodec().Should().Be(Multicodec.Secp256k1Pub);
        KeyType.Bls12381G1.GetMulticodec().Should().Be(Multicodec.Bls12381G1Pub);
        KeyType.Bls12381G2.GetMulticodec().Should().Be(Multicodec.Bls12381G2Pub);
    }
}
