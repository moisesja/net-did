using FluentAssertions;
using NetDid.Core.Crypto;
using NetDid.Core.Encoding;

namespace NetDid.Core.Tests.Encoding;

public class MulticodecEncoderTests
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

        var prefixed = MulticodecEncoder.Prefix(keyType, rawKey);
        var (decodedType, decodedKey) = MulticodecEncoder.Decode(prefixed);

        decodedType.Should().Be(keyType);
        decodedKey.Should().Equal(rawKey);
    }

    [Fact]
    public void Prefix_Ed25519_StartsWithCorrectVarintBytes()
    {
        var rawKey = new byte[32];
        var prefixed = MulticodecEncoder.Prefix(KeyType.Ed25519, rawKey);

        // Ed25519 multicodec = 0xed, varint = [0xed, 0x01]
        prefixed[0].Should().Be(0xed);
        prefixed[1].Should().Be(0x01);
        prefixed.Length.Should().Be(34); // 2 varint bytes + 32 key bytes
    }

    [Fact]
    public void Prefix_P256_StartsWithCorrectVarintBytes()
    {
        var rawKey = new byte[65]; // uncompressed point
        var prefixed = MulticodecEncoder.Prefix(KeyType.P256, rawKey);

        // P-256 multicodec = 0x1200, varint = [0x80, 0x24]
        prefixed[0].Should().Be(0x80);
        prefixed[1].Should().Be(0x24);
    }

    [Fact]
    public void Decode_UnknownPrefix_ThrowsArgumentException()
    {
        var data = new byte[] { 0xFF, 0xFF, 0x01, 0x02, 0x03 };
        var act = () => MulticodecEncoder.Decode(data);
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void EncodeVarint_SmallValue_SingleByte()
    {
        var varint = MulticodecEncoder.EncodeVarint(0x01);
        varint.Should().Equal(new byte[] { 0x01 });
    }

    [Fact]
    public void EncodeVarint_LargeValue_MultipleBytes()
    {
        // 0x1200 = 4608 decimal = varint bytes [0x80, 0x24]
        var varint = MulticodecEncoder.EncodeVarint(0x1200);
        varint.Should().Equal(new byte[] { 0x80, 0x24 });
    }

    [Fact]
    public void DecodeVarint_RoundTrip()
    {
        var originalValue = 0xed; // 237
        var encoded = MulticodecEncoder.EncodeVarint(originalValue);
        var (decoded, bytesRead) = MulticodecEncoder.DecodeVarint(encoded);

        decoded.Should().Be(originalValue);
        bytesRead.Should().Be(encoded.Length);
    }
}
