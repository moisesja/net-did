using FluentAssertions;
using NetDid.Core.Encoding;

namespace NetDid.Core.Tests.Encoding;

public class MultibaseEncoderTests
{
    [Fact]
    public void Encode_Base58Btc_StartsWithZ()
    {
        var data = new byte[] { 0x01, 0x02, 0x03 };
        var encoded = MultibaseEncoder.Encode(data, MultibaseEncoding.Base58Btc);
        encoded.Should().StartWith("z");
    }

    [Fact]
    public void Encode_Base64Url_StartsWithU()
    {
        var data = new byte[] { 0x01, 0x02, 0x03 };
        var encoded = MultibaseEncoder.Encode(data, MultibaseEncoding.Base64Url);
        encoded.Should().StartWith("u");
    }

    [Fact]
    public void Encode_Base32Lower_StartsWithB()
    {
        var data = new byte[] { 0x01, 0x02, 0x03 };
        var encoded = MultibaseEncoder.Encode(data, MultibaseEncoding.Base32Lower);
        encoded.Should().StartWith("b");
    }

    [Theory]
    [InlineData(MultibaseEncoding.Base58Btc)]
    [InlineData(MultibaseEncoding.Base64Url)]
    [InlineData(MultibaseEncoding.Base32Lower)]
    public void RoundTrip_AllEncodings_PreservesData(MultibaseEncoding encoding)
    {
        var data = new byte[32];
        Random.Shared.NextBytes(data);

        var encoded = MultibaseEncoder.Encode(data, encoding);
        var decoded = MultibaseEncoder.Decode(encoded);
        decoded.Should().Equal(data);
    }

    [Fact]
    public void Decode_DefaultEncoding_IsBase58Btc()
    {
        var data = new byte[] { 0x01, 0x02, 0x03 };
        var encoded = MultibaseEncoder.Encode(data);
        encoded.Should().StartWith("z");
    }

    [Fact]
    public void Decode_UnsupportedPrefix_ThrowsArgumentException()
    {
        var act = () => MultibaseEncoder.Decode("Xinvalid");
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Decode_Empty_ThrowsArgumentException()
    {
        var act = () => MultibaseEncoder.Decode("");
        act.Should().Throw<ArgumentException>();
    }
}
