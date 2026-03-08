using FluentAssertions;
using NetCid;

namespace NetDid.Core.Tests.Encoding;

public class MultibaseTests
{
    [Fact]
    public void Encode_Base58Btc_StartsWithZ()
    {
        var data = new byte[] { 0x01, 0x02, 0x03 };
        var encoded = Multibase.Encode(data, MultibaseEncoding.Base58Btc);
        encoded.Should().StartWith("z");
    }

    [Fact]
    public void Encode_Base64Url_StartsWithU()
    {
        var data = new byte[] { 0x01, 0x02, 0x03 };
        var encoded = Multibase.Encode(data, MultibaseEncoding.Base64Url);
        encoded.Should().StartWith("u");
    }

    [Fact]
    public void Encode_Base32Lower_StartsWithB()
    {
        var data = new byte[] { 0x01, 0x02, 0x03 };
        var encoded = Multibase.Encode(data, MultibaseEncoding.Base32Lower);
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

        var encoded = Multibase.Encode(data, encoding);
        var decoded = Multibase.Decode(encoded);
        decoded.Should().Equal(data);
    }

    [Fact]
    public void Encode_Base64Url_NoPrefixMode_ProducesRawPayload()
    {
        var data = new byte[] { 0x01, 0x02, 0x03 };
        var encoded = Multibase.Encode(data, MultibaseEncoding.Base64Url, includePrefix: false);
        encoded.Should().NotStartWith("u");
        // Verify round-trip: prepend prefix then decode
        var decoded = Multibase.Decode("u" + encoded);
        decoded.Should().Equal(data);
    }
}
