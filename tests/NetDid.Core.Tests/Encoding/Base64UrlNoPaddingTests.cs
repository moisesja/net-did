using FluentAssertions;
using NetDid.Core.Encoding;

namespace NetDid.Core.Tests.Encoding;

public class Base64UrlNoPaddingTests
{
    [Fact]
    public void RoundTrip_PreservesData()
    {
        var data = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05 };
        var encoded = Base64UrlNoPadding.Encode(data);
        var decoded = Base64UrlNoPadding.Decode(encoded);
        decoded.Should().Equal(data);
    }

    [Fact]
    public void Encode_NoPaddingCharacters()
    {
        var data = new byte[] { 0x01 };
        var encoded = Base64UrlNoPadding.Encode(data);
        encoded.Should().NotContain("=");
    }

    [Fact]
    public void Encode_UrlSafeCharacters()
    {
        // Use bytes that would produce + and / in standard base64
        var data = new byte[] { 0xfb, 0xef, 0xbe };
        var encoded = Base64UrlNoPadding.Encode(data);
        encoded.Should().NotContain("+");
        encoded.Should().NotContain("/");
    }

    [Fact]
    public void RoundTrip_32Bytes_PreservesData()
    {
        var data = new byte[32];
        Random.Shared.NextBytes(data);
        var encoded = Base64UrlNoPadding.Encode(data);
        var decoded = Base64UrlNoPadding.Decode(encoded);
        decoded.Should().Equal(data);
    }
}
