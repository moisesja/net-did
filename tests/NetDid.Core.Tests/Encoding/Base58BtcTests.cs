using FluentAssertions;
using NetDid.Core.Encoding;

namespace NetDid.Core.Tests.Encoding;

public class Base58BtcTests
{
    [Fact]
    public void RoundTrip_PreservesData()
    {
        var data = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05 };
        var encoded = Base58Btc.Encode(data);
        var decoded = Base58Btc.Decode(encoded);

        decoded.Should().Equal(data);
    }

    [Fact]
    public void Encode_KnownVector_ProducesExpectedOutput()
    {
        // "Hello World" in Base58 Bitcoin
        var data = System.Text.Encoding.UTF8.GetBytes("Hello World");
        var encoded = Base58Btc.Encode(data);
        encoded.Should().Be("JxF12TrwUP45BMd");
    }

    [Fact]
    public void RoundTrip_EmptyData_ReturnsEmpty()
    {
        var data = Array.Empty<byte>();
        var encoded = Base58Btc.Encode(data);
        var decoded = Base58Btc.Decode(encoded);
        decoded.Should().BeEmpty();
    }

    [Fact]
    public void RoundTrip_LeadingZeros_PreservesZeros()
    {
        var data = new byte[] { 0x00, 0x00, 0x01 };
        var encoded = Base58Btc.Encode(data);
        var decoded = Base58Btc.Decode(encoded);
        decoded.Should().Equal(data);
    }

    [Fact]
    public void RoundTrip_RandomData_PreservesData()
    {
        var data = new byte[32];
        Random.Shared.NextBytes(data);
        var encoded = Base58Btc.Encode(data);
        var decoded = Base58Btc.Decode(encoded);
        decoded.Should().Equal(data);
    }
}
