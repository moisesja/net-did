using System.Numerics;
using System.Text;
using FluentAssertions;
using NetDid.Method.Ethr.Transactions;
using Xunit;

namespace NetDid.Method.Ethr.Tests;

/// <summary>
/// RLP encoder vectors. Every expected byte string below is an EXTERNAL oracle —
/// taken from the Ethereum Yellow Paper appendix B examples and the canonical
/// ethereum/tests RLP suite — never from this repo's own encoder (writer/reader
/// parity is not conformance).
/// </summary>
public class RlpEncoderTests
{
    private static string Hex(byte[] bytes) => Convert.ToHexString(bytes).ToLowerInvariant();

    // ── Byte strings ─────────────────────────────────────────────────────────

    [Fact]
    public void EncodeBytes_EmptyString_Is0x80()
        => Hex(RlpEncoder.EncodeBytes([])).Should().Be("80");

    [Fact]
    public void EncodeBytes_SingleByteBelow0x80_IsItself()
    {
        Hex(RlpEncoder.EncodeBytes([0x00])).Should().Be("00");
        Hex(RlpEncoder.EncodeBytes([0x0f])).Should().Be("0f");
        Hex(RlpEncoder.EncodeBytes([0x7f])).Should().Be("7f");
    }

    [Fact]
    public void EncodeBytes_SingleByte0x80_GetsLengthPrefix()
        => Hex(RlpEncoder.EncodeBytes([0x80])).Should().Be("8180");

    [Fact]
    public void EncodeBytes_Dog_Is0x83646f67()
        => Hex(RlpEncoder.EncodeBytes(Encoding.ASCII.GetBytes("dog"))).Should().Be("83646f67");

    [Fact]
    public void EncodeBytes_55ByteString_UsesShortForm()
    {
        // ethereum/tests: "Lorem ipsum dolor sit amet, consectetur adipisicing eli" (55 chars) → 0xb7 prefix
        var value = Encoding.ASCII.GetBytes("Lorem ipsum dolor sit amet, consectetur adipisicing eli");
        value.Should().HaveCount(55);
        var encoded = RlpEncoder.EncodeBytes(value);
        encoded[0].Should().Be(0xb7);
        encoded.Should().HaveCount(56);
    }

    [Fact]
    public void EncodeBytes_56ByteString_UsesLongForm()
    {
        // ethereum/tests: "Lorem ipsum dolor sit amet, consectetur adipisicing elit" (56 chars) → 0xb8 0x38 prefix
        var value = Encoding.ASCII.GetBytes("Lorem ipsum dolor sit amet, consectetur adipisicing elit");
        value.Should().HaveCount(56);
        var encoded = RlpEncoder.EncodeBytes(value);
        encoded[0].Should().Be(0xb8);
        encoded[1].Should().Be(0x38);
        encoded.Should().HaveCount(58);
    }

    // ── Integers ─────────────────────────────────────────────────────────────

    [Fact]
    public void EncodeUnsigned_Zero_IsEmptyString0x80()
        => Hex(RlpEncoder.EncodeUnsigned(0UL)).Should().Be("80");

    [Fact]
    public void EncodeUnsigned_15_Is0x0f()
        => Hex(RlpEncoder.EncodeUnsigned(15UL)).Should().Be("0f");

    [Fact]
    public void EncodeUnsigned_1024_Is0x820400()
        => Hex(RlpEncoder.EncodeUnsigned(1024UL)).Should().Be("820400");

    [Fact]
    public void EncodeUnsigned_128_Is0x8180()
        => Hex(RlpEncoder.EncodeUnsigned(128UL)).Should().Be("8180");

    [Fact]
    public void EncodeUnsigned_Negative_Throws()
    {
        var act = () => RlpEncoder.EncodeUnsigned(BigInteger.MinusOne);
        act.Should().Throw<ArgumentOutOfRangeException>().WithParameterName("value");
    }

    [Fact]
    public void ToMinimalBigEndian_StripsLeadingZeros()
    {
        // A 32-byte r/s scalar with leading zero bytes must shrink to its minimal form.
        var scalar = new byte[32];
        scalar[30] = 0x04;
        scalar[31] = 0x00;
        var minimal = RlpEncoder.ToMinimalBigEndian(
            new BigInteger(scalar, isUnsigned: true, isBigEndian: true));
        Hex(minimal).Should().Be("0400");
    }

    // ── Lists ────────────────────────────────────────────────────────────────

    [Fact]
    public void EncodeList_Empty_Is0xc0()
        => Hex(RlpEncoder.EncodeList([])).Should().Be("c0");

    [Fact]
    public void EncodeList_CatDog_Is0xc88363617483646f67()
        => Hex(RlpEncoder.EncodeList(
        [
            RlpEncoder.EncodeBytes(Encoding.ASCII.GetBytes("cat")),
            RlpEncoder.EncodeBytes(Encoding.ASCII.GetBytes("dog")),
        ])).Should().Be("c88363617483646f67");
}
