using FluentAssertions;
using NetDid.Method.Ethr.Abi;
using Xunit;

namespace NetDid.Method.Ethr.Tests;

/// <summary>
/// Tests for ABI encoding/decoding of ERC-1056 calldata and event data.
/// All hex fixtures are either hand-computed or taken from the Ethereum ABI spec.
/// </summary>
public class AbiDecoderTests
{
    // ── AbiEncoder ───────────────────────────────────────────────────────────

    [Fact]
    public void EncodeAddress_PadsTo32Bytes()
    {
        // address 0x001d3F1ef827552Ae1114027BD3ECF1f086bA0F9
        var addrHex = "001d3f1ef827552ae1114027bd3ecf1f086ba0f9";
        var encoded = AbiEncoder.EncodeAddress(Convert.FromHexString(addrHex));
        // 32 bytes: 12 leading zero bytes + 20 address bytes
        encoded.Should().HaveCount(32);
        encoded[..12].Should().AllBeEquivalentTo((byte)0);
        encoded[12..].Should().BeEquivalentTo(Convert.FromHexString(addrHex));
    }

    [Fact]
    public void BuildCalldata_IncludesSelector_ThenPaddedAddress()
    {
        var addrBytes = Convert.FromHexString("001d3f1ef827552ae1114027bd3ecf1f086ba0f9");
        // selector (4 bytes) + padded address (32 bytes) = 36 bytes
        var calldata = AbiEncoder.BuildCalldata(new byte[] { 0xAA, 0xBB, 0xCC, 0xDD }, addrBytes);
        calldata.Should().HaveCount(36);
        calldata[..4].Should().BeEquivalentTo(new byte[] { 0xAA, 0xBB, 0xCC, 0xDD });
    }

    // ── AbiDecoder — static types ─────────────────────────────────────────────

    [Fact]
    public void DecodeAddress_From32ByteWord_ReturnsLast20Bytes()
    {
        var word = new byte[32];
        var addrBytes = Convert.FromHexString("5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed");
        addrBytes.CopyTo(word, 12);

        var result = AbiDecoder.DecodeAddress(word);
        result.Should().BeEquivalentTo(addrBytes);
    }

    [Fact]
    public void DecodeUint256_BigEndian_ReturnsCorrectValue()
    {
        var word = new byte[32];
        word[31] = 0x64; // 100 decimal
        AbiDecoder.DecodeUint256(word).Should().Be(100UL);
    }

    [Fact]
    public void DecodeBytes32_TrimsTrailingNulls()
    {
        // "veriKey\0\0..." → "veriKey"
        var word = new byte[32];
        System.Text.Encoding.ASCII.GetBytes("veriKey").CopyTo(word, 0);
        var result = AbiDecoder.DecodeBytes32AsString(word);
        result.Should().Be("veriKey");
    }

    // ── AbiDecoder — DIDOwnerChanged event data ───────────────────────────────

    [Fact]
    public void DecodeOwnerChangedData_TwoWords_ReturnsOwnerAndPreviousChange()
    {
        // data = owner(32) | previousChange(32)
        var owner20 = Convert.FromHexString("dbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB");
        var data = new byte[64];
        owner20.CopyTo(data, 12);            // owner at offset 0, padded to 32
        data[63] = 0x05;                     // previousChange = 5

        var (owner, prev) = AbiDecoder.DecodeOwnerChangedData(data);
        owner.Should().BeEquivalentTo(owner20);
        prev.Should().Be(5UL);
    }

    // ── AbiDecoder — DIDDelegateChanged event data ────────────────────────────

    [Fact]
    public void DecodeDelegateChangedData_FourWords_ReturnsAllFields()
    {
        // data = delegateType(32) | delegate(32) | validTo(32) | previousChange(32)
        var data = new byte[128];
        System.Text.Encoding.ASCII.GetBytes("veriKey").CopyTo(data, 0); // delegateType word
        var delegate20 = Convert.FromHexString("5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed");
        delegate20.CopyTo(data, 32 + 12);   // delegate at offset 32, padded
        data[2 * 32 + 31] = 0xC8;           // validTo = 200
        data[3 * 32 + 31] = 0x0A;           // previousChange = 10

        var (delegateType, del, validTo, prev) = AbiDecoder.DecodeDelegateChangedData(data);
        delegateType.Should().Be("veriKey");
        del.Should().BeEquivalentTo(delegate20);
        validTo.Should().Be(200UL);
        prev.Should().Be(10UL);
    }

    // ── AbiDecoder — DIDAttributeChanged event data ───────────────────────────

    [Fact]
    public void DecodeAttributeChangedData_ReturnsNameValueValidToPrev()
    {
        // data = name(32) | valueOffset(32) | validTo(32) | previousChange(32)
        //      | valueLength(32) | valueBytes(padded to 32)
        var valueBytes = System.Text.Encoding.UTF8.GetBytes("https://example.com");
        var paddedLen = ((valueBytes.Length + 31) / 32) * 32;
        var data = new byte[5 * 32 + paddedLen];

        System.Text.Encoding.ASCII.GetBytes("did/svc/TestService").CopyTo(data, 0); // name
        // valueOffset = 4*32 = 128 (points to the length prefix)
        data[32 + 31] = (byte)(4 * 32);
        data[2 * 32 + 31] = 0x01;           // validTo = 1
        data[3 * 32 + 31] = 0x00;           // previousChange = 0
        // length word at position 4*32
        data[4 * 32 + 31] = (byte)valueBytes.Length;
        valueBytes.CopyTo(data, 5 * 32);

        var (name, value, validTo, prev) = AbiDecoder.DecodeAttributeChangedData(data);
        name.Should().Be("did/svc/TestService");
        value.Should().BeEquivalentTo(valueBytes);
        validTo.Should().Be(1UL);
        prev.Should().Be(0UL);
    }

    // ── DecodeDynamicBytes — bounds / overflow guards (PR review) ─────────────

    [Fact]
    public void DecodeDynamicBytes_OffsetInDataBeyondSpan_ThrowsArgumentException()
    {
        // offsetInData points past the end of the data blob entirely
        var data = new byte[64];
        var act = () => AbiDecoder.DecodeDynamicBytes(data, offsetInData: 40);
        // offsetInData + 32 = 72 > 64 — must fail with controlled ArgumentException
        act.Should().Throw<ArgumentException>()
           .WithMessage("*offset*");
    }

    [Fact]
    public void DecodeDynamicBytes_PointerBeyondSpan_ThrowsArgumentException()
    {
        // The offset word itself is in-range, but the pointer VALUE it encodes
        // points beyond the data buffer.
        var data = new byte[64];
        // Encode pointer = 500 (well beyond data.Length=64) in word at offsetInData=0
        data[31] = 0xF4; // 244 … no: 500 = 0x01F4
        data[30] = 0x01;
        data[31] = 0xF4;
        var act = () => AbiDecoder.DecodeDynamicBytes(data, offsetInData: 0);
        act.Should().Throw<ArgumentException>()
           .WithMessage("*pointer*");
    }

    [Fact]
    public void DecodeDynamicBytes_LengthBeyondSpan_ThrowsArgumentException()
    {
        // Pointer is valid, but the length word encodes a value that would make
        // pointer + 32 + length exceed data.Length.
        // Layout: [offset-word(32)] [length-word(32)] [no payload bytes]
        var data = new byte[64];
        // pointer = 32 (offset word says "payload starts at byte 32")
        data[31] = 32;
        // length = 100 (way beyond the remaining data)
        data[32 + 31] = 100;
        var act = () => AbiDecoder.DecodeDynamicBytes(data, offsetInData: 0);
        act.Should().Throw<ArgumentException>()
           .WithMessage("*length*");
    }

    [Fact]
    public void DecodeDynamicBytes_PointerOverflowsInt_ThrowsArgumentException()
    {
        // The ulong encoded in the offset word is larger than int.MaxValue.
        // Without a checked cast this silently wraps / produces a negative index.
        // 0x80000000 = 2147483648 = int.MaxValue + 1
        // Big-endian layout for bytes[24..32]: the 5th byte (index 28) carries the
        // value's most-significant non-zero octet (0x80), all others zero.
        var data = new byte[64];
        data[28] = 0x80; // encodes ulong = 0x0000_0000_8000_0000 = 2147483648
        var act = () => AbiDecoder.DecodeDynamicBytes(data, offsetInData: 0);
        act.Should().Throw<ArgumentException>()
           .WithMessage("*pointer*");
    }

    [Fact]
    public void DecodeDynamicBytes_LengthOverflowsInt_ThrowsArgumentException()
    {
        // Pointer is valid (points to byte 32), but the length word encodes
        // a value > int.MaxValue.
        // Length word lives at bytes[56..64]; its 5th byte (index 60) carries 0x80
        // → ulong = 0x0000_0000_8000_0000 = 2147483648 = int.MaxValue + 1
        var data = new byte[64];
        data[31] = 32;   // pointer = 32 (LSB of bytes[24..32])
        data[60] = 0x80; // encodes length ulong = 2147483648
        var act = () => AbiDecoder.DecodeDynamicBytes(data, offsetInData: 0);
        act.Should().Throw<ArgumentException>()
           .WithMessage("*length*");
    }
}
