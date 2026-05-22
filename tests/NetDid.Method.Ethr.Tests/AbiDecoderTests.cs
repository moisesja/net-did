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
}
