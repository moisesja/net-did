using FluentAssertions;
using NetDid.Method.Ethr.Erc1056;
using NetDid.Method.Ethr.Rpc;
using Xunit;

namespace NetDid.Method.Ethr.Tests;

/// <summary>
/// Tests that EthereumLogEntry → typed Erc1056Event parsing is correct for all three events.
/// All hex data is hand-crafted to match the ABI layout verified in AbiDecoderTests.
/// </summary>
public class Erc1056EventParserTests
{
    private const string Identity = "0x001d3F1ef827552Ae1114027BD3ECF1f086bA0F9";
    private const string IdentityTopic = "0x000000000000000000000000001d3f1ef827552ae1114027bd3ecf1f086ba0f9";

    // ── DIDOwnerChanged ───────────────────────────────────────────────────────

    [Fact]
    public void Parse_OwnerChangedLog_ReturnsOwnerChangedEvent()
    {
        // data = owner(32) | previousChange(32)
        var owner20 = "dbf03b407c01e7cd3cbea99509d93f8dddc8c6fb";
        var data = "0x"
            + "000000000000000000000000" + owner20   // owner padded
            + "0000000000000000000000000000000000000000000000000000000000000005"; // prev=5

        var log = new EthereumLogEntry
        {
            Address = "0xdCa7EF03e98e0DC2B855bE647C39ABe984fcF21B",
            Topics = [Erc1056Topics.DIDOwnerChanged, IdentityTopic],
            Data = data,
            BlockNumber = "0x0a",  // block 10
        };

        var ev = Erc1056EventParser.Parse(log);

        ev.Should().BeOfType<OwnerChangedEvent>();
        var oc = (OwnerChangedEvent)ev;
        oc.Identity.Should().Be(Identity.ToLowerInvariant());
        oc.NewOwner.Should().Be("0x" + owner20);
        oc.PreviousChange.Should().Be(5UL);
        oc.BlockNumber.Should().Be(10UL);
    }

    // ── DIDDelegateChanged ────────────────────────────────────────────────────

    [Fact]
    public void Parse_DelegateChangedLog_ReturnsDelegateChangedEvent()
    {
        var delegate20 = "5aaeb6053f3e94c9b9a09f33669435e7ef1beaed";
        var delegateTypePadded = PadRight32("veriKey");

        var data = "0x"
            + delegateTypePadded
            + "000000000000000000000000" + delegate20
            + "00000000000000000000000000000000000000000000000000000000000000c8" // validTo=200
            + "000000000000000000000000000000000000000000000000000000000000000a"; // prev=10

        var log = new EthereumLogEntry
        {
            Address = "0xdCa7EF03e98e0DC2B855bE647C39ABe984fcF21B",
            Topics = [Erc1056Topics.DIDDelegateChanged, IdentityTopic],
            Data = data,
            BlockNumber = "0x14",  // block 20
        };

        var ev = Erc1056EventParser.Parse(log);

        ev.Should().BeOfType<DelegateChangedEvent>();
        var dc = (DelegateChangedEvent)ev;
        dc.Identity.Should().Be(Identity.ToLowerInvariant());
        dc.DelegateType.Should().Be("veriKey");
        dc.Delegate.Should().Be("0x" + delegate20);
        dc.ValidTo.Should().Be(200UL);
        dc.PreviousChange.Should().Be(10UL);
        dc.BlockNumber.Should().Be(20UL);
    }

    // ── DIDAttributeChanged ───────────────────────────────────────────────────

    [Fact]
    public void Parse_AttributeChangedLog_ReturnsAttributeChangedEvent()
    {
        var nameStr = "did/svc/TestService";
        var valueStr = "https://example.com";
        var valueBytes = System.Text.Encoding.UTF8.GetBytes(valueStr);
        var paddedValueLen = ((valueBytes.Length + 31) / 32) * 32;

        // Layout: name(32) | valueOffset(32) | validTo(32) | previousChange(32) | length(32) | value(padded)
        // valueOffset = 4*32 = 128 = 0x80 (byte offset within the data blob)
        var dataBytes = new byte[5 * 32 + paddedValueLen];
        System.Text.Encoding.ASCII.GetBytes(nameStr).CopyTo(dataBytes, 0);
        dataBytes[32 + 31] = 0x80; // valueOffset = 128
        dataBytes[2 * 32 + 31] = 0x01; // validTo = 1
        // previousChange = 0 (already zeroed)
        dataBytes[4 * 32 + 31] = (byte)valueBytes.Length;
        valueBytes.CopyTo(dataBytes, 5 * 32);

        var log = new EthereumLogEntry
        {
            Address = "0xdCa7EF03e98e0DC2B855bE647C39ABe984fcF21B",
            Topics = [Erc1056Topics.DIDAttributeChanged, IdentityTopic],
            Data = "0x" + Convert.ToHexString(dataBytes).ToLowerInvariant(),
            BlockNumber = "0x1e",  // block 30
        };

        var ev = Erc1056EventParser.Parse(log);

        ev.Should().BeOfType<AttributeChangedEvent>();
        var ac = (AttributeChangedEvent)ev;
        ac.Identity.Should().Be(Identity.ToLowerInvariant());
        ac.Name.Should().Be(nameStr);
        ac.Value.Should().BeEquivalentTo(valueBytes);
        ac.ValidTo.Should().Be(1UL);
        ac.PreviousChange.Should().Be(0UL);
        ac.BlockNumber.Should().Be(30UL);
    }

    // ── Unknown topic ─────────────────────────────────────────────────────────

    [Fact]
    public void Parse_UnknownTopic_ThrowsArgumentException()
    {
        var log = new EthereumLogEntry
        {
            Address = "0xdCa7EF03e98e0DC2B855bE647C39ABe984fcF21B",
            Topics = ["0xdeadbeef", IdentityTopic],
            Data = "0x",
            BlockNumber = "0x1",
        };

        var act = () => Erc1056EventParser.Parse(log);
        act.Should().Throw<ArgumentException>();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static string PadRight32(string ascii)
    {
        var bytes = new byte[32];
        System.Text.Encoding.ASCII.GetBytes(ascii).CopyTo(bytes, 0);
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }
}
