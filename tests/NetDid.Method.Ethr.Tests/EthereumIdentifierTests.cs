using FluentAssertions;
using NetDid.Method.Ethr.Crypto;
using Xunit;

namespace NetDid.Method.Ethr.Tests;

/// <summary>
/// Tests for EthrIdentifier.ParseMethodSpecificId and .Parse covering all
/// network-prefix formats, including multi-segment names like "artis:sigma1".
/// </summary>
public class EthereumIdentifierTests
{
    private const string Addr40 = "0x001d3f1ef827552ae1114027bd3ecf1f086ba0f9";
    private const string PubKey66 =
        "026e145ccef1033dea239875dd00dfb4fee6e3348b84985c92f103444683bae07b";

    // ── No network prefix ─────────────────────────────────────────────────────

    [Fact]
    public void Parse_AddressOnly_DefaultsToMainnet()
    {
        var id = EthrIdentifier.ParseMethodSpecificId(Addr40);
        id.Network.Should().Be("mainnet");
        id.IdentityAddress.Should().Be(Addr40);
        id.IsPublicKey.Should().BeFalse();
    }

    // ── Simple named network ──────────────────────────────────────────────────

    [Fact]
    public void Parse_SepoliaPrefix_ExtractsNetworkAndAddress()
    {
        var id = EthrIdentifier.ParseMethodSpecificId($"sepolia:{Addr40}");
        id.Network.Should().Be("sepolia");
        id.IdentityAddress.Should().Be(Addr40);
    }

    // ── Hex chain-ID prefix ───────────────────────────────────────────────────

    [Fact]
    public void Parse_HexChainIdPrefix_ExtractsNetworkAndAddress()
    {
        var id = EthrIdentifier.ParseMethodSpecificId($"0xaa36a7:{Addr40}");
        id.Network.Should().Be("0xaa36a7");
        id.IdentityAddress.Should().Be(Addr40);
    }

    // ── Multi-segment network names (the bug) ─────────────────────────────────

    [Fact]
    public void Parse_ArtisNetworkSigma1_ExtractsFullNetworkName()
    {
        var id = EthrIdentifier.ParseMethodSpecificId($"artis:sigma1:{Addr40}");
        id.Network.Should().Be("artis:sigma1");
        id.IdentityAddress.Should().Be(Addr40);
    }

    [Fact]
    public void Parse_ArtisNetworkTau1_ExtractsFullNetworkName()
    {
        var id = EthrIdentifier.ParseMethodSpecificId($"artis:tau1:{Addr40}");
        id.Network.Should().Be("artis:tau1");
        id.IdentityAddress.Should().Be(Addr40);
    }

    [Fact]
    public void Parse_DeeplyNestedNetwork_ExtractsFullNetworkName()
    {
        // Hypothetical three-segment network: "a:b:c" — last segment before 0x is address
        var id = EthrIdentifier.ParseMethodSpecificId($"a:b:c:{Addr40}");
        id.Network.Should().Be("a:b:c");
        id.IdentityAddress.Should().Be(Addr40);
    }

    // ── Full DID parse ────────────────────────────────────────────────────────

    [Fact]
    public void Parse_FullDidWithMultiSegmentNetwork_Succeeds()
    {
        var id = EthrIdentifier.Parse($"did:ethr:artis:sigma1:{Addr40}");
        id.Network.Should().Be("artis:sigma1");
        id.IdentityAddress.Should().Be(Addr40);
    }

    // ── Public-key identifier ─────────────────────────────────────────────────

    [Fact]
    public void Parse_PublicKeyWithNetwork_DerivesAddress()
    {
        var id = EthrIdentifier.ParseMethodSpecificId($"sepolia:0x{PubKey66}");
        id.Network.Should().Be("sepolia");
        id.IsPublicKey.Should().BeTrue();
        id.PublicKeyBytes.Should().BeEquivalentTo(Convert.FromHexString(PubKey66));
    }

    [Fact]
    public void Parse_PublicKeyWithMultiSegmentNetwork_DerivesAddress()
    {
        var id = EthrIdentifier.ParseMethodSpecificId($"artis:sigma1:0x{PubKey66}");
        id.Network.Should().Be("artis:sigma1");
        id.IsPublicKey.Should().BeTrue();
    }

    // ── ChainId property ─────────────────────────────────────────────────────

    [Fact]
    public void ChainId_SepoliaNetwork_Returns11155111()
    {
        var id = EthrIdentifier.ParseMethodSpecificId($"sepolia:{Addr40}");
        id.ChainId.Should().Be("11155111");
    }

    [Fact]
    public void ChainId_HexChainId_ReturnsDecimal()
    {
        var id = EthrIdentifier.ParseMethodSpecificId($"0xaa36a7:{Addr40}");
        id.ChainId.Should().Be("11155111");
    }
}
