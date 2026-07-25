using FluentAssertions;
using NetDid.Method.Ethr.Crypto;
using NetDid.Method.Ethr.Rpc;
using Xunit;

namespace NetDid.Method.Ethr.Tests;

/// <summary>
/// Guards every KnownNetworks name → chain-ID pair (PR #104 review found artis:sigma1
/// carrying tau1's chain ID, aliasing the two ARTIS built-ins). Values mirror the JS
/// ethr-did-resolver deployments catalogue.
/// </summary>
public class KnownNetworksTests
{
    [Theory]
    [InlineData("mainnet",       1UL)]
    [InlineData("polygon",       137UL)]
    [InlineData("gno",           100UL)]
    [InlineData("aurora",        1313161554UL)]
    [InlineData("ewc",           246UL)]
    [InlineData("artis:sigma1",  246529UL)]
    [InlineData("sepolia",       11155111UL)]
    [InlineData("holesky",       17000UL)]
    [InlineData("polygon:test",  80001UL)]
    [InlineData("volta",         73799UL)]
    [InlineData("artis:tau1",    246785UL)]
    [InlineData("linea:goerli",  59140UL)]
    public void KnownNetwork_HasCorrectChainId(string name, ulong expectedDecimal)
    {
        var net = KnownNetworks.Find(name);

        net.Should().NotBeNull($"'{name}' must be a known network");
        var hex = net!.ChainId!.StartsWith("0x") ? net.ChainId[2..] : net.ChainId;
        Convert.ToUInt64(hex, 16).Should().Be(expectedDecimal);
    }

    [Fact]
    public void AllTwelveNetworksAreCovered()
        => KnownNetworks.All.Should().HaveCount(12);

    [Fact]
    public void ArtisSigma1AndTau1_HaveDistinctChainIds()
    {
        var sigma1 = KnownNetworks.Find("artis:sigma1")!;
        var tau1   = KnownNetworks.Find("artis:tau1")!;

        sigma1.ChainId.Should().Be("0x3C301");
        tau1.ChainId.Should().Be("0x3C401");
        sigma1.ChainId.Should().NotBe(tau1.ChainId, "the two ARTIS chains must not alias");
    }

    [Fact]
    public void FindByChainId_ResolvesArtisChainsToDistinctConfigs()
    {
        KnownNetworks.Find("0x3C301")!.Name.Should().Be("artis:sigma1");
        KnownNetworks.Find("0x3C401")!.Name.Should().Be("artis:tau1");
    }

    [Fact]
    public void AllChainIds_AreUnique()
    {
        var ids = KnownNetworks.All.Select(n => n.ChainId!.ToLowerInvariant()).ToList();
        ids.Should().OnlyHaveUniqueItems("no two built-in networks may share a chain ID");
    }

    [Fact]
    public void Pr104Review_EthrIdentifierUsesKnownNetworkCatalogueForEveryNamedChain()
    {
        const string address = "0x001d3f1ef827552ae1114027bd3ecf1f086ba0f9";

        foreach (var network in KnownNetworks.All)
        {
            var identifier = EthrIdentifier.ParseMethodSpecificId($"{network.Name}:{address}");
            var chainIdHex = network.ChainId!.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
                ? network.ChainId[2..]
                : network.ChainId;
            var expectedDecimal = Convert.ToUInt64(chainIdHex, 16).ToString();

            identifier.ChainId.Should().Be(expectedDecimal,
                $"the {network.Name} identifier must use the central KnownNetworks catalogue");
        }
    }

    [Fact]
    public void Pr104Review_DeprecatedGoerliIdentifierRetainsNumericChainId()
    {
        const string address = "0x001d3f1ef827552ae1114027bd3ecf1f086ba0f9";

        var identifier = EthrIdentifier.ParseMethodSpecificId($"goerli:{address}");

        identifier.ChainId.Should().Be("5");
        KnownNetworks.All.Should().NotContain(network => network.Name == "goerli",
            "deprecated deployments must not be advertised as active configurations");
    }
}
