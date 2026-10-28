using System.Net;
using FluentAssertions;
using NetDid.Method.WebVh;

namespace NetDid.Method.WebVh.Tests;

public class WebVhNetworkPolicyTests
{
    [Theory]
    [InlineData("0.0.0.0")]
    [InlineData("10.255.255.255")]
    [InlineData("100.64.0.0")]
    [InlineData("100.127.255.255")]
    [InlineData("127.255.255.255")]
    [InlineData("169.254.0.1")]
    [InlineData("172.16.0.0")]
    [InlineData("172.31.255.255")]
    [InlineData("192.168.255.255")]
    [InlineData("224.0.0.1")]
    [InlineData("255.255.255.255")]
    [InlineData("::")]
    [InlineData("::1")]
    [InlineData("fe80::1")]
    [InlineData("fc00::1")]
    [InlineData("fdff::1")]
    [InlineData("ff02::1")]
    [InlineData("::ffff:127.0.0.1")]
    [InlineData("::ffff:192.168.1.1")]
    [InlineData("::ffff:0:127.0.0.1")]
    [InlineData("64:ff9b::127.0.0.1")]
    [InlineData("64:ff9b:1::a00:1")]
    [InlineData("100::1")]
    [InlineData("2001::1")]
    [InlineData("2001:2::1")]
    [InlineData("2001:10::1")]
    [InlineData("2001:db8::1")]
    [InlineData("2002:7f00:1::1")]
    [InlineData("3ffe::1")]
    [InlineData("3fff::1")]
    public void IsPublicAddress_NonPublicAddress_ReturnsFalse(string value)
    {
        WebVhNetworkPolicy.IsPublicAddress(IPAddress.Parse(value)).Should().BeFalse();
    }

    [Theory]
    [InlineData("8.8.8.8")]
    [InlineData("100.63.255.255")]
    [InlineData("100.128.0.0")]
    [InlineData("172.15.255.255")]
    [InlineData("172.32.0.0")]
    [InlineData("1.1.1.1")]
    [InlineData("2606:4700:4700::1111")]
    public void IsPublicAddress_PublicAddress_ReturnsTrue(string value)
    {
        WebVhNetworkPolicy.IsPublicAddress(IPAddress.Parse(value)).Should().BeTrue();
    }

    [Fact]
    public async Task ResolveAndConnect_UnsafeDnsAnswer_DoesNotConnect()
    {
        var connectCount = 0;

        var act = async () => await DefaultWebVhHttpClient.ResolveAndConnectAsync(
            new DnsEndPoint("attacker.example", 443),
            (_, _) => Task.FromResult(new[] { IPAddress.Parse("10.0.0.1") }),
            (_, _, _) =>
            {
                connectCount++;
                return ValueTask.FromResult<Stream>(new MemoryStream());
            },
            CancellationToken.None);

        await act.Should().ThrowAsync<HttpRequestException>();
        connectCount.Should().Be(0);
    }

    [Fact]
    public async Task ResolveAndConnect_MixedPublicAndPrivateDnsAnswers_DoesNotConnect()
    {
        var connectCount = 0;

        var act = async () => await DefaultWebVhHttpClient.ResolveAndConnectAsync(
            new DnsEndPoint("attacker.example", 443),
            (_, _) => Task.FromResult(new[]
            {
                IPAddress.Parse("8.8.8.8"),
                IPAddress.Parse("169.254.169.254")
            }),
            (_, _, _) =>
            {
                connectCount++;
                return ValueTask.FromResult<Stream>(new MemoryStream());
            },
            CancellationToken.None);

        await act.Should().ThrowAsync<HttpRequestException>();
        connectCount.Should().Be(0);
    }

    [Fact]
    public async Task ResolveAndConnect_PublicDnsAnswer_ConnectsToValidatedAddressAndPort()
    {
        var expectedAddress = IPAddress.Parse("8.8.8.8");
        IPAddress? connectedAddress = null;
        int? connectedPort = null;

        await using var stream = await DefaultWebVhHttpClient.ResolveAndConnectAsync(
            new DnsEndPoint("public.example", 8443),
            (_, _) => Task.FromResult(new[] { expectedAddress }),
            (address, port, _) =>
            {
                connectedAddress = address;
                connectedPort = port;
                return ValueTask.FromResult<Stream>(new MemoryStream());
            },
            CancellationToken.None);

        connectedAddress.Should().Be(expectedAddress);
        connectedPort.Should().Be(8443);
    }

    [Fact]
    public async Task ResolveAndConnect_EmptyDnsAnswer_DoesNotConnect()
    {
        var connectCount = 0;

        var act = async () => await DefaultWebVhHttpClient.ResolveAndConnectAsync(
            new DnsEndPoint("missing.example", 443),
            (_, _) => Task.FromResult(Array.Empty<IPAddress>()),
            (_, _, _) =>
            {
                connectCount++;
                return ValueTask.FromResult<Stream>(new MemoryStream());
            },
            CancellationToken.None);

        await act.Should().ThrowAsync<HttpRequestException>();
        connectCount.Should().Be(0);
    }

    [Fact]
    public async Task ResolveAndConnect_CancellationFromDns_Propagates()
    {
        using var source = new CancellationTokenSource();
        source.Cancel();

        var act = async () => await DefaultWebVhHttpClient.ResolveAndConnectAsync(
            new DnsEndPoint("public.example", 443),
            (_, ct) => Task.FromCanceled<IPAddress[]>(ct),
            (_, _, _) => ValueTask.FromResult<Stream>(new MemoryStream()),
            source.Token);

        await act.Should().ThrowAsync<OperationCanceledException>();
    }
}
