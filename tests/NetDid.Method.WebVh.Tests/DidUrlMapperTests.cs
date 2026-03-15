using FluentAssertions;
using NetDid.Method.WebVh;

namespace NetDid.Method.WebVh.Tests;

public class DidUrlMapperTests
{
    [Fact]
    public void MapToLogUrl_RootDid_MapsToWellKnown()
    {
        var url = DidUrlMapper.MapToLogUrl("did:webvh:QmTest:example.com");
        url.Should().Be(new Uri("https://example.com/.well-known/did.jsonl"));
    }

    [Fact]
    public void MapToLogUrl_PathDid_MapsToPath()
    {
        var url = DidUrlMapper.MapToLogUrl("did:webvh:QmTest:example.com:users:alice");
        url.Should().Be(new Uri("https://example.com/users/alice/did.jsonl"));
    }

    [Fact]
    public void MapToLogUrl_PortEncoded_DecodesPort()
    {
        var url = DidUrlMapper.MapToLogUrl("did:webvh:QmTest:example.com%3A8443");
        url.Should().Be(new Uri("https://example.com:8443/.well-known/did.jsonl"));
    }

    [Fact]
    public void MapToWitnessUrl_RootDid_MapsToWellKnown()
    {
        var url = DidUrlMapper.MapToWitnessUrl("did:webvh:QmTest:example.com");
        url.Should().Be(new Uri("https://example.com/.well-known/did-witness.json"));
    }

    [Fact]
    public void ExtractScid_ValidDid_ReturnsScid()
    {
        var scid = DidUrlMapper.ExtractScid("did:webvh:QmAbc123:example.com");
        scid.Should().Be("QmAbc123");
    }

    [Fact]
    public void ExtractDomain_ValidDid_ReturnsDomain()
    {
        var domain = DidUrlMapper.ExtractDomain("did:webvh:QmAbc123:example.com");
        domain.Should().Be("example.com");
    }

    [Fact]
    public void ExtractPath_RootDid_ReturnsNull()
    {
        var path = DidUrlMapper.ExtractPath("did:webvh:QmAbc123:example.com");
        path.Should().BeNull();
    }

    [Fact]
    public void ExtractPath_PathDid_ReturnsPath()
    {
        var path = DidUrlMapper.ExtractPath("did:webvh:QmAbc123:example.com:users:alice");
        path.Should().Be("users/alice");
    }
}
