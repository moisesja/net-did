using FluentAssertions;
using NetCrypto;
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

    // --- Issue #49: hostile authority/path inputs ---

    [Theory]
    [InlineData("did:webvh:QmTest:trusted.example%40evil.example", "@")]
    [InlineData("did:webvh:QmTest:example.com%2Fattacker", "/")]
    [InlineData("did:webvh:QmTest:example.com%5Cevil", "\\")]
    [InlineData("did:webvh:QmTest:example.com%3Fquery", "?")]
    [InlineData("did:webvh:QmTest:example.com%23frag", "#")]
    public void Issue49_MapToLogUrl_UnsafeDomainChar_Throws(string did, string _)
    {
        var act = () => DidUrlMapper.MapToLogUrl(did);
        act.Should().Throw<ArgumentException>();
    }

    [Theory]
    [InlineData("did:webvh:QmTest:")]                     // empty domain
    [InlineData("did:webvh:QmTest:example.com%3A99999")]  // port out of range
    [InlineData("did:webvh:QmTest:example.com%3Aabc")]    // non-numeric port
    [InlineData("did:webvh:QmTest:example.com%3A0")]      // port zero
    [InlineData("did:webvh:QmTest:example.com%3A-1")]     // negative port
    [InlineData("did:webvh:QmTest:%3A8443")]              // empty host with port
    public void Issue49_MapToLogUrl_InvalidHostOrPort_Throws(string did)
    {
        var act = () => DidUrlMapper.MapToLogUrl(did);
        act.Should().Throw<ArgumentException>();
    }

    [Theory]
    [InlineData("did:webvh:QmTest:example.com:..:admin")]      // literal traversal
    [InlineData("did:webvh:QmTest:example.com:%2E%2E:admin")]  // encoded ..
    [InlineData("did:webvh:QmTest:example.com:.:admin")]       // literal "."
    [InlineData("did:webvh:QmTest:example.com:%2E:admin")]     // encoded "."
    [InlineData("did:webvh:QmTest:example.com:bad%2Fseg")]     // encoded slash in segment
    public void Issue49_MapToLogUrl_UnsafePathSegment_Throws(string did)
    {
        var act = () => DidUrlMapper.MapToLogUrl(did);
        act.Should().Throw<ArgumentException>();
    }

    [Theory]
    [InlineData("did:webvh:QmTest:example.com%40evil")]
    [InlineData("did:webvh:QmTest:example.com:..:admin")]
    public void Issue49_MapToWitnessUrl_UnsafeInput_Throws(string did)
    {
        var act = () => DidUrlMapper.MapToWitnessUrl(did);
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Issue49_MapToLogUrl_ValidEncodedPort_StillMaps()
    {
        // Regression: the spec's port-encoding path must continue to work.
        var url = DidUrlMapper.MapToLogUrl("did:webvh:QmTest:example.com%3A8443");
        url.Should().Be(new Uri("https://example.com:8443/.well-known/did.jsonl"));
    }

    [Fact]
    public void Issue49_MapToLogUrl_ValidPath_StillMaps()
    {
        var url = DidUrlMapper.MapToLogUrl("did:webvh:QmTest:example.com:users:alice");
        url.Should().Be(new Uri("https://example.com/users/alice/did.jsonl"));
    }

    [Fact]
    public async Task Create_LocalhostDomain_ThrowsBeforeProducingArtifacts()
    {
        var client = new RecordingWebVhHttpClient();
        var method = new DidWebVhMethod(client);
        var keyPair = new DefaultKeyGenerator().Generate(KeyType.Ed25519);
        var signer = new KeyPairSigner(keyPair, new DefaultCryptoProvider());

        var act = () => method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "localhost",
            UpdateKey = signer
        });

        await act.Should().ThrowAsync<ArgumentException>();
        client.FetchCount.Should().Be(0);
    }

    [Fact]
    public async Task Resolve_LocalhostDid_ReturnsNotFoundWithoutCallingCustomClient()
    {
        var client = new RecordingWebVhHttpClient();
        var method = new DidWebVhMethod(client);

        var result = await method.ResolveAsync("did:webvh:QmTest:localhost");

        result.DidDocument.Should().BeNull();
        result.ResolutionMetadata.Error.Should().Be("notFound");
        client.FetchCount.Should().Be(0);
    }

    [Theory]
    [InlineData("did:webvh:QmTest:localhost")]
    [InlineData("did:webvh:QmTest:sub.localhost")]
    [InlineData("did:webvh:QmTest:0.0.0.0")]
    [InlineData("did:webvh:QmTest:10.0.0.5")]
    [InlineData("did:webvh:QmTest:127.0.0.1")]
    [InlineData("did:webvh:QmTest:2130706433")]
    [InlineData("did:webvh:QmTest:0177.0.0.1")]
    [InlineData("did:webvh:QmTest:0x7f000001")]
    [InlineData("did:webvh:QmTest:localhost。")]
    [InlineData("did:webvh:QmTest:localhost．")]
    [InlineData("did:webvh:QmTest:localhost｡")]
    [InlineData("did:webvh:QmTest:１２７。０。０。１")]
    [InlineData("did:webvh:QmTest:127。0。0。1")]
    [InlineData("did:webvh:QmTest:169.254.169.254")]
    [InlineData("did:webvh:QmTest:172.16.0.1")]
    [InlineData("did:webvh:QmTest:172.31.255.255")]
    [InlineData("did:webvh:QmTest:192.168.1.10")]
    [InlineData("did:webvh:QmTest:192.168.1.10%3A8443")]
    public void SecurityAdvisory_MapToLogUrl_NonPublicHost_Throws(string did)
    {
        var act = () => DidUrlMapper.MapToLogUrl(did);

        act.Should().Throw<ArgumentException>();
    }

    private sealed class RecordingWebVhHttpClient : IWebVhHttpClient
    {
        public int FetchCount { get; private set; }

        public Task<byte[]?> FetchDidLogAsync(Uri logUrl, CancellationToken ct = default)
        {
            FetchCount++;
            return Task.FromResult<byte[]?>(null);
        }

        public Task<byte[]?> FetchWitnessFileAsync(Uri witnessUrl, CancellationToken ct = default)
        {
            FetchCount++;
            return Task.FromResult<byte[]?>(null);
        }
    }
}
