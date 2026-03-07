using FluentAssertions;
using NSubstitute;
using NetDid.Core.Model;
using NetDid.Core.Resolution;

namespace NetDid.Core.Tests.Resolution;

public class DefaultDidUrlDereferencerTests
{
    private readonly IDidResolver _resolver;
    private readonly DefaultDidUrlDereferencer _dereferencer;

    public DefaultDidUrlDereferencerTests()
    {
        _resolver = Substitute.For<IDidResolver>();
        _dereferencer = new DefaultDidUrlDereferencer(_resolver);
    }

    private DidDocument CreateDocWithVmAndService()
    {
        return new DidDocument
        {
            Id = new Did("did:example:123"),
            VerificationMethod = new List<VerificationMethod>
            {
                new()
                {
                    Id = "did:example:123#key-1",
                    Type = "Multikey",
                    Controller = new Did("did:example:123"),
                    PublicKeyMultibase = "z6Mk..."
                }
            },
            Service = new List<Service>
            {
                new()
                {
                    Id = "did:example:123#linked-domain",
                    Type = "LinkedDomains",
                    ServiceEndpoint = ServiceEndpointValue.FromUri("https://example.com")
                }
            }
        };
    }

    private void SetupResolverSuccess(DidDocument doc)
    {
        _resolver.ResolveAsync(Arg.Any<string>(), Arg.Any<DidResolutionOptions?>(), Arg.Any<CancellationToken>())
            .Returns(new DidResolutionResult
            {
                DidDocument = doc,
                ResolutionMetadata = new DidResolutionMetadata { ContentType = DidContentTypes.JsonLd }
            });
    }

    private void SetupResolverNotFound()
    {
        _resolver.ResolveAsync(Arg.Any<string>(), Arg.Any<DidResolutionOptions?>(), Arg.Any<CancellationToken>())
            .Returns(DidResolutionResult.NotFound("did:example:123"));
    }

    [Fact]
    public async Task DereferenceAsync_InvalidDidUrl_ReturnsError()
    {
        var result = await _dereferencer.DereferenceAsync("not-a-did-url");

        result.DereferencingMetadata.Error.Should().Be("invalidDidUrl");
    }

    [Fact]
    public async Task DereferenceAsync_Fragment_ReturnsVerificationMethod()
    {
        var doc = CreateDocWithVmAndService();
        SetupResolverSuccess(doc);

        var result = await _dereferencer.DereferenceAsync("did:example:123#key-1");

        result.DereferencingMetadata.Error.Should().BeNull();
        result.ContentStream.Should().NotBeNull();
        result.ContentStream.Should().BeOfType<VerificationMethod>();
        ((VerificationMethod)result.ContentStream!).Id.Should().Be("did:example:123#key-1");
    }

    [Fact]
    public async Task DereferenceAsync_Fragment_ServiceMatch_ReturnsService()
    {
        var doc = CreateDocWithVmAndService();
        SetupResolverSuccess(doc);

        var result = await _dereferencer.DereferenceAsync("did:example:123#linked-domain");

        result.DereferencingMetadata.Error.Should().BeNull();
        result.ContentStream.Should().BeOfType<Service>();
    }

    [Fact]
    public async Task DereferenceAsync_Fragment_NotFound_ReturnsError()
    {
        var doc = CreateDocWithVmAndService();
        SetupResolverSuccess(doc);

        var result = await _dereferencer.DereferenceAsync("did:example:123#nonexistent");

        result.DereferencingMetadata.Error.Should().Be("notFound");
    }

    [Fact]
    public async Task DereferenceAsync_ServiceQuery_ReturnsRedirect()
    {
        var doc = CreateDocWithVmAndService();
        SetupResolverSuccess(doc);

        var result = await _dereferencer.DereferenceAsync("did:example:123?service=linked-domain");

        result.DereferencingMetadata.ContentType.Should().Be("text/uri-list");
        result.ContentStream.Should().Be("https://example.com");
    }

    [Fact]
    public async Task DereferenceAsync_ServiceQuery_WithRelativeRef_ConstructsUrl()
    {
        var doc = CreateDocWithVmAndService();
        SetupResolverSuccess(doc);

        var result = await _dereferencer.DereferenceAsync(
            "did:example:123?service=linked-domain&relativeRef=/path/to/resource");

        result.ContentStream.Should().Be("https://example.com/path/to/resource");
    }

    [Fact]
    public async Task DereferenceAsync_ServiceQuery_NotFound_ReturnsError()
    {
        var doc = CreateDocWithVmAndService();
        SetupResolverSuccess(doc);

        var result = await _dereferencer.DereferenceAsync("did:example:123?service=nonexistent");

        result.DereferencingMetadata.Error.Should().Be("notFound");
    }

    [Fact]
    public async Task DereferenceAsync_ResolutionFails_ReturnsError()
    {
        SetupResolverNotFound();

        var result = await _dereferencer.DereferenceAsync("did:example:123#key-1");

        result.DereferencingMetadata.Error.Should().Be("notFound");
    }

    [Fact]
    public async Task DereferenceAsync_BareDid_ReturnsFullDocument()
    {
        var doc = CreateDocWithVmAndService();
        SetupResolverSuccess(doc);

        var result = await _dereferencer.DereferenceAsync("did:example:123");

        result.DereferencingMetadata.Error.Should().BeNull();
        result.ContentStream.Should().BeOfType<DidDocument>();
    }

    [Fact]
    public async Task DereferenceAsync_Path_WithoutServiceQuery_ReturnsNotFound()
    {
        var doc = CreateDocWithVmAndService();
        SetupResolverSuccess(doc);

        var result = await _dereferencer.DereferenceAsync("did:example:123/some/path");

        result.DereferencingMetadata.Error.Should().Be("notFound");
    }
}
