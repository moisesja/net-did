using System.Text.Json;
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
    public async Task DereferenceAsync_ServiceQuery_WithUriListAccept_ReturnsRedirect()
    {
        var doc = CreateDocWithVmAndService();
        SetupResolverSuccess(doc);

        var result = await _dereferencer.DereferenceAsync(
            "did:example:123?service=linked-domain",
            new DidUrlDereferencingOptions { Accept = "text/uri-list" });

        result.DereferencingMetadata.ContentType.Should().Be("text/uri-list");
        result.ContentStream.Should().Be("https://example.com/");
    }

    [Fact]
    public async Task DereferenceAsync_ServiceQuery_DefaultAccept_ReturnsDidDocumentWithService()
    {
        var doc = CreateDocWithVmAndService();
        SetupResolverSuccess(doc);

        var result = await _dereferencer.DereferenceAsync("did:example:123?service=linked-domain");

        result.DereferencingMetadata.Error.Should().BeNull();
        result.ContentStream.Should().BeOfType<DidDocument>();
        var filtered = (DidDocument)result.ContentStream!;
        filtered.Id.Value.Should().Be("did:example:123");
        filtered.Service.Should().HaveCount(1);
        filtered.Service![0].Type.Should().Be("LinkedDomains");
    }

    [Fact]
    public async Task DereferenceAsync_ServiceQuery_WithRelativeRef_ConstructsUrl()
    {
        var doc = CreateDocWithVmAndService();
        SetupResolverSuccess(doc);

        var result = await _dereferencer.DereferenceAsync(
            "did:example:123?service=linked-domain&relativeRef=/path/to/resource",
            new DidUrlDereferencingOptions { Accept = "text/uri-list" });

        result.ContentStream.Should().Be("https://example.com/path/to/resource");
    }

    [Fact]
    public async Task DereferenceAsync_ServiceTypeQuery_ReturnsDidDocumentWithMatchingService()
    {
        var doc = CreateDocWithVmAndService();
        SetupResolverSuccess(doc);

        var result = await _dereferencer.DereferenceAsync("did:example:123?serviceType=LinkedDomains");

        result.DereferencingMetadata.Error.Should().BeNull();
        result.ContentStream.Should().BeOfType<DidDocument>();
        var filtered = (DidDocument)result.ContentStream!;
        filtered.Service.Should().HaveCount(1);
        filtered.Service![0].Type.Should().Be("LinkedDomains");
    }

    [Fact]
    public async Task DereferenceAsync_ServiceTypeQuery_NotFound_ReturnsError()
    {
        var doc = CreateDocWithVmAndService();
        SetupResolverSuccess(doc);

        var result = await _dereferencer.DereferenceAsync("did:example:123?serviceType=NonExistentType");

        result.DereferencingMetadata.Error.Should().Be("notFound");
    }

    [Fact]
    public async Task DereferenceAsync_ServiceQuery_MapEndpoint_WhenUriListAccept_ReturnsError()
    {
        var doc = new DidDocument
        {
            Id = new Did("did:example:123"),
            Service =
            [
                new Service
                {
                    Id = "did:example:123#map-svc",
                    Type = "MapService",
                    ServiceEndpoint = ServiceEndpointValue.FromMap(
                        new Dictionary<string, JsonElement> { ["origin"] = JsonSerializer.SerializeToElement("https://example.com") })
                }
            ]
        };
        SetupResolverSuccess(doc);

        var result = await _dereferencer.DereferenceAsync(
            "did:example:123?service=map-svc",
            new DidUrlDereferencingOptions { Accept = "text/uri-list" });

        result.DereferencingMetadata.Error.Should().Be("notFound");
    }

    [Fact]
    public async Task DereferenceAsync_ServiceQuery_MapEndpoint_DefaultAccept_ReturnsDidDocumentWithService()
    {
        var doc = new DidDocument
        {
            Id = new Did("did:example:123"),
            Service =
            [
                new Service
                {
                    Id = "did:example:123#map-svc",
                    Type = "MapService",
                    ServiceEndpoint = ServiceEndpointValue.FromMap(
                        new Dictionary<string, JsonElement> { ["origin"] = JsonSerializer.SerializeToElement("https://example.com") })
                }
            ]
        };
        SetupResolverSuccess(doc);

        var result = await _dereferencer.DereferenceAsync("did:example:123?service=map-svc");

        result.DereferencingMetadata.Error.Should().BeNull();
        result.ContentStream.Should().BeOfType<DidDocument>();
        var filtered = (DidDocument)result.ContentStream!;
        filtered.Service.Should().HaveCount(1);
        filtered.Service![0].Type.Should().Be("MapService");
    }

    [Fact]
    public async Task DereferenceAsync_ServiceQuery_RelativeRef_UsesRfc3986()
    {
        var doc = new DidDocument
        {
            Id = new Did("did:example:123"),
            Service =
            [
                new Service
                {
                    Id = "did:example:123#svc",
                    Type = "TestService",
                    ServiceEndpoint = ServiceEndpointValue.FromUri("https://example.com/base/path/")
                }
            ]
        };
        SetupResolverSuccess(doc);

        // RFC 3986: "../resource" relative to "https://example.com/base/path/" resolves to "https://example.com/base/resource"
        var result = await _dereferencer.DereferenceAsync(
            "did:example:123?service=svc&relativeRef=../resource",
            new DidUrlDereferencingOptions { Accept = "text/uri-list" });

        result.DereferencingMetadata.ContentType.Should().Be("text/uri-list");
        result.ContentStream.Should().Be("https://example.com/base/resource");
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

    [Fact]
    public async Task DereferenceAsync_ServiceQuery_FullIdMatch_ReturnsService()
    {
        var doc = CreateDocWithVmAndService();
        SetupResolverSuccess(doc);

        // Match by full service ID instead of just fragment
        var result = await _dereferencer.DereferenceAsync(
            "did:example:123?service=did:example:123%23linked-domain",
            new DidUrlDereferencingOptions { Accept = "text/uri-list" });

        result.DereferencingMetadata.ContentType.Should().Be("text/uri-list");
        result.ContentStream.Should().BeOfType<string>();
    }

    [Fact]
    public async Task DereferenceAsync_ServiceQuery_SetEndpoint_UriListAccept_ReturnsAllUris()
    {
        var doc = new DidDocument
        {
            Id = new Did("did:example:123"),
            Service =
            [
                new Service
                {
                    Id = "did:example:123#multi-svc",
                    Type = "MultiEndpoint",
                    ServiceEndpoint = ServiceEndpointValue.FromSet([
                        ServiceEndpointValue.FromUri("https://a.example.com"),
                        ServiceEndpointValue.FromUri("https://b.example.com")
                    ])
                }
            ]
        };
        SetupResolverSuccess(doc);

        var result = await _dereferencer.DereferenceAsync(
            "did:example:123?service=multi-svc",
            new DidUrlDereferencingOptions { Accept = "text/uri-list" });

        result.DereferencingMetadata.ContentType.Should().Be("text/uri-list");
        var uriList = (string)result.ContentStream!;
        uriList.Should().Contain("https://a.example.com/");
        uriList.Should().Contain("https://b.example.com/");
    }

    [Fact]
    public async Task DereferenceAsync_ServiceQuery_SetEndpoint_DefaultAccept_ReturnsDidDocument()
    {
        var doc = new DidDocument
        {
            Id = new Did("did:example:123"),
            Service =
            [
                new Service
                {
                    Id = "did:example:123#multi-svc",
                    Type = "MultiEndpoint",
                    ServiceEndpoint = ServiceEndpointValue.FromSet([
                        ServiceEndpointValue.FromUri("https://a.example.com"),
                        ServiceEndpointValue.FromUri("https://b.example.com")
                    ])
                }
            ]
        };
        SetupResolverSuccess(doc);

        var result = await _dereferencer.DereferenceAsync("did:example:123?service=multi-svc");

        result.DereferencingMetadata.Error.Should().BeNull();
        result.ContentStream.Should().BeOfType<DidDocument>();
        var filtered = (DidDocument)result.ContentStream!;
        filtered.Service.Should().HaveCount(1);
        filtered.Service![0].Type.Should().Be("MultiEndpoint");
    }

    [Fact]
    public async Task DereferenceAsync_Fragment_WithVerificationRelationship_FiltersCorrectly()
    {
        var doc = new DidDocument
        {
            Id = new Did("did:example:123"),
            VerificationMethod =
            [
                new VerificationMethod
                {
                    Id = "did:example:123#key-auth",
                    Type = "Multikey",
                    Controller = new Did("did:example:123"),
                    PublicKeyMultibase = "z6MkAuth"
                },
                new VerificationMethod
                {
                    Id = "did:example:123#key-agree",
                    Type = "Multikey",
                    Controller = new Did("did:example:123"),
                    PublicKeyMultibase = "z6MkAgree"
                }
            ],
            Authentication = [VerificationRelationshipEntry.FromReference("did:example:123#key-auth")],
            KeyAgreement = [VerificationRelationshipEntry.FromReference("did:example:123#key-agree")]
        };
        SetupResolverSuccess(doc);

        // With verificationRelationship=authentication, key-auth should be found
        var result = await _dereferencer.DereferenceAsync(
            "did:example:123#key-auth",
            new DidUrlDereferencingOptions { VerificationRelationship = "authentication" });

        result.DereferencingMetadata.Error.Should().BeNull();
        result.ContentStream.Should().BeOfType<VerificationMethod>();
        ((VerificationMethod)result.ContentStream!).Id.Should().Be("did:example:123#key-auth");
    }

    [Fact]
    public async Task DereferenceAsync_Fragment_WrongRelationship_ReturnsNotFound()
    {
        var doc = new DidDocument
        {
            Id = new Did("did:example:123"),
            VerificationMethod =
            [
                new VerificationMethod
                {
                    Id = "did:example:123#key-auth",
                    Type = "Multikey",
                    Controller = new Did("did:example:123"),
                    PublicKeyMultibase = "z6MkAuth"
                }
            ],
            Authentication = [VerificationRelationshipEntry.FromReference("did:example:123#key-auth")]
        };
        SetupResolverSuccess(doc);

        // key-auth is in authentication, not keyAgreement — should not be found
        var result = await _dereferencer.DereferenceAsync(
            "did:example:123#key-auth",
            new DidUrlDereferencingOptions { VerificationRelationship = "keyAgreement" });

        result.DereferencingMetadata.Error.Should().Be("notFound");
    }

    // --- Unsupported Accept returns representationNotSupported ---

    [Theory]
    [InlineData("text/plain")]
    [InlineData("application/xml")]
    [InlineData("text/html")]
    public async Task DereferenceAsync_ServiceQuery_UnsupportedAccept_ReturnsRepresentationNotSupported(string accept)
    {
        var doc = CreateDocWithVmAndService();
        SetupResolverSuccess(doc);

        var result = await _dereferencer.DereferenceAsync(
            "did:example:123?service=linked-domain",
            new DidUrlDereferencingOptions { Accept = accept });

        result.DereferencingMetadata.Error.Should().Be("representationNotSupported");
    }

    [Theory]
    [InlineData("text/plain")]
    [InlineData("application/xml")]
    public async Task DereferenceAsync_ServiceTypeQuery_UnsupportedAccept_ReturnsRepresentationNotSupported(string accept)
    {
        var doc = CreateDocWithVmAndService();
        SetupResolverSuccess(doc);

        var result = await _dereferencer.DereferenceAsync(
            "did:example:123?serviceType=LinkedDomains",
            new DidUrlDereferencingOptions { Accept = accept });

        result.DereferencingMetadata.Error.Should().Be("representationNotSupported");
    }

    [Theory]
    [InlineData(DidContentTypes.JsonLd)]
    [InlineData(DidContentTypes.Json)]
    public async Task DereferenceAsync_ServiceQuery_DidDocumentAccept_Succeeds(string accept)
    {
        var doc = CreateDocWithVmAndService();
        SetupResolverSuccess(doc);

        var result = await _dereferencer.DereferenceAsync(
            "did:example:123?service=linked-domain",
            new DidUrlDereferencingOptions { Accept = accept });

        result.DereferencingMetadata.Error.Should().BeNull();
        result.ContentStream.Should().BeOfType<DidDocument>();
    }

    // --- Service ID normalization (relative ↔ absolute) ---

    [Fact]
    public async Task DereferenceAsync_ServiceQuery_RelativeServiceId_MatchesAbsoluteQuery()
    {
        // Service has relative ID "#svc", query uses absolute "did:example:123#svc"
        var doc = new DidDocument
        {
            Id = new Did("did:example:123"),
            Service =
            [
                new Service
                {
                    Id = "#svc",
                    Type = "TestService",
                    ServiceEndpoint = ServiceEndpointValue.FromUri("https://example.com")
                }
            ]
        };
        SetupResolverSuccess(doc);

        var result = await _dereferencer.DereferenceAsync(
            "did:example:123?service=did:example:123%23svc",
            new DidUrlDereferencingOptions { Accept = "text/uri-list" });

        result.DereferencingMetadata.ContentType.Should().Be("text/uri-list");
        result.ContentStream.Should().BeOfType<string>();
    }

    [Fact]
    public async Task DereferenceAsync_ServiceQuery_AbsoluteServiceId_MatchesRelativeQuery()
    {
        // Service has absolute ID, query uses fragment-only "svc"
        var doc = new DidDocument
        {
            Id = new Did("did:example:123"),
            Service =
            [
                new Service
                {
                    Id = "did:example:123#svc",
                    Type = "TestService",
                    ServiceEndpoint = ServiceEndpointValue.FromUri("https://example.com")
                }
            ]
        };
        SetupResolverSuccess(doc);

        var result = await _dereferencer.DereferenceAsync(
            "did:example:123?service=svc",
            new DidUrlDereferencingOptions { Accept = "text/uri-list" });

        result.DereferencingMetadata.ContentType.Should().Be("text/uri-list");
        result.ContentStream.Should().BeOfType<string>();
    }

    [Fact]
    public async Task DereferenceAsync_ServiceQuery_RelativeHashId_MatchesRelativeQuery()
    {
        // Service has relative ID "#svc", query uses fragment-only "svc"
        var doc = new DidDocument
        {
            Id = new Did("did:example:123"),
            Service =
            [
                new Service
                {
                    Id = "#svc",
                    Type = "TestService",
                    ServiceEndpoint = ServiceEndpointValue.FromUri("https://example.com")
                }
            ]
        };
        SetupResolverSuccess(doc);

        var result = await _dereferencer.DereferenceAsync(
            "did:example:123?service=svc",
            new DidUrlDereferencingOptions { Accept = "text/uri-list" });

        result.DereferencingMetadata.ContentType.Should().Be("text/uri-list");
        result.ContentStream.Should().BeOfType<string>();
    }

    // --- serviceType + text/uri-list returns ALL matching services ---

    [Fact]
    public async Task DereferenceAsync_ServiceTypeQuery_UriList_ReturnsAllMatchingServiceUrls()
    {
        var doc = new DidDocument
        {
            Id = new Did("did:example:123"),
            Service =
            [
                new Service
                {
                    Id = "did:example:123#svc-1",
                    Type = "LinkedDomains",
                    ServiceEndpoint = ServiceEndpointValue.FromUri("https://one.example.com")
                },
                new Service
                {
                    Id = "did:example:123#svc-2",
                    Type = "LinkedDomains",
                    ServiceEndpoint = ServiceEndpointValue.FromUri("https://two.example.com")
                },
                new Service
                {
                    Id = "did:example:123#other",
                    Type = "OtherType",
                    ServiceEndpoint = ServiceEndpointValue.FromUri("https://other.example.com")
                }
            ]
        };
        SetupResolverSuccess(doc);

        var result = await _dereferencer.DereferenceAsync(
            "did:example:123?serviceType=LinkedDomains",
            new DidUrlDereferencingOptions { Accept = "text/uri-list" });

        result.DereferencingMetadata.ContentType.Should().Be("text/uri-list");
        var uriList = (string)result.ContentStream!;
        uriList.Should().Contain("https://one.example.com/");
        uriList.Should().Contain("https://two.example.com/");
        uriList.Should().NotContain("https://other.example.com/");
    }

    // --- Fragment guard: endpoint URI with existing fragment ---

    [Fact]
    public async Task DereferenceAsync_ServiceQuery_EndpointWithFragment_DoesNotAppendDidFragment()
    {
        var doc = new DidDocument
        {
            Id = new Did("did:example:123"),
            Service =
            [
                new Service
                {
                    Id = "did:example:123#svc",
                    Type = "TestService",
                    ServiceEndpoint = ServiceEndpointValue.FromUri("https://example.com/page#section")
                }
            ]
        };
        SetupResolverSuccess(doc);

        // DID URL has fragment "extra", but endpoint already has "#section"
        var result = await _dereferencer.DereferenceAsync(
            "did:example:123?service=svc#extra",
            new DidUrlDereferencingOptions { Accept = "text/uri-list" });

        result.DereferencingMetadata.ContentType.Should().Be("text/uri-list");
        var url = (string)result.ContentStream!;
        // The endpoint's own fragment should be preserved, not replaced
        url.Should().Contain("#section");
        url.Should().NotContain("#extra");
    }

    [Fact]
    public async Task DereferenceAsync_ServiceQuery_EndpointWithoutFragment_AppendsDidFragment()
    {
        var doc = new DidDocument
        {
            Id = new Did("did:example:123"),
            Service =
            [
                new Service
                {
                    Id = "did:example:123#svc",
                    Type = "TestService",
                    ServiceEndpoint = ServiceEndpointValue.FromUri("https://example.com/page")
                }
            ]
        };
        SetupResolverSuccess(doc);

        var result = await _dereferencer.DereferenceAsync(
            "did:example:123?service=svc#extra",
            new DidUrlDereferencingOptions { Accept = "text/uri-list" });

        result.DereferencingMetadata.ContentType.Should().Be("text/uri-list");
        var url = (string)result.ContentStream!;
        url.Should().Contain("#extra");
    }

    // --- Embedded verification method dereferencing ---

    [Fact]
    public async Task DereferenceAsync_EmbeddedVm_InAuthentication_ReturnsVm()
    {
        var doc = new DidDocument
        {
            Id = new Did("did:example:123"),
            Authentication =
            [
                VerificationRelationshipEntry.FromEmbedded(new VerificationMethod
                {
                    Id = "did:example:123#embedded-auth",
                    Type = "Multikey",
                    Controller = new Did("did:example:123"),
                    PublicKeyMultibase = "z6Mkexample"
                })
            ]
        };
        SetupResolverSuccess(doc);

        var result = await _dereferencer.DereferenceAsync("did:example:123#embedded-auth");

        result.DereferencingMetadata.Error.Should().BeNull();
        result.ContentStream.Should().BeOfType<VerificationMethod>();
        ((VerificationMethod)result.ContentStream!).Id.Should().Be("did:example:123#embedded-auth");
    }

    [Fact]
    public async Task DereferenceAsync_EmbeddedVm_InKeyAgreement_ReturnsVm()
    {
        var doc = new DidDocument
        {
            Id = new Did("did:example:123"),
            KeyAgreement =
            [
                VerificationRelationshipEntry.FromEmbedded(new VerificationMethod
                {
                    Id = "did:example:123#embedded-agree",
                    Type = "Multikey",
                    Controller = new Did("did:example:123"),
                    PublicKeyMultibase = "z6LSexample"
                })
            ]
        };
        SetupResolverSuccess(doc);

        var result = await _dereferencer.DereferenceAsync("did:example:123#embedded-agree");

        result.DereferencingMetadata.Error.Should().BeNull();
        result.ContentStream.Should().BeOfType<VerificationMethod>();
    }

    [Fact]
    public async Task DereferenceAsync_EmbeddedVm_InAssertionMethod_ReturnsVm()
    {
        var doc = new DidDocument
        {
            Id = new Did("did:example:123"),
            AssertionMethod =
            [
                VerificationRelationshipEntry.FromEmbedded(new VerificationMethod
                {
                    Id = "did:example:123#embedded-assert",
                    Type = "Multikey",
                    Controller = new Did("did:example:123"),
                    PublicKeyMultibase = "z6Mkexample"
                })
            ]
        };
        SetupResolverSuccess(doc);

        var result = await _dereferencer.DereferenceAsync("did:example:123#embedded-assert");

        result.DereferencingMetadata.Error.Should().BeNull();
        result.ContentStream.Should().BeOfType<VerificationMethod>();
    }

    [Fact]
    public async Task DereferenceAsync_EmbeddedVm_InCapabilityInvocation_ReturnsVm()
    {
        var doc = new DidDocument
        {
            Id = new Did("did:example:123"),
            CapabilityInvocation =
            [
                VerificationRelationshipEntry.FromEmbedded(new VerificationMethod
                {
                    Id = "did:example:123#embedded-invoke",
                    Type = "Multikey",
                    Controller = new Did("did:example:123"),
                    PublicKeyMultibase = "z6Mkexample"
                })
            ]
        };
        SetupResolverSuccess(doc);

        var result = await _dereferencer.DereferenceAsync("did:example:123#embedded-invoke");

        result.DereferencingMetadata.Error.Should().BeNull();
        result.ContentStream.Should().BeOfType<VerificationMethod>();
    }

    [Fact]
    public async Task DereferenceAsync_EmbeddedVm_InCapabilityDelegation_ReturnsVm()
    {
        var doc = new DidDocument
        {
            Id = new Did("did:example:123"),
            CapabilityDelegation =
            [
                VerificationRelationshipEntry.FromEmbedded(new VerificationMethod
                {
                    Id = "did:example:123#embedded-delegate",
                    Type = "Multikey",
                    Controller = new Did("did:example:123"),
                    PublicKeyMultibase = "z6Mkexample"
                })
            ]
        };
        SetupResolverSuccess(doc);

        var result = await _dereferencer.DereferenceAsync("did:example:123#embedded-delegate");

        result.DereferencingMetadata.Error.Should().BeNull();
        result.ContentStream.Should().BeOfType<VerificationMethod>();
    }
}
