using System.Text;
using FluentAssertions;
using NetDid.Core.Model;
using NetDid.Core.Serialization;
using NetDid.Method.WebVh;

namespace NetDid.Method.WebVh.Tests;

public class DidWebCompatibilityTests
{
    [Fact]
    public void ToDidWeb_RootDid_Converts()
    {
        var result = DidWebCompatibility.ToDidWeb("did:webvh:QmTest:example.com");
        result.Should().Be("did:web:example.com");
    }

    [Fact]
    public void ToDidWeb_PathDid_Converts()
    {
        var result = DidWebCompatibility.ToDidWeb("did:webvh:QmTest:example.com:users:alice");
        result.Should().Be("did:web:example.com:users:alice");
    }

    [Fact]
    public void GenerateDidJson_ContainsAlsoKnownAs()
    {
        var didWebVh = "did:webvh:QmTest:example.com";
        var doc = new DidDocument
        {
            Id = new Did(didWebVh),
            VerificationMethod =
            [
                new VerificationMethod
                {
                    Id = $"{didWebVh}#key-1",
                    Type = "Multikey",
                    Controller = new Did(didWebVh),
                    PublicKeyMultibase = "z6MkTest"
                }
            ]
        };

        var json = DidWebCompatibility.GenerateDidJson(didWebVh, doc);
        var text = Encoding.UTF8.GetString(json);

        text.Should().Contain("did:web:example.com");
        text.Should().Contain("alsoKnownAs");
        text.Should().Contain(didWebVh);

        // Verify the document is valid JSON
        var parsed = DidDocumentSerializer.Deserialize(text);
        parsed.Id.Value.Should().Be("did:web:example.com");
        parsed.AlsoKnownAs.Should().Contain(didWebVh);
    }

    [Fact]
    public void Issue136_GenerateDidJson_AddsImplicitServicesBesideDeploymentPath()
    {
        var didWebVh = "did:webvh:QmTest:example.com:users:alice";
        var document = new DidDocument { Id = new Did(didWebVh) };

        var generated = DidDocumentSerializer.Deserialize(
            Encoding.UTF8.GetString(DidWebCompatibility.GenerateDidJson(didWebVh, document)));

        generated.Service.Should().HaveCount(2);
        var services = generated.Service!;
        services.Single(service => service.Id == "#files")
            .ServiceEndpoint.Uri.Should().Be("https://example.com/users/alice/");
        var whois = services.Single(service => service.Id == "#whois");
        whois.ServiceEndpoint.Uri.Should().Be("https://example.com/users/alice/whois.vp");
        whois.AdditionalProperties!["@context"].GetString().Should()
            .Be("https://identity.foundation/linked-vp/contexts/v1");
    }

    [Fact]
    public void Issue136_GenerateDidJson_ImplicitServicesPreserveEncodedPort()
    {
        var didWebVh = "did:webvh:QmTest:example.com%3A8443";
        var document = new DidDocument { Id = new Did(didWebVh) };

        var generated = DidDocumentSerializer.Deserialize(
            Encoding.UTF8.GetString(DidWebCompatibility.GenerateDidJson(didWebVh, document)));

        var services = generated.Service!;
        services.Single(service => service.Id == "#files")
            .ServiceEndpoint.Uri.Should().Be("https://example.com:8443/");
        services.Single(service => service.Id == "#whois")
            .ServiceEndpoint.Uri.Should().Be("https://example.com:8443/whois.vp");
    }

    [Fact]
    public void Issue136_GenerateDidJson_ExplicitAbsoluteServicesOverrideImplicitDefaults()
    {
        var didWebVh = "did:webvh:QmTest:example.com";
        var document = new DidDocument
        {
            Id = new Did(didWebVh),
            Service =
            [
                new Service
                {
                    Id = $"{didWebVh}#files",
                    Type = "CustomFiles",
                    ServiceEndpoint = ServiceEndpointValue.FromUri("https://cdn.example/resources/")
                },
                new Service
                {
                    Id = $"{didWebVh}#whois",
                    Type = "CustomWhois",
                    ServiceEndpoint = ServiceEndpointValue.FromUri("https://trust.example/profile.json")
                },
                new Service
                {
                    Id = "#messages",
                    Type = "Messaging",
                    ServiceEndpoint = ServiceEndpointValue.FromUri("https://example.com/messages")
                }
            ]
        };

        var generated = DidDocumentSerializer.Deserialize(
            Encoding.UTF8.GetString(DidWebCompatibility.GenerateDidJson(didWebVh, document)));

        generated.Service.Should().HaveCount(3);
        var services = generated.Service!;
        var files = services.Single(service => service.Id.EndsWith("#files", StringComparison.Ordinal));
        files.Id.Should().Be("did:web:example.com#files");
        files.ServiceEndpoint.Uri.Should().Be("https://cdn.example/resources/");
        var whois = services.Single(service => service.Id.EndsWith("#whois", StringComparison.Ordinal));
        whois.Id.Should().Be("did:web:example.com#whois");
        whois.ServiceEndpoint.Uri.Should().Be("https://trust.example/profile.json");
        services.Should().ContainSingle(service => service.Id == "#messages");
    }
}
