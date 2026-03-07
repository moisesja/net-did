using System.Text.Json;
using FluentAssertions;
using Microsoft.IdentityModel.Tokens;
using NetDid.Core.Model;
using NetDid.Core.Serialization;

namespace NetDid.Core.Tests.Serialization;

public class DidDocumentSerializerTests
{
    private static DidDocument CreateMinimalDocument() => new()
    {
        Id = new Did("did:example:123")
    };

    private static DidDocument CreateFullDocument() => new()
    {
        Id = new Did("did:example:123"),
        AlsoKnownAs = new List<string> { "https://example.com/user/123" },
        Controller = new List<Did> { new("did:example:controller") },
        VerificationMethod = new List<VerificationMethod>
        {
            new()
            {
                Id = "did:example:123#key-1",
                Type = "Multikey",
                Controller = new Did("did:example:123"),
                PublicKeyMultibase = "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
            }
        },
        Authentication = new List<VerificationRelationshipEntry>
        {
            VerificationRelationshipEntry.FromReference("did:example:123#key-1")
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

    [Fact]
    public void Serialize_JsonLd_IncludesContext()
    {
        var doc = CreateMinimalDocument();
        var json = DidDocumentSerializer.Serialize(doc, DidContentTypes.JsonLd);
        using var parsed = JsonDocument.Parse(json);

        parsed.RootElement.TryGetProperty("@context", out _).Should().BeTrue();
        parsed.RootElement.GetProperty("id").GetString().Should().Be("did:example:123");
    }

    [Fact]
    public void Serialize_Json_OmitsContext()
    {
        var doc = CreateMinimalDocument();
        var json = DidDocumentSerializer.Serialize(doc, DidContentTypes.Json);
        using var parsed = JsonDocument.Parse(json);

        parsed.RootElement.TryGetProperty("@context", out _).Should().BeFalse();
        parsed.RootElement.GetProperty("id").GetString().Should().Be("did:example:123");
    }

    [Fact]
    public void Serialize_JsonLd_MultikeyVm_IncludesMultikeyContext()
    {
        var doc = CreateFullDocument();
        var json = DidDocumentSerializer.Serialize(doc, DidContentTypes.JsonLd);
        using var parsed = JsonDocument.Parse(json);

        var context = parsed.RootElement.GetProperty("@context");
        context.ValueKind.Should().Be(JsonValueKind.Array);

        var contextValues = context.EnumerateArray().Select(e => e.GetString()).ToList();
        contextValues.Should().Contain("https://www.w3.org/ns/did/v1");
        contextValues.Should().Contain("https://w3id.org/security/multikey/v1");
    }

    [Fact]
    public void Serialize_JsonLd_JsonWebKeyVm_IncludesJwsContext()
    {
        var doc = new DidDocument
        {
            Id = new Did("did:example:123"),
            VerificationMethod = new List<VerificationMethod>
            {
                new()
                {
                    Id = "did:example:123#key-1",
                    Type = "JsonWebKey2020",
                    Controller = new Did("did:example:123"),
                    PublicKeyJwk = new JsonWebKey { Kty = "OKP", Crv = "Ed25519", X = "abc" }
                }
            }
        };

        var json = DidDocumentSerializer.Serialize(doc, DidContentTypes.JsonLd);
        json.Should().Contain("https://w3id.org/security/suites/jws-2020/v1");
    }

    [Fact]
    public void Serialize_Controller_SingleValue_SerializedAsString()
    {
        var doc = new DidDocument
        {
            Id = new Did("did:example:123"),
            Controller = new List<Did> { new("did:example:controller") }
        };

        var json = DidDocumentSerializer.Serialize(doc, DidContentTypes.Json);
        using var parsed = JsonDocument.Parse(json);

        var controller = parsed.RootElement.GetProperty("controller");
        controller.ValueKind.Should().Be(JsonValueKind.String);
        controller.GetString().Should().Be("did:example:controller");
    }

    [Fact]
    public void Serialize_Controller_MultipleValues_SerializedAsArray()
    {
        var doc = new DidDocument
        {
            Id = new Did("did:example:123"),
            Controller = new List<Did>
            {
                new("did:example:c1"),
                new("did:example:c2")
            }
        };

        var json = DidDocumentSerializer.Serialize(doc, DidContentTypes.Json);
        using var parsed = JsonDocument.Parse(json);

        var controller = parsed.RootElement.GetProperty("controller");
        controller.ValueKind.Should().Be(JsonValueKind.Array);
        controller.GetArrayLength().Should().Be(2);
    }

    [Fact]
    public void Serialize_VerificationRelationship_ReferenceAsString()
    {
        var doc = CreateFullDocument();
        var json = DidDocumentSerializer.Serialize(doc, DidContentTypes.Json);
        using var parsed = JsonDocument.Parse(json);

        var auth = parsed.RootElement.GetProperty("authentication");
        auth[0].ValueKind.Should().Be(JsonValueKind.String);
        auth[0].GetString().Should().Be("did:example:123#key-1");
    }

    [Fact]
    public void Serialize_VerificationRelationship_EmbeddedAsObject()
    {
        var vm = new VerificationMethod
        {
            Id = "did:example:123#embedded",
            Type = "Multikey",
            Controller = new Did("did:example:123"),
            PublicKeyMultibase = "z6Mk..."
        };

        var doc = new DidDocument
        {
            Id = new Did("did:example:123"),
            Authentication = new List<VerificationRelationshipEntry>
            {
                VerificationRelationshipEntry.FromEmbedded(vm)
            }
        };

        var json = DidDocumentSerializer.Serialize(doc, DidContentTypes.Json);
        using var parsed = JsonDocument.Parse(json);

        var auth = parsed.RootElement.GetProperty("authentication");
        auth[0].ValueKind.Should().Be(JsonValueKind.Object);
        auth[0].GetProperty("id").GetString().Should().Be("did:example:123#embedded");
    }

    [Fact]
    public void Serialize_ServiceEndpoint_UriAsString()
    {
        var doc = CreateFullDocument();
        var json = DidDocumentSerializer.Serialize(doc, DidContentTypes.Json);
        using var parsed = JsonDocument.Parse(json);

        var svc = parsed.RootElement.GetProperty("service")[0];
        svc.GetProperty("serviceEndpoint").ValueKind.Should().Be(JsonValueKind.String);
    }

    [Fact]
    public void Serialize_ServiceEndpoint_MapAsObject()
    {
        var doc = new DidDocument
        {
            Id = new Did("did:example:123"),
            Service = new List<Service>
            {
                new()
                {
                    Id = "did:example:123#svc",
                    Type = "DIDComm",
                    ServiceEndpoint = ServiceEndpointValue.FromMap(new Dictionary<string, JsonElement>
                    {
                        ["uri"] = JsonDocument.Parse("\"https://example.com\"").RootElement.Clone()
                    })
                }
            }
        };

        var json = DidDocumentSerializer.Serialize(doc, DidContentTypes.Json);
        using var parsed = JsonDocument.Parse(json);

        parsed.RootElement.GetProperty("service")[0]
            .GetProperty("serviceEndpoint").ValueKind.Should().Be(JsonValueKind.Object);
    }

    [Fact]
    public void Deserialize_MinimalDocument_RoundTrips()
    {
        var json = """{"id":"did:example:123"}""";
        var doc = DidDocumentSerializer.Deserialize(json);

        doc.Id.Value.Should().Be("did:example:123");
    }

    [Fact]
    public void Deserialize_FullDocument_RoundTrips()
    {
        var original = CreateFullDocument();
        var json = DidDocumentSerializer.Serialize(original, DidContentTypes.Json);
        var restored = DidDocumentSerializer.Deserialize(json);

        restored.Id.Should().Be(original.Id);
        restored.AlsoKnownAs.Should().BeEquivalentTo(original.AlsoKnownAs);
        restored.Controller.Should().HaveCount(1);
        restored.VerificationMethod.Should().HaveCount(1);
        restored.Authentication.Should().HaveCount(1);
        restored.Service.Should().HaveCount(1);
    }

    [Fact]
    public void Deserialize_JsonLd_ValidContext_Succeeds()
    {
        var json = """{"@context":"https://www.w3.org/ns/did/v1","id":"did:example:123"}""";
        var doc = DidDocumentSerializer.Deserialize(json, DidContentTypes.JsonLd);

        doc.Id.Value.Should().Be("did:example:123");
    }

    [Fact]
    public void Deserialize_JsonLd_MissingContext_Throws()
    {
        var json = """{"id":"did:example:123"}""";
        var act = () => DidDocumentSerializer.Deserialize(json, DidContentTypes.JsonLd);

        act.Should().Throw<JsonException>().WithMessage("*@context*");
    }

    [Fact]
    public void Deserialize_JsonLd_WrongFirstContext_Throws()
    {
        var json = """{"@context":"https://wrong.example.com","id":"did:example:123"}""";
        var act = () => DidDocumentSerializer.Deserialize(json, DidContentTypes.JsonLd);

        act.Should().Throw<JsonException>();
    }

    [Fact]
    public void Deserialize_Json_NoContextRequired()
    {
        var json = """{"id":"did:example:123"}""";
        var doc = DidDocumentSerializer.Deserialize(json, DidContentTypes.Json);

        doc.Id.Value.Should().Be("did:example:123");
        doc.Context.Should().BeNull();
    }

    [Fact]
    public void Deserialize_ControllerAsString_ParsedAsSingleList()
    {
        var json = """{"id":"did:example:123","controller":"did:example:c1"}""";
        var doc = DidDocumentSerializer.Deserialize(json);

        doc.Controller.Should().HaveCount(1);
        doc.Controller![0].Value.Should().Be("did:example:c1");
    }

    [Fact]
    public void Deserialize_ControllerAsArray_ParsedAsList()
    {
        var json = """{"id":"did:example:123","controller":["did:example:c1","did:example:c2"]}""";
        var doc = DidDocumentSerializer.Deserialize(json);

        doc.Controller.Should().HaveCount(2);
    }

    [Fact]
    public void Deserialize_EmbeddedVerificationRelationship_ParsedCorrectly()
    {
        var json = """
        {
            "id": "did:example:123",
            "authentication": [
                "did:example:123#ref",
                {
                    "id": "did:example:123#embedded",
                    "type": "Multikey",
                    "controller": "did:example:123",
                    "publicKeyMultibase": "z6Mk..."
                }
            ]
        }
        """;

        var doc = DidDocumentSerializer.Deserialize(json);

        doc.Authentication.Should().HaveCount(2);
        doc.Authentication![0].IsReference.Should().BeTrue();
        doc.Authentication[0].Reference.Should().Be("did:example:123#ref");
        doc.Authentication[1].IsReference.Should().BeFalse();
        doc.Authentication[1].EmbeddedMethod!.Id.Should().Be("did:example:123#embedded");
    }

    [Fact]
    public void Deserialize_AdditionalProperties_Preserved()
    {
        var json = """{"id":"did:example:123","customProp":"customValue"}""";
        var doc = DidDocumentSerializer.Deserialize(json);

        doc.AdditionalProperties.Should().ContainKey("customProp");
        doc.AdditionalProperties!["customProp"].GetString().Should().Be("customValue");
    }

    [Fact]
    public void SerializeToUtf8_ProducesValidUtf8()
    {
        var doc = CreateMinimalDocument();
        var bytes = DidDocumentSerializer.SerializeToUtf8(doc, DidContentTypes.Json);

        var json = System.Text.Encoding.UTF8.GetString(bytes);
        json.Should().Contain("did:example:123");
    }

    [Fact]
    public void RoundTrip_JsonLd_FullDocument()
    {
        var original = CreateFullDocument();
        var json = DidDocumentSerializer.Serialize(original, DidContentTypes.JsonLd);
        var restored = DidDocumentSerializer.Deserialize(json, DidContentTypes.JsonLd);

        restored.Id.Should().Be(original.Id);
        restored.VerificationMethod.Should().HaveCount(1);
        restored.VerificationMethod![0].PublicKeyMultibase
            .Should().Be("z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");
    }
}
