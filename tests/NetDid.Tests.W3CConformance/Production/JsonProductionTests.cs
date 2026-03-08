using System.Text.Json;
using FluentAssertions;
using NetDid.Core.Serialization;
using NetDid.Tests.W3CConformance.Infrastructure;

namespace NetDid.Tests.W3CConformance.Production;

[Collection("W3C Conformance")]
public class JsonProductionTests
{
    private readonly TestDidFactory _factory = new();

    public static TheoryData<string> AllMethods => new() { "did:key", "did:peer" };

    [Theory, MemberData(nameof(AllMethods))]
    [Trait("W3CCategory", "did-production")]
    public async Task ProducesValidJson(string method)
    {
        var (_, doc) = await _factory.CreateDid(method);

        var json = DidDocumentSerializer.Serialize(doc, DidContentTypes.Json);
        var passed = false;
        try
        {
            using var _ = JsonDocument.Parse(json);
            passed = true;
        }
        catch { }

        ConformanceReportSink.Record(method, "did-production", "6", "6-1",
            "JSON production produces valid JSON", passed);
        passed.Should().BeTrue();
    }

    [Theory, MemberData(nameof(AllMethods))]
    [Trait("W3CCategory", "did-production")]
    public async Task OmitsContext(string method)
    {
        var (_, doc) = await _factory.CreateDid(method);

        var json = DidDocumentSerializer.Serialize(doc, DidContentTypes.Json);
        using var parsed = JsonDocument.Parse(json);

        var noContext = !parsed.RootElement.TryGetProperty("@context", out _);
        ConformanceReportSink.Record(method, "did-production", "6", "6-2",
            "JSON production omits @context", noContext);
        noContext.Should().BeTrue();
    }

    [Theory, MemberData(nameof(AllMethods))]
    [Trait("W3CCategory", "did-production")]
    public async Task IdSerializedAsString(string method)
    {
        var (_, doc) = await _factory.CreateDid(method);

        var json = DidDocumentSerializer.Serialize(doc, DidContentTypes.Json);
        using var parsed = JsonDocument.Parse(json);

        var isString = parsed.RootElement.GetProperty("id").ValueKind == JsonValueKind.String;
        ConformanceReportSink.Record(method, "did-production", "6", "6-3",
            "id serialized as string", isString);
        isString.Should().BeTrue();
    }

    [Theory, MemberData(nameof(AllMethods))]
    [Trait("W3CCategory", "did-production")]
    public async Task VerificationMethodSerializedAsArray(string method)
    {
        var (_, doc) = await _factory.CreateDid(method);

        var json = DidDocumentSerializer.Serialize(doc, DidContentTypes.Json);
        using var parsed = JsonDocument.Parse(json);

        var isArray = parsed.RootElement.TryGetProperty("verificationMethod", out var vm)
            && vm.ValueKind == JsonValueKind.Array;
        ConformanceReportSink.Record(method, "did-production", "6", "6-4",
            "verificationMethod serialized as array", isArray);
        isArray.Should().BeTrue();
    }

    [Theory, MemberData(nameof(AllMethods))]
    [Trait("W3CCategory", "did-production")]
    public async Task NullPropertiesOmitted(string method)
    {
        var (_, doc) = await _factory.CreateDid(method);

        var json = DidDocumentSerializer.Serialize(doc, DidContentTypes.Json);
        using var parsed = JsonDocument.Parse(json);

        // alsoKnownAs is null by default — should not appear
        var omitted = !parsed.RootElement.TryGetProperty("alsoKnownAs", out _);
        ConformanceReportSink.Record(method, "did-production", "6", "6-5",
            "Null properties omitted from JSON", omitted);
        omitted.Should().BeTrue();
    }

    [Theory, MemberData(nameof(AllMethods))]
    [Trait("W3CCategory", "did-production")]
    public async Task RelationshipReferenceSerializedAsString(string method)
    {
        var (_, doc) = await _factory.CreateDid(method);

        var json = DidDocumentSerializer.Serialize(doc, DidContentTypes.Json);
        using var parsed = JsonDocument.Parse(json);

        // Check authentication if present — references should be strings
        var passed = true;
        if (parsed.RootElement.TryGetProperty("authentication", out var auth))
        {
            foreach (var entry in auth.EnumerateArray())
            {
                if (entry.ValueKind == JsonValueKind.String)
                    continue;
                if (entry.ValueKind == JsonValueKind.Object)
                    continue; // Embedded VM is also valid
                passed = false;
            }
        }

        ConformanceReportSink.Record(method, "did-production", "6", "6-6",
            "Relationship references serialized as strings", passed);
        passed.Should().BeTrue();
    }
}
