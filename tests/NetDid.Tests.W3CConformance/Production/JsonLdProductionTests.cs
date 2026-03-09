using System.Text.Json;
using FluentAssertions;
using NetDid.Core.Serialization;
using NetDid.Tests.W3CConformance.Infrastructure;

namespace NetDid.Tests.W3CConformance.Production;

[Collection("W3C Conformance")]
public class JsonLdProductionTests
{
    private readonly TestDidFactory _factory = new();

    public static TheoryData<string> AllMethods => new() { "did:key", "did:peer", "did:webvh" };

    [Theory, MemberData(nameof(AllMethods))]
    [Trait("W3CCategory", "did-production")]
    public async Task IncludesContext(string method)
    {
        var (_, doc) = await _factory.CreateDid(method);

        var json = DidDocumentSerializer.Serialize(doc, DidContentTypes.JsonLd);
        using var parsed = JsonDocument.Parse(json);

        var hasContext = parsed.RootElement.TryGetProperty("@context", out _);
        ConformanceReportSink.Record(method, "did-production", "6", "6-7",
            "JSON-LD production includes @context", hasContext);
        hasContext.Should().BeTrue();
    }

    [Theory, MemberData(nameof(AllMethods))]
    [Trait("W3CCategory", "did-production")]
    public async Task FirstContextIsW3CDidV1(string method)
    {
        var (_, doc) = await _factory.CreateDid(method);

        var json = DidDocumentSerializer.Serialize(doc, DidContentTypes.JsonLd);
        using var parsed = JsonDocument.Parse(json);

        var context = parsed.RootElement.GetProperty("@context");
        string? firstContext = null;
        if (context.ValueKind == JsonValueKind.Array)
            firstContext = context[0].GetString();
        else if (context.ValueKind == JsonValueKind.String)
            firstContext = context.GetString();

        var correct = firstContext == "https://www.w3.org/ns/did/v1";
        ConformanceReportSink.Record(method, "did-production", "6", "6-8",
            "First @context is https://www.w3.org/ns/did/v1", correct);
        correct.Should().BeTrue();
    }

    [Theory, MemberData(nameof(AllMethods))]
    [Trait("W3CCategory", "did-production")]
    public async Task ContextIncludesMethodSpecificEntries(string method)
    {
        var (_, doc) = await _factory.CreateDid(method);

        var json = DidDocumentSerializer.Serialize(doc, DidContentTypes.JsonLd);
        using var parsed = JsonDocument.Parse(json);

        var context = parsed.RootElement.GetProperty("@context");
        var contextValues = context.EnumerateArray().Select(e => e.GetString()).ToList();

        // Default VMs are Multikey, so multikey context should be present
        var hasMultikey = contextValues.Contains("https://w3id.org/security/multikey/v1");
        ConformanceReportSink.Record(method, "did-production", "6", "6-9",
            "Context includes method-specific entries (Multikey)", hasMultikey);
        hasMultikey.Should().BeTrue();
    }

    [Theory, MemberData(nameof(AllMethods))]
    [Trait("W3CCategory", "did-production")]
    public async Task RoundTripsViaDeserialization(string method)
    {
        var (_, doc) = await _factory.CreateDid(method);

        var json = DidDocumentSerializer.Serialize(doc, DidContentTypes.JsonLd);
        var restored = DidDocumentSerializer.Deserialize(json, DidContentTypes.JsonLd);

        var matches = restored.Id.Value == doc.Id.Value
            && restored.VerificationMethod?.Count == doc.VerificationMethod?.Count;
        ConformanceReportSink.Record(method, "did-production", "6", "6-10",
            "JSON-LD round-trips via deserialization", matches);
        matches.Should().BeTrue();
    }

    [Fact]
    [Trait("W3CCategory", "did-production")]
    public void MissingContextRejectedOnConsumption()
    {
        var json = """{"id":"did:example:123"}""";

        var passed = false;
        try
        {
            DidDocumentSerializer.Deserialize(json, DidContentTypes.JsonLd);
        }
        catch (JsonException)
        {
            passed = true;
        }

        ConformanceReportSink.Record("did:key", "did-production", "6", "6-11",
            "Missing @context rejected on JSON-LD consumption", passed);
        ConformanceReportSink.Record("did:peer", "did-production", "6", "6-11",
            "Missing @context rejected on JSON-LD consumption", passed);
        passed.Should().BeTrue();
    }

    [Fact]
    [Trait("W3CCategory", "did-production")]
    public void WrongFirstContextRejectedOnConsumption()
    {
        var json = """{"@context":"https://wrong.example.com","id":"did:example:123"}""";

        var passed = false;
        try
        {
            DidDocumentSerializer.Deserialize(json, DidContentTypes.JsonLd);
        }
        catch (JsonException)
        {
            passed = true;
        }

        ConformanceReportSink.Record("did:key", "did-production", "6", "6-12",
            "Wrong first @context rejected on JSON-LD consumption", passed);
        ConformanceReportSink.Record("did:peer", "did-production", "6", "6-12",
            "Wrong first @context rejected on JSON-LD consumption", passed);
        passed.Should().BeTrue();
    }
}
