using System.Text.Json;
using FluentAssertions;
using NetDid.Core.Parsing;
using NetDid.Core.Serialization;
using NetDid.Tests.W3CConformance.Infrastructure;

namespace NetDid.Tests.W3CConformance.CoreProperties;

[Collection("W3C Conformance")]
public class ControllerTests
{
    private readonly TestDidFactory _factory = new();

    public static TheoryData<string> MethodsWithController => new() { "did:peer" };

    [Theory, MemberData(nameof(MethodsWithController))]
    [Trait("W3CCategory", "did-core-properties")]
    public async Task ControllerValuesConformToDIDSyntax(string method)
    {
        var (_, doc) = await _factory.CreateDidWithController(method);

        var allValid = doc.Controller?.All(c => DidParser.IsValid(c.Value)) ?? true;
        ConformanceReportSink.Record(method, "did-core-properties", "4", "4-4",
            "Controller values conform to DID syntax", allValid);
        allValid.Should().BeTrue();
    }

    [Theory, MemberData(nameof(MethodsWithController))]
    [Trait("W3CCategory", "did-core-properties")]
    public async Task ControllerSerializesAsStringOrArray(string method)
    {
        var (_, doc) = await _factory.CreateDidWithController(method);

        var json = DidDocumentSerializer.Serialize(doc, DidContentTypes.Json);
        using var parsed = JsonDocument.Parse(json);

        var passed = false;
        if (parsed.RootElement.TryGetProperty("controller", out var ctrl))
        {
            passed = ctrl.ValueKind is JsonValueKind.String or JsonValueKind.Array;
        }
        else
        {
            passed = true; // controller is optional
        }

        ConformanceReportSink.Record(method, "did-core-properties", "4", "4-5",
            "Controller serializes as string or array", passed);
        passed.Should().BeTrue();
    }
}
