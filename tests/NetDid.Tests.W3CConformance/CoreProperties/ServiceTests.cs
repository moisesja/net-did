using FluentAssertions;
using NetDid.Core.Parsing;
using NetDid.Tests.W3CConformance.Infrastructure;

namespace NetDid.Tests.W3CConformance.CoreProperties;

[Collection("W3C Conformance")]
public class ServiceTests
{
    private readonly TestDidFactory _factory = new();

    public static TheoryData<string> MethodsWithServices => new() { "did:peer" };

    [Theory, MemberData(nameof(MethodsWithServices))]
    [Trait("W3CCategory", "did-core-properties")]
    public async Task ServiceHasRequiredProperties(string method)
    {
        var (_, doc) = await _factory.CreateDidWithServices(method);

        var allValid = doc.Service?.All(s =>
            s.Id is not null && s.Type is not null && s.ServiceEndpoint is not null) ?? true;
        ConformanceReportSink.Record(method, "did-core-properties", "4", "4-20",
            "Service has required properties (id, type, serviceEndpoint)", allValid);
        allValid.Should().BeTrue();
    }

    [Theory, MemberData(nameof(MethodsWithServices))]
    [Trait("W3CCategory", "did-core-properties")]
    public async Task ServiceEndpointIsUriOrMapOrSet(string method)
    {
        var (_, doc) = await _factory.CreateDidWithServices(method);

        var allValid = doc.Service?.All(s =>
        {
            var count = 0;
            if (s.ServiceEndpoint.IsUri) count++;
            if (s.ServiceEndpoint.IsMap) count++;
            if (s.ServiceEndpoint.IsSet) count++;
            return count == 1;
        }) ?? true;
        ConformanceReportSink.Record(method, "did-core-properties", "4", "4-21",
            "ServiceEndpoint is exactly one of URI, map, or set", allValid);
        allValid.Should().BeTrue();
    }

    [Theory, MemberData(nameof(MethodsWithServices))]
    [Trait("W3CCategory", "did-core-properties")]
    public async Task ServiceIdsAreUnique(string method)
    {
        var (_, doc) = await _factory.CreateDidWithServices(method);

        var ids = doc.Service?.Select(s => s.Id).ToList() ?? [];
        var unique = ids.Distinct().Count() == ids.Count;
        ConformanceReportSink.Record(method, "did-core-properties", "4", "4-22",
            "Service IDs are unique within document", unique);
        unique.Should().BeTrue();
    }

    [Theory, MemberData(nameof(MethodsWithServices))]
    [Trait("W3CCategory", "did-core-properties")]
    public async Task ServiceEndpointUriIsValid(string method)
    {
        var (_, doc) = await _factory.CreateDidWithServices(method);

        var allValid = doc.Service?
            .Where(s => s.ServiceEndpoint.IsUri)
            .All(s => Uri.TryCreate(s.ServiceEndpoint.Uri, UriKind.Absolute, out _)) ?? true;
        ConformanceReportSink.Record(method, "did-core-properties", "4", "4-23",
            "Service endpoint URI is valid", allValid);
        allValid.Should().BeTrue();
    }
}
