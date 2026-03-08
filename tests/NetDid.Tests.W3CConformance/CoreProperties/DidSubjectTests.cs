using FluentAssertions;
using NetDid.Core.Parsing;
using NetDid.Tests.W3CConformance.Infrastructure;

namespace NetDid.Tests.W3CConformance.CoreProperties;

[Collection("W3C Conformance")]
public class DidSubjectTests
{
    private readonly TestDidFactory _factory = new();

    public static TheoryData<string> AllMethods => new() { "did:key", "did:peer" };

    [Theory, MemberData(nameof(AllMethods))]
    [Trait("W3CCategory", "did-core-properties")]
    public async Task DocumentIdIsPresent(string method)
    {
        var (_, doc) = await _factory.CreateDid(method);

        var passed = doc.Id.Value is not null && doc.Id.Value.Length > 0;
        ConformanceReportSink.Record(method, "did-core-properties", "4", "4-1",
            "Document id is present and non-empty", passed);
        doc.Id.Value.Should().NotBeNullOrEmpty();
    }

    [Theory, MemberData(nameof(AllMethods))]
    [Trait("W3CCategory", "did-core-properties")]
    public async Task DocumentIdConformsToDIDSyntax(string method)
    {
        var (_, doc) = await _factory.CreateDid(method);

        var valid = DidParser.IsValid(doc.Id.Value);
        ConformanceReportSink.Record(method, "did-core-properties", "4", "4-2",
            "Document id conforms to DID syntax", valid);
        valid.Should().BeTrue();
    }

    [Theory, MemberData(nameof(AllMethods))]
    [Trait("W3CCategory", "did-core-properties")]
    public async Task DocumentIdMatchesResolvedDid(string method)
    {
        var (did, _) = await _factory.CreateDid(method);
        var resolver = _factory.GetMethod(method);
        var result = await resolver.ResolveAsync(did);

        var matches = result.DidDocument?.Id.Value == did;
        ConformanceReportSink.Record(method, "did-core-properties", "4", "4-3",
            "Document id matches resolved DID", matches);
        result.DidDocument!.Id.Value.Should().Be(did);
    }
}
