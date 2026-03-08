using System.Text.RegularExpressions;
using FluentAssertions;
using NetDid.Tests.W3CConformance.Infrastructure;

namespace NetDid.Tests.W3CConformance.Resolution;

[Collection("W3C Conformance")]
public partial class ResolutionMetadataTests
{
    private readonly TestDidFactory _factory = new();

    public static TheoryData<string> AllMethods => new() { "did:key", "did:peer" };

    [Theory, MemberData(nameof(AllMethods))]
    [Trait("W3CCategory", "did-resolution")]
    public async Task ContentTypeIsValidMediaType(string method)
    {
        var (did, _) = await _factory.CreateDid(method);
        var resolver = _factory.GetMethod(method);
        var result = await resolver.ResolveAsync(did);

        var ct = result.ResolutionMetadata.ContentType;
        var isValid = ct is not null && MediaTypeRegex().IsMatch(ct);
        ConformanceReportSink.Record(method, "did-resolution", "7.1", "7.1-8",
            "ContentType is a valid media type", isValid);
        isValid.Should().BeTrue();
    }

    [Theory, MemberData(nameof(AllMethods))]
    [Trait("W3CCategory", "did-resolution")]
    public async Task ErrorIsNullOnSuccess(string method)
    {
        var (did, _) = await _factory.CreateDid(method);
        var resolver = _factory.GetMethod(method);
        var result = await resolver.ResolveAsync(did);

        var passed = result.ResolutionMetadata.Error is null;
        ConformanceReportSink.Record(method, "did-resolution", "7.1", "7.1-9",
            "Error is null on successful resolution", passed);
        result.ResolutionMetadata.Error.Should().BeNull();
    }

    [Theory, MemberData(nameof(AllMethods))]
    [Trait("W3CCategory", "did-resolution")]
    public async Task ErrorPropertyIsStringOnFailure(string method)
    {
        var resolver = _factory.GetMethod(method);
        var result = await resolver.ResolveAsync("not-a-did");

        var passed = result.ResolutionMetadata.Error is not null
            && result.ResolutionMetadata.Error.Length > 0;
        ConformanceReportSink.Record(method, "did-resolution", "7.1", "7.1-10",
            "Error property is non-empty string on failure", passed);
        result.ResolutionMetadata.Error.Should().NotBeNullOrEmpty();
    }

    [GeneratedRegex(@"^application/did\+(ld\+)?json$")]
    private static partial Regex MediaTypeRegex();
}
