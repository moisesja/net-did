using FluentAssertions;
using NetDid.Tests.W3CConformance.Infrastructure;

namespace NetDid.Tests.W3CConformance.Dereferencing;

[Collection("W3C Conformance")]
public class DereferencingMetadataTests
{
    private readonly TestDidFactory _factory = new();

    public static TheoryData<string> AllMethods => new() { "did:key", "did:peer" };

    [Theory, MemberData(nameof(AllMethods))]
    [Trait("W3CCategory", "did-url-dereferencing")]
    public async Task ContentTypeSetOnSuccess(string method)
    {
        var (did, _) = await _factory.CreateDid(method);
        var dereferencer = _factory.CreateDereferencer();

        var result = await dereferencer.DereferenceAsync(did);

        var passed = result.DereferencingMetadata.ContentType is not null;
        ConformanceReportSink.Record(method, "did-url-dereferencing", "7.2", "7.2-10",
            "ContentType is set on successful dereference", passed);
        result.DereferencingMetadata.ContentType.Should().NotBeNull();
    }

    [Theory, MemberData(nameof(AllMethods))]
    [Trait("W3CCategory", "did-url-dereferencing")]
    public async Task ErrorNullOnSuccess(string method)
    {
        var (did, _) = await _factory.CreateDid(method);
        var dereferencer = _factory.CreateDereferencer();

        var result = await dereferencer.DereferenceAsync(did);

        var passed = result.DereferencingMetadata.Error is null;
        ConformanceReportSink.Record(method, "did-url-dereferencing", "7.2", "7.2-11",
            "Error is null on successful dereference", passed);
        result.DereferencingMetadata.Error.Should().BeNull();
    }

    [Fact]
    [Trait("W3CCategory", "did-url-dereferencing")]
    public async Task ErrorSetOnFailure()
    {
        var dereferencer = _factory.CreateDereferencer();

        var result = await dereferencer.DereferenceAsync("not-a-did-url");

        var passed = result.DereferencingMetadata.Error is not null
            && result.DereferencingMetadata.Error.Length > 0;
        ConformanceReportSink.Record("did:key", "did-url-dereferencing", "7.2", "7.2-12",
            "Error is set on failed dereference", passed);
        ConformanceReportSink.Record("did:peer", "did-url-dereferencing", "7.2", "7.2-12",
            "Error is set on failed dereference", passed);
        result.DereferencingMetadata.Error.Should().NotBeNullOrEmpty();
    }
}
