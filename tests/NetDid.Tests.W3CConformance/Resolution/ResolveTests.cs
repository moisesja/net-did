using FluentAssertions;
using NetDid.Core.Serialization;
using NetDid.Tests.W3CConformance.Infrastructure;

namespace NetDid.Tests.W3CConformance.Resolution;

[Collection("W3C Conformance")]
public class ResolveTests
{
    private readonly TestDidFactory _factory = new();

    public static TheoryData<string> AllMethods => new() { "did:key", "did:peer", "did:webvh" };

    [Theory, MemberData(nameof(AllMethods))]
    [Trait("W3CCategory", "did-resolution")]
    public async Task ValidDid_ReturnsDocument(string method)
    {
        var (did, _) = await _factory.CreateDid(method);
        var resolver = _factory.GetMethod(method);
        var result = await resolver.ResolveAsync(did);

        var passed = result.DidDocument is not null;
        ConformanceReportSink.Record(method, "did-resolution", "7.1", "7.1-1",
            "Valid DID resolution returns non-null document", passed);
        result.DidDocument.Should().NotBeNull();
    }

    [Theory, MemberData(nameof(AllMethods))]
    [Trait("W3CCategory", "did-resolution")]
    public async Task ValidDid_NoError(string method)
    {
        var (did, _) = await _factory.CreateDid(method);
        var resolver = _factory.GetMethod(method);
        var result = await resolver.ResolveAsync(did);

        var passed = result.ResolutionMetadata.Error is null;
        ConformanceReportSink.Record(method, "did-resolution", "7.1", "7.1-2",
            "Valid DID resolution has no error", passed);
        result.ResolutionMetadata.Error.Should().BeNull();
    }

    [Theory, MemberData(nameof(AllMethods))]
    [Trait("W3CCategory", "did-resolution")]
    public async Task ValidDid_ContentTypeSet(string method)
    {
        var (did, _) = await _factory.CreateDid(method);
        var resolver = _factory.GetMethod(method);
        var result = await resolver.ResolveAsync(did);

        var passed = result.ResolutionMetadata.ContentType == DidContentTypes.JsonLd;
        ConformanceReportSink.Record(method, "did-resolution", "7.1", "7.1-3",
            "Resolution metadata contentType is set", passed);
        result.ResolutionMetadata.ContentType.Should().Be(DidContentTypes.JsonLd);
    }

    [Theory, MemberData(nameof(AllMethods))]
    [Trait("W3CCategory", "did-resolution")]
    public async Task ValidDid_DocumentIdMatchesDid(string method)
    {
        var (did, _) = await _factory.CreateDid(method);
        var resolver = _factory.GetMethod(method);
        var result = await resolver.ResolveAsync(did);

        var matches = result.DidDocument!.Id.Value == did;
        ConformanceReportSink.Record(method, "did-resolution", "7.1", "7.1-4",
            "Resolved document id matches requested DID", matches);
        result.DidDocument!.Id.Value.Should().Be(did);
    }

    [Theory, MemberData(nameof(AllMethods))]
    [Trait("W3CCategory", "did-resolution")]
    public async Task InvalidDid_ReturnsError(string method)
    {
        var resolver = _factory.GetMethod(method);
        var result = await resolver.ResolveAsync("not-a-did");

        var passed = result.ResolutionMetadata.Error == "invalidDid"
            && result.DidDocument is null;
        ConformanceReportSink.Record(method, "did-resolution", "7.1", "7.1-5",
            "Invalid DID returns invalidDid error", passed);
        result.ResolutionMetadata.Error.Should().Be("invalidDid");
        result.DidDocument.Should().BeNull();
    }

    [Fact]
    [Trait("W3CCategory", "did-resolution")]
    public async Task MethodNotSupported_ReturnsError()
    {
        var resolver = _factory.CreateCompositeResolver();
        var result = await resolver.ResolveAsync("did:unknown:abc123");

        var passed = result.ResolutionMetadata.Error == "methodNotSupported"
            && result.DidDocument is null;
        ConformanceReportSink.Record("did:key", "did-resolution", "7.1", "7.1-6",
            "Unknown method returns methodNotSupported error", passed);
        ConformanceReportSink.Record("did:peer", "did-resolution", "7.1", "7.1-6",
            "Unknown method returns methodNotSupported error", passed);
        result.ResolutionMetadata.Error.Should().Be("methodNotSupported");
    }

    [Theory, MemberData(nameof(AllMethods))]
    [Trait("W3CCategory", "did-resolution")]
    public async Task NotFound_ReturnsError(string method)
    {
        var resolver = _factory.GetMethod(method);
        // Syntactically valid but nonexistent DID for each method
        var fakeDid = method switch
        {
            "did:key" => "did:key:z6MkinvalidNotARealKeyButValidSyntax",
            "did:peer" => "did:peer:3invalidnumalgo",
            "did:webvh" => "did:webvh:zNotExist:example.com",
            _ => throw new ArgumentException()
        };

        var result = await resolver.ResolveAsync(fakeDid);
        var passed = result.DidDocument is null && result.ResolutionMetadata.Error is not null;
        ConformanceReportSink.Record(method, "did-resolution", "7.1", "7.1-7",
            "Nonexistent DID returns error with null document", passed);
        result.DidDocument.Should().BeNull();
        result.ResolutionMetadata.Error.Should().NotBeNull();
    }
}
