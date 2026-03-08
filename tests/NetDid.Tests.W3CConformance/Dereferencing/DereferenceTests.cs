using FluentAssertions;
using NetDid.Core.Model;
using NetDid.Tests.W3CConformance.Infrastructure;

namespace NetDid.Tests.W3CConformance.Dereferencing;

[Collection("W3C Conformance")]
public class DereferenceTests
{
    private readonly TestDidFactory _factory = new();

    public static TheoryData<string> AllMethods => new() { "did:key", "did:peer" };
    public static TheoryData<string> MethodsWithServices => new() { "did:peer" };

    [Theory, MemberData(nameof(AllMethods))]
    [Trait("W3CCategory", "did-url-dereferencing")]
    public async Task Fragment_ReturnsVerificationMethod(string method)
    {
        var (did, doc) = await _factory.CreateDid(method);
        var dereferencer = _factory.CreateDereferencer();

        var vm = doc.VerificationMethod![0];
        var fragment = vm.Id.Contains('#') ? vm.Id[(vm.Id.IndexOf('#') + 1)..] : vm.Id;
        var didUrl = $"{did}#{fragment}";

        var result = await dereferencer.DereferenceAsync(didUrl);

        var passed = result.ContentStream is VerificationMethod;
        ConformanceReportSink.Record(method, "did-url-dereferencing", "7.2", "7.2-1",
            "Fragment dereferencing returns VerificationMethod", passed);
        result.ContentStream.Should().BeOfType<VerificationMethod>();
    }

    [Theory, MemberData(nameof(AllMethods))]
    [Trait("W3CCategory", "did-url-dereferencing")]
    public async Task Fragment_VmIdMatches(string method)
    {
        var (did, doc) = await _factory.CreateDid(method);
        var dereferencer = _factory.CreateDereferencer();

        var vm = doc.VerificationMethod![0];
        var fragment = vm.Id.Contains('#') ? vm.Id[(vm.Id.IndexOf('#') + 1)..] : vm.Id;
        var didUrl = $"{did}#{fragment}";

        var result = await dereferencer.DereferenceAsync(didUrl);
        var returnedVm = result.ContentStream as VerificationMethod;

        var passed = returnedVm?.Id.Contains(fragment) ?? false;
        ConformanceReportSink.Record(method, "did-url-dereferencing", "7.2", "7.2-2",
            "Returned VM id contains the requested fragment", passed);
        returnedVm!.Id.Should().Contain(fragment);
    }

    [Theory, MemberData(nameof(MethodsWithServices))]
    [Trait("W3CCategory", "did-url-dereferencing")]
    public async Task ServiceQuery_ReturnsRedirect(string method)
    {
        var (did, doc) = await _factory.CreateDidWithServices(method);
        var dereferencer = _factory.CreateDereferencer();

        var svc = doc.Service![0];
        var svcFragment = svc.Id.Contains('#') ? svc.Id[(svc.Id.IndexOf('#') + 1)..] : svc.Id;
        var didUrl = $"{did}?service={svcFragment}";

        var result = await dereferencer.DereferenceAsync(didUrl);

        var passed = result.ContentStream is string;
        ConformanceReportSink.Record(method, "did-url-dereferencing", "7.2", "7.2-3",
            "Service query returns redirect URL", passed);
        result.ContentStream.Should().BeOfType<string>();
    }

    [Theory, MemberData(nameof(MethodsWithServices))]
    [Trait("W3CCategory", "did-url-dereferencing")]
    public async Task ServiceQuery_WithRelativeRef(string method)
    {
        var (did, doc) = await _factory.CreateDidWithServices(method);
        var dereferencer = _factory.CreateDereferencer();

        var svc = doc.Service![0];
        var svcFragment = svc.Id.Contains('#') ? svc.Id[(svc.Id.IndexOf('#') + 1)..] : svc.Id;
        var didUrl = $"{did}?service={svcFragment}&relativeRef=%2Fpath";

        var result = await dereferencer.DereferenceAsync(didUrl);

        var url = result.ContentStream as string;
        var passed = url is not null && url.Contains("/path");
        ConformanceReportSink.Record(method, "did-url-dereferencing", "7.2", "7.2-4",
            "Service query with relativeRef constructs correct URL", passed);
        url.Should().Contain("/path");
    }

    [Theory, MemberData(nameof(AllMethods))]
    [Trait("W3CCategory", "did-url-dereferencing")]
    public async Task BareDid_ReturnsFullDocument(string method)
    {
        var (did, _) = await _factory.CreateDid(method);
        var dereferencer = _factory.CreateDereferencer();

        var result = await dereferencer.DereferenceAsync(did);

        var passed = result.ContentStream is DidDocument;
        ConformanceReportSink.Record(method, "did-url-dereferencing", "7.2", "7.2-5",
            "Bare DID dereference returns full document", passed);
        result.ContentStream.Should().BeOfType<DidDocument>();
    }

    [Theory, MemberData(nameof(AllMethods))]
    [Trait("W3CCategory", "did-url-dereferencing")]
    public async Task NonexistentFragment_NotFound(string method)
    {
        var (did, _) = await _factory.CreateDid(method);
        var dereferencer = _factory.CreateDereferencer();

        var result = await dereferencer.DereferenceAsync($"{did}#nonexistent-key-999");

        var passed = result.DereferencingMetadata.Error == "notFound";
        ConformanceReportSink.Record(method, "did-url-dereferencing", "7.2", "7.2-6",
            "Nonexistent fragment returns notFound error", passed);
        result.DereferencingMetadata.Error.Should().Be("notFound");
    }

    [Theory, MemberData(nameof(MethodsWithServices))]
    [Trait("W3CCategory", "did-url-dereferencing")]
    public async Task NonexistentService_NotFound(string method)
    {
        var (did, _) = await _factory.CreateDidWithServices(method);
        var dereferencer = _factory.CreateDereferencer();

        var result = await dereferencer.DereferenceAsync($"{did}?service=nonexistent");

        var passed = result.DereferencingMetadata.Error == "notFound";
        ConformanceReportSink.Record(method, "did-url-dereferencing", "7.2", "7.2-7",
            "Nonexistent service returns notFound error", passed);
        result.DereferencingMetadata.Error.Should().Be("notFound");
    }

    [Fact]
    [Trait("W3CCategory", "did-url-dereferencing")]
    public async Task InvalidDidUrl_Error()
    {
        var dereferencer = _factory.CreateDereferencer();

        var result = await dereferencer.DereferenceAsync("not-a-did-url");

        var passed = result.DereferencingMetadata.Error == "invalidDidUrl";
        ConformanceReportSink.Record("did:key", "did-url-dereferencing", "7.2", "7.2-8",
            "Invalid DID URL returns invalidDidUrl error", passed);
        ConformanceReportSink.Record("did:peer", "did-url-dereferencing", "7.2", "7.2-8",
            "Invalid DID URL returns invalidDidUrl error", passed);
        result.DereferencingMetadata.Error.Should().Be("invalidDidUrl");
    }

    [Theory, MemberData(nameof(MethodsWithServices))]
    [Trait("W3CCategory", "did-url-dereferencing")]
    public async Task ServiceFragment_ReturnsService(string method)
    {
        var (did, doc) = await _factory.CreateDidWithServices(method);
        var dereferencer = _factory.CreateDereferencer();

        var svc = doc.Service![0];
        var svcFragment = svc.Id.Contains('#') ? svc.Id[(svc.Id.IndexOf('#') + 1)..] : svc.Id;

        var result = await dereferencer.DereferenceAsync($"{did}#{svcFragment}");

        var passed = result.ContentStream is Service;
        ConformanceReportSink.Record(method, "did-url-dereferencing", "7.2", "7.2-9",
            "Service fragment returns Service object", passed);
        result.ContentStream.Should().BeOfType<Service>();
    }
}
