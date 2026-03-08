using FluentAssertions;
using NetDid.Core.Parsing;
using NetDid.Tests.W3CConformance.Infrastructure;

namespace NetDid.Tests.W3CConformance.DidIdentifier;

[Collection("W3C Conformance")]
public class DidUrlSyntaxTests
{
    private readonly TestDidFactory _factory = new();

    public static TheoryData<string> AllMethods => new() { "did:key", "did:peer" };

    [Theory, MemberData(nameof(AllMethods))]
    [Trait("W3CCategory", "did-identifier")]
    public async Task DidUrlWithFragmentParsesCorrectly(string method)
    {
        var (did, doc) = await _factory.CreateDid(method);
        var vm = doc.VerificationMethod![0];
        var fragmentIndex = vm.Id.IndexOf('#');
        var fragment = fragmentIndex >= 0 ? vm.Id[(fragmentIndex + 1)..] : vm.Id;
        var didUrl = $"{did}#{fragment}";

        var parsed = DidParser.ParseDidUrl(didUrl);
        var success = parsed is not null && parsed.Fragment == fragment;
        ConformanceReportSink.Record(method, "did-identifier", "3.1", "3.1-5",
            "DID URL with fragment parses correctly", success);
        parsed.Should().NotBeNull();
        parsed!.Fragment.Should().Be(fragment);
    }

    [Theory, MemberData(nameof(AllMethods))]
    [Trait("W3CCategory", "did-identifier")]
    public async Task DidUrlWithQueryParsesCorrectly(string method)
    {
        var (did, _) = await _factory.CreateDid(method);
        var didUrl = $"{did}?service=hub";

        var parsed = DidParser.ParseDidUrl(didUrl);
        var success = parsed is not null && parsed.Query == "service=hub";
        ConformanceReportSink.Record(method, "did-identifier", "3.1", "3.1-6",
            "DID URL with query parses correctly", success);
        parsed.Should().NotBeNull();
        parsed!.Query.Should().Be("service=hub");
    }

    [Theory, MemberData(nameof(AllMethods))]
    [Trait("W3CCategory", "did-identifier")]
    public async Task DidUrlWithPathParsesCorrectly(string method)
    {
        var (did, _) = await _factory.CreateDid(method);
        var didUrl = $"{did}/path/to/resource";

        var parsed = DidParser.ParseDidUrl(didUrl);
        var success = parsed is not null && parsed.Path == "/path/to/resource";
        ConformanceReportSink.Record(method, "did-identifier", "3.1", "3.1-7",
            "DID URL with path parses correctly", success);
        parsed.Should().NotBeNull();
        parsed!.Path.Should().Be("/path/to/resource");
    }

    [Theory, MemberData(nameof(AllMethods))]
    [Trait("W3CCategory", "did-identifier")]
    public async Task DidUrlWithParametersParsesCorrectly(string method)
    {
        var (did, _) = await _factory.CreateDid(method);
        var didUrl = $"{did};service=files";

        var parsed = DidParser.ParseDidUrl(didUrl);
        var success = parsed is not null && parsed.Parameters is not null;
        ConformanceReportSink.Record(method, "did-identifier", "3.1", "3.1-8",
            "DID URL with parameters parses correctly", success);
        parsed.Should().NotBeNull();
        parsed!.Parameters.Should().NotBeNull();
    }

    [Fact]
    [Trait("W3CCategory", "did-identifier")]
    public void InvalidDidUrlIsRejected()
    {
        var invalidUrls = new[] { "", "not-a-did-url", "http://example.com" };
        var allRejected = invalidUrls.All(url => DidParser.ParseDidUrl(url) is null);

        ConformanceReportSink.Record("did:key", "did-identifier", "3.1", "3.1-9",
            "Invalid DID URL is rejected", allRejected);
        ConformanceReportSink.Record("did:peer", "did-identifier", "3.1", "3.1-9",
            "Invalid DID URL is rejected", allRejected);
        allRejected.Should().BeTrue();
    }

    [Theory, MemberData(nameof(AllMethods))]
    [Trait("W3CCategory", "did-identifier")]
    public async Task FullUrlReconstructsCorrectly(string method)
    {
        var (did, _) = await _factory.CreateDid(method);
        var didUrl = $"{did}?service=hub#key-1";

        var parsed = DidParser.ParseDidUrl(didUrl);
        var success = parsed is not null && parsed.FullUrl == didUrl;
        ConformanceReportSink.Record(method, "did-identifier", "3.1", "3.1-10",
            "FullUrl reconstructs correctly", success);
        parsed.Should().NotBeNull();
        parsed!.FullUrl.Should().Be(didUrl);
    }
}
