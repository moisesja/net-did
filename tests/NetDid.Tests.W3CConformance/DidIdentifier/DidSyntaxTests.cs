using System.Text.RegularExpressions;
using FluentAssertions;
using NetDid.Core.Parsing;
using NetDid.Tests.W3CConformance.Infrastructure;

namespace NetDid.Tests.W3CConformance.DidIdentifier;

[Collection("W3C Conformance")]
public class DidSyntaxTests
{
    private readonly TestDidFactory _factory = new();

    public static TheoryData<string> AllMethods => new() { "did:key", "did:peer" };

    [Theory, MemberData(nameof(AllMethods))]
    [Trait("W3CCategory", "did-identifier")]
    public async Task DidConformsToAbnfSyntax(string method)
    {
        var (did, _) = await _factory.CreateDid(method);

        var isValid = DidParser.IsValid(did);
        ConformanceReportSink.Record(method, "did-identifier", "3.1", "3.1-1",
            "DID conforms to ABNF syntax", isValid);
        isValid.Should().BeTrue();
    }

    [Theory, MemberData(nameof(AllMethods))]
    [Trait("W3CCategory", "did-identifier")]
    public async Task MethodNameIsLowercaseAlphanumeric(string method)
    {
        var (did, _) = await _factory.CreateDid(method);
        var parsed = new Did(did);

        var matches = Regex.IsMatch(parsed.Method, "^[a-z0-9]+$");
        ConformanceReportSink.Record(method, "did-identifier", "3.1", "3.1-2",
            "Method name is lowercase alphanumeric", matches);
        matches.Should().BeTrue();
    }

    [Theory, MemberData(nameof(AllMethods))]
    [Trait("W3CCategory", "did-identifier")]
    public async Task MethodSpecificIdContainsOnlyValidChars(string method)
    {
        var (did, _) = await _factory.CreateDid(method);
        var parsed = new Did(did);

        // W3C idchar = ALPHA / DIGIT / "." / "-" / "_" / pct-encoded, plus ":"
        var matches = Regex.IsMatch(parsed.MethodSpecificId,
            @"^([A-Za-z0-9._\-]|%[0-9A-Fa-f]{2}|:)+$");
        ConformanceReportSink.Record(method, "did-identifier", "3.1", "3.1-3",
            "Method-specific-id contains only valid characters", matches);
        matches.Should().BeTrue();
    }

    [Fact]
    [Trait("W3CCategory", "did-identifier")]
    public void InvalidDidSyntaxIsRejected()
    {
        var invalidDids = new[]
        {
            "", "not-a-did", "did:", "did:key:", "did::something",
            "DID:key:abc", "did:KEY:abc", "did:example:abc def",
            "did:example:abc{brace}", "did:example:abc<angle>",
            "did:example:abc#fragment", "did:example:abc?query=1"
        };

        var allRejected = true;
        foreach (var invalid in invalidDids)
        {
            if (DidParser.IsValid(invalid))
            {
                allRejected = false;
                break;
            }
        }

        ConformanceReportSink.Record("did:key", "did-identifier", "3.1", "3.1-4",
            "Invalid DID syntax is rejected", allRejected);
        ConformanceReportSink.Record("did:peer", "did-identifier", "3.1", "3.1-4",
            "Invalid DID syntax is rejected", allRejected);
        allRejected.Should().BeTrue();
    }
}
