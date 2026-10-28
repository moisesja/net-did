using FluentAssertions;
using NetDid.Core.Parsing;

namespace NetDid.Core.Tests.Parsing;

public class DidParserTests
{
    [Theory]
    [InlineData("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")]
    [InlineData("did:peer:0z6MkhaXgBZDvotDkL")]
    [InlineData("did:webvh:example.com")]
    [InlineData("did:ethr:0x1:0xabc123")]
    [InlineData("did:example:123")]
    [InlineData("did:a:1")]
    [InlineData("did:example:abc%20def")]       // percent-encoded
    [InlineData("did:example:with.dots")]
    [InlineData("did:example:with-dashes")]
    [InlineData("did:example:with_underscores")]
    public void IsValid_ValidDids_ReturnsTrue(string did)
    {
        DidParser.IsValid(did).Should().BeTrue();
    }

    [Theory]
    [InlineData("")]
    [InlineData("not-a-did")]
    [InlineData("did:")]
    [InlineData("did:key:")]
    [InlineData("did::something")]
    [InlineData("DID:key:abc")]
    [InlineData("did:KEY:abc")]
    [InlineData("did:example:abc#frag")]         // DID URL, not a bare DID
    [InlineData("did:example:abc?query=1")]      // DID URL with query
    [InlineData("did:example:abc/path")]         // DID URL with path
    [InlineData("did:example:abc def")]          // space is illegal
    [InlineData("did:example:abc{brace}")]       // braces are illegal
    [InlineData("did:example:abc<angle>")]       // angle brackets illegal
    [InlineData("did:example:abc;param=val")]    // DID URL with parameters
    public void IsValid_InvalidDids_ReturnsFalse(string did)
    {
        DidParser.IsValid(did).Should().BeFalse();
    }

    [Fact]
    public void IsValid_Null_ReturnsFalse()
    {
        DidParser.IsValid(null!).Should().BeFalse();
    }

    [Theory]
    [InlineData("did:key:z6Mk", "key")]
    [InlineData("did:peer:0z6Mk", "peer")]
    [InlineData("did:webvh:example.com", "webvh")]
    [InlineData("did:ethr:0x1:0xabc", "ethr")]
    public void ExtractMethod_ValidDid_ReturnsMethodName(string did, string expectedMethod)
    {
        DidParser.ExtractMethod(did).Should().Be(expectedMethod);
    }

    [Fact]
    public void ExtractMethod_InvalidDid_ReturnsNull()
    {
        DidParser.ExtractMethod("not-a-did").Should().BeNull();
    }

    [Theory]
    [InlineData("did:key:z6Mk", "z6Mk")]
    [InlineData("did:ethr:0x1:0xabc", "0x1:0xabc")]
    public void ExtractMethodSpecificId_ValidDid_ReturnsId(string did, string expectedId)
    {
        DidParser.ExtractMethodSpecificId(did).Should().Be(expectedId);
    }

    // --- Did value object ---

    [Fact]
    public void Did_RejectsDidUrl()
    {
        var act = () => new NetDid.Core.Model.Did("did:example:abc#frag");
        act.Should().Throw<NetDid.Core.Exceptions.InvalidDidException>();
    }

    [Fact]
    public void Did_RejectsSpaces()
    {
        var act = () => new NetDid.Core.Model.Did("did:example:abc def");
        act.Should().Throw<NetDid.Core.Exceptions.InvalidDidException>();
    }

    // --- DID URL parsing ---

    [Fact]
    public void ParseDidUrl_BareDid_ReturnsParsedUrl()
    {
        var result = DidParser.ParseDidUrl("did:key:z6Mk");

        result.Should().NotBeNull();
        result!.Did.Value.Should().Be("did:key:z6Mk");
        result.Path.Should().BeNull();
        result.Parameters.Should().BeNull();
        result.Query.Should().BeNull();
        result.Fragment.Should().BeNull();
    }

    [Fact]
    public void ParseDidUrl_WithFragment_ParsesCorrectly()
    {
        var result = DidParser.ParseDidUrl("did:key:z6Mk#key-1");

        result.Should().NotBeNull();
        result!.Did.Value.Should().Be("did:key:z6Mk");
        result.Fragment.Should().Be("key-1");
    }

    [Fact]
    public void ParseDidUrl_WithQueryAndFragment_ParsesCorrectly()
    {
        var result = DidParser.ParseDidUrl("did:key:z6Mk?service=hub#fragment");

        result.Should().NotBeNull();
        result!.Query.Should().Be("service=hub");
        result.Fragment.Should().Be("fragment");
    }

    [Fact]
    public void ParseDidUrl_WithPath_ParsesCorrectly()
    {
        var result = DidParser.ParseDidUrl("did:webvh:example.com/path/to/resource");

        result.Should().NotBeNull();
        result!.Path.Should().Be("/path/to/resource");
    }

    [Fact]
    public void ParseDidUrl_WithParameters_ParsesCorrectly()
    {
        var result = DidParser.ParseDidUrl("did:example:abc;service=files");

        result.Should().NotBeNull();
        result!.Did.Value.Should().Be("did:example:abc");
        result.Parameters.Should().Be("service=files");
        result.Query.Should().BeNull();
    }

    [Fact]
    public void ParseDidUrl_WithParametersAndQuery_ParsesCorrectly()
    {
        var result = DidParser.ParseDidUrl("did:example:abc;service=files?version=2#key-1");

        result.Should().NotBeNull();
        result!.Did.Value.Should().Be("did:example:abc");
        result.Parameters.Should().Be("service=files");
        result.Query.Should().Be("version=2");
        result.Fragment.Should().Be("key-1");
    }

    [Fact]
    public void ParseDidUrl_Invalid_ReturnsNull()
    {
        DidParser.ParseDidUrl("not-a-did-url").Should().BeNull();
    }

    [Fact]
    public void ParseDidUrl_FullUrl_ReconstructsCorrectly()
    {
        var url = "did:key:z6Mk?service=hub#key-1";
        var result = DidParser.ParseDidUrl(url);

        result.Should().NotBeNull();
        result!.FullUrl.Should().Be(url);
    }

    [Fact]
    public void ParseDidUrl_WithParameters_ReconstructsCorrectly()
    {
        var url = "did:example:abc;service=files?version=2#key-1";
        var result = DidParser.ParseDidUrl(url);

        result.Should().NotBeNull();
        result!.FullUrl.Should().Be(url);
    }
}
