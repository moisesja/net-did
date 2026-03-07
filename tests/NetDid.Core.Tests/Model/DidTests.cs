using FluentAssertions;
using NetDid.Core.Exceptions;
using NetDid.Core.Model;

namespace NetDid.Core.Tests.Model;

public class DidTests
{
    [Fact]
    public void Constructor_ValidDid_SetsProperties()
    {
        var did = new Did("did:key:z6Mk");

        did.Value.Should().Be("did:key:z6Mk");
        did.Method.Should().Be("key");
        did.MethodSpecificId.Should().Be("z6Mk");
    }

    [Fact]
    public void Constructor_InvalidDid_ThrowsInvalidDidException()
    {
        var act = () => new Did("not-a-did");
        act.Should().Throw<InvalidDidException>();
    }

    [Fact]
    public void ImplicitConversionFromString_Works()
    {
        Did did = "did:key:z6Mk";
        did.Value.Should().Be("did:key:z6Mk");
    }

    [Fact]
    public void ImplicitConversionToString_Works()
    {
        var did = new Did("did:key:z6Mk");
        string value = did;
        value.Should().Be("did:key:z6Mk");
    }

    [Fact]
    public void ToString_ReturnsValue()
    {
        var did = new Did("did:key:z6Mk");
        did.ToString().Should().Be("did:key:z6Mk");
    }

    [Fact]
    public void Equality_SameValue_AreEqual()
    {
        var did1 = new Did("did:key:z6Mk");
        var did2 = new Did("did:key:z6Mk");
        did1.Should().Be(did2);
    }

    [Fact]
    public void Equality_DifferentValue_AreNotEqual()
    {
        var did1 = new Did("did:key:z6Mk1");
        var did2 = new Did("did:key:z6Mk2");
        did1.Should().NotBe(did2);
    }
}
