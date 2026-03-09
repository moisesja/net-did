using System.Text;
using FluentAssertions;
using NetDid.Core.Model;
using NetDid.Core.Serialization;
using NetDid.Method.WebVh;

namespace NetDid.Method.WebVh.Tests;

public class DidWebCompatibilityTests
{
    [Fact]
    public void ToDidWeb_RootDid_Converts()
    {
        var result = DidWebCompatibility.ToDidWeb("did:webvh:QmTest:example.com");
        result.Should().Be("did:web:example.com");
    }

    [Fact]
    public void ToDidWeb_PathDid_Converts()
    {
        var result = DidWebCompatibility.ToDidWeb("did:webvh:QmTest:example.com:users:alice");
        result.Should().Be("did:web:example.com:users:alice");
    }

    [Fact]
    public void GenerateDidJson_ContainsAlsoKnownAs()
    {
        var didWebVh = "did:webvh:QmTest:example.com";
        var doc = new DidDocument
        {
            Id = new Did(didWebVh),
            VerificationMethod =
            [
                new VerificationMethod
                {
                    Id = $"{didWebVh}#key-1",
                    Type = "Multikey",
                    Controller = new Did(didWebVh),
                    PublicKeyMultibase = "z6MkTest"
                }
            ]
        };

        var json = DidWebCompatibility.GenerateDidJson(didWebVh, doc);
        var text = Encoding.UTF8.GetString(json);

        text.Should().Contain("did:web:example.com");
        text.Should().Contain("alsoKnownAs");
        text.Should().Contain(didWebVh);

        // Verify the document is valid JSON
        var parsed = DidDocumentSerializer.Deserialize(text);
        parsed.Id.Value.Should().Be("did:web:example.com");
        parsed.AlsoKnownAs.Should().Contain(didWebVh);
    }
}
