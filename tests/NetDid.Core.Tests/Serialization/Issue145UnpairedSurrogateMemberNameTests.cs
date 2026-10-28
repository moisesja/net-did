using System.Text.Json;
using AwesomeAssertions;
using NetDid.Core.Serialization;

namespace NetDid.Core.Tests.Serialization;

/// <summary>
/// Issue #145: an unpaired UTF-16 surrogate escape in a JSON member NAME. The duplicate-member
/// guard parses with <c>AllowDuplicateProperties = false</c>, which decodes every member name to
/// compare it, so a lone surrogate threw a raw <see cref="InvalidOperationException"/> out of the
/// public consumption API. Every other malformed-input case on this boundary (duplicate members,
/// a malformed controller, a lone surrogate in a VALUE) throws <see cref="JsonException"/>.
/// </summary>
public class Issue145UnpairedSurrogateMemberNameTests
{
    private const string Document = """
    {
      "id": "did:example:123",
      "verificationMethod": [{
        "id": "did:example:123#key-1",
        "type": "Multikey",
        "controller": "did:example:123",
        "publicKeyMultibase": "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
      }],
      "service": [{
        "id": "did:example:123#svc",
        "type": "Example",
        "serviceEndpoint": "https://example.com"
      }]
    }
    """;

    private static string Doctor(string find, string replace)
    {
        Document.Should().Contain(find, "the substitution anchor must exist");
        var index = Document.IndexOf(find, StringComparison.Ordinal);
        return Document[..index] + replace + Document[(index + find.Length)..];
    }

    public static TheoryData<string, string> SurrogateMemberNames => new()
    {
        // Document root.
        { "\"id\": \"did:example:123\",", "\"\\uD800\": 1, \"id\": \"did:example:123\"," },
        // A verification method object (nested inside the verificationMethod array).
        { "\"type\": \"Multikey\",", "\"\\uD800\": 1, \"type\": \"Multikey\"," },
        // A service object (nested inside the service array).
        { "\"type\": \"Example\",", "\"\\uD800\": 1, \"type\": \"Example\"," },
        // A deeper extension object.
        { "\"id\": \"did:example:123\",", "\"x-ext\": {\"a\": {\"\\uD800\": 1}}, \"id\": \"did:example:123\"," },
        // A lone LOW surrogate takes a different BCL decode path.
        { "\"id\": \"did:example:123\",", "\"\\uDC00\": 1, \"id\": \"did:example:123\"," },
    };

    #region Issue145_SurrogateMemberName_ThrowsJsonException

    [Fact]
    public void Issue145_Baseline_DocumentDeserializes()
    {
        var act = () => DidDocumentSerializer.Deserialize(Document);
        act.Should().NotThrow();
    }

    [Theory]
    [MemberData(nameof(SurrogateMemberNames))]
    public void Issue145_SurrogateMemberName_StringOverload_ThrowsJsonException(string find, string replace)
    {
        var json = Doctor(find, replace);

        var act = () => DidDocumentSerializer.Deserialize(json);

        act.Should().Throw<JsonException>()
            .WithInnerException<InvalidOperationException>();
    }

    [Theory]
    [MemberData(nameof(SurrogateMemberNames))]
    public void Issue145_SurrogateMemberName_Utf8Overload_ThrowsJsonException(string find, string replace)
    {
        var utf8 = System.Text.Encoding.UTF8.GetBytes(Doctor(find, replace));

        var act = () => DidDocumentSerializer.Deserialize(utf8.AsSpan());

        act.Should().Throw<JsonException>()
            .WithInnerException<InvalidOperationException>();
    }

    [Theory]
    [MemberData(nameof(SurrogateMemberNames))]
    public void Issue145_SurrogateMemberName_IncompleteVmPath_ThrowsJsonException(string find, string replace)
    {
        // The did:peer:4 template path shares the same duplicate-member guard.
        var json = Doctor(find, replace);

        var act = () => DidDocumentSerializer.DeserializeAllowingIncompleteVerificationMethods(json);

        act.Should().Throw<JsonException>()
            .WithInnerException<InvalidOperationException>();
    }

    [Fact]
    public void Issue145_SurrogateMemberName_MessageDoesNotEchoTheName()
    {
        var json = Doctor("\"id\": \"did:example:123\",", "\"\\uD800\": 1, \"id\": \"did:example:123\",");

        var act = () => DidDocumentSerializer.Deserialize(json);

        act.Should().Throw<JsonException>()
            .Which.Message.Should().NotContain("\uD800").And.NotContain("\\uD800");
    }

    [Fact]
    public void Issue145_Control_SurrogateValue_ThrowsJsonException()
    {
        // The same escape in a VALUE position already surfaced as JsonException.
        var json = Doctor("\"type\": \"Multikey\",", "\"type\": \"\\uD800\",");

        var act = () => DidDocumentSerializer.Deserialize(json);

        act.Should().Throw<JsonException>();
    }

    #endregion
}
