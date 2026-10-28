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

    #endregion

    #region Issue145_RawSurrogateAndIllFormedUtf8 (adversarial review)

    // HIGH/LOW stand for raw lone surrogate chars, substituted at run time: a lone surrogate
    // cannot survive in an attribute argument, which is stored as UTF-8.
    [Theory]
    [InlineData("\"HIGH\": 1, \"id\": \"did:example:123\",")]
    [InlineData("\"x-ext\": {\"LOW\": 1}, \"id\": \"did:example:123\",")]
    [InlineData("\"x-ext\": \"HIGH\", \"id\": \"did:example:123\",")]
    public void Issue145_StringOverload_RawLoneSurrogateChar_ThrowsJsonException(string replace)
    {
        // An unescaped lone surrogate char cannot be transcoded to UTF-8, which System.Text.Json
        // reports as ArgumentException; the boundary's documented error is JsonException.
        var json = Doctor("\"id\": \"did:example:123\",",
            replace.Replace("HIGH", "\uD800").Replace("LOW", "\uDC00"));

        var act = () => DidDocumentSerializer.Deserialize(json);

        act.Should().Throw<JsonException>().WithInnerException<ArgumentException>();
    }

    [Fact]
    public void Issue145_StringOverload_Null_StillThrowsArgumentNullException()
    {
        var act = () => DidDocumentSerializer.Deserialize((string)null!);

        act.Should().Throw<ArgumentNullException>();
    }

    // Splices raw bytes into a nested extension member name: {"x-ext": {"<bytes>": 1}, ...}.
    private static byte[] WithNestedExtensionName(params byte[][] names)
    {
        var members = string.Join(", ", names.Select((_, i) => $"\"@{i}@\": {i}"));
        var template = System.Text.Encoding.UTF8.GetBytes(
            Doctor("\"id\": \"did:example:123\",", $"\"x-ext\": {{{members}}}, \"id\": \"did:example:123\","));
        for (var i = 0; i < names.Length; i++)
        {
            var marker = System.Text.Encoding.UTF8.GetBytes($"@{i}@");
            var at = template.AsSpan().IndexOf(marker);
            template = [.. template[..at], .. names[i], .. template[(at + marker.Length)..]];
        }
        return template;
    }

    public static TheoryData<byte[][]> IllFormedUtf8Names => new()
    {
        // WTF-8 encoding of the lone surrogate U+D800.
        new[] { new byte[] { 0xED, 0xA0, 0x80 } },
        // Two distinct ill-formed names that both decode to U+FFFD: the raw-byte duplicate check
        // sees two members, but every decoder sees one name twice.
        new[] { new byte[] { 0xFF }, new byte[] { 0xFE } },
    };

    [Theory]
    [MemberData(nameof(IllFormedUtf8Names))]
    public void Issue145_Utf8Overload_IllFormedNestedName_ThrowsJsonException(byte[][] names)
    {
        var utf8 = WithNestedExtensionName(names);

        var act = () => DidDocumentSerializer.Deserialize(utf8.AsSpan());

        act.Should().Throw<JsonException>();
    }

    [Fact]
    public void Issue145_Control_WellFormedNonAsciiUtf8_StillDeserializes()
    {
        // Positive control: real non-ASCII text (U+00E9 and the 4-byte U+1F600) in a nested name.
        var utf8 = WithNestedExtensionName(
            System.Text.Encoding.UTF8.GetBytes("café"),
            System.Text.Encoding.UTF8.GetBytes("\U0001F600"));

        var act = () => DidDocumentSerializer.Deserialize(utf8.AsSpan());

        act.Should().NotThrow();
    }

    [Fact]
    public void Issue145_Control_EscapedSurrogatePairName_StillDeserializes()
    {
        var json = Doctor("\"id\": \"did:example:123\",", "\"\\uD83D\\uDE00\": 1, \"id\": \"did:example:123\",");

        var utf8 = System.Text.Encoding.UTF8.GetBytes(json);
        var fromString = () => DidDocumentSerializer.Deserialize(json);
        var fromUtf8 = () => DidDocumentSerializer.Deserialize(utf8.AsSpan());

        fromString.Should().NotThrow();
        fromUtf8.Should().NotThrow();
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
