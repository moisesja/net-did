using System.Text.Json;
using AwesomeAssertions;
using Microsoft.IdentityModel.Tokens;
using NetDid.Core.Model;
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

    #region Issue145_UndecodedValuesAndJwk (adversarial review, pre-existing)

    private const string PublicKeyMultibase =
        "\"publicKeyMultibase\": \"z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK\"";

    // Extension values are kept as raw JsonElements and were never decoded on the way in, so a
    // lone surrogate there deserialized fine and only failed later, in Serialize. {0} is the
    // string value placed at each position.
    public static TheoryData<string, string> ExtensionValuePositions => new()
    {
        // Document-level extension member.
        { "\"id\": \"did:example:123\",", "\"x-ext\": \"{0}\", \"id\": \"did:example:123\"," },
        // Verification-method extension member.
        { "\"type\": \"Multikey\",", "\"x-ext\": \"{0}\", \"type\": \"Multikey\"," },
        // Service extension member, nested in an array.
        { "\"type\": \"Example\",", "\"x-ext\": [\"{0}\"], \"type\": \"Example\"," },
        // A serviceEndpoint map value.
        { "\"serviceEndpoint\": \"https://example.com\"", "\"serviceEndpoint\": {\"uri\": \"{0}\"}" },
        // An unknown publicKeyJwk member (the JWK model never surfaces it).
        { PublicKeyMultibase, "\"publicKeyJwk\": {\"kty\": \"OKP\", \"crv\": \"Ed25519\", \"x\": \"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\", \"x-ext\": \"{0}\"}" },
    };

    [Theory]
    [MemberData(nameof(ExtensionValuePositions))]
    public void Issue145_LoneSurrogateExtensionValue_ThrowsJsonException(string find, string replace)
    {
        var json = Doctor(find, replace.Replace("{0}", "\\uD800"));
        var utf8 = System.Text.Encoding.UTF8.GetBytes(json);

        var fromString = () => DidDocumentSerializer.Deserialize(json);
        var fromUtf8 = () => DidDocumentSerializer.Deserialize(utf8.AsSpan());

        fromString.Should().Throw<JsonException>();
        fromUtf8.Should().Throw<JsonException>();
    }

    [Theory]
    [MemberData(nameof(ExtensionValuePositions))]
    public void Issue145_Control_EscapedSurrogatePairExtensionValue_RoundTrips(string find, string replace)
    {
        // Positive control: a well-formed pair still deserializes and survives a round-trip.
        var json = Doctor(find, replace.Replace("{0}", "\\uD83D\\uDE00"));

        var doc = DidDocumentSerializer.Deserialize(json);
        var again = DidDocumentSerializer.Deserialize(DidDocumentSerializer.Serialize(doc));

        again.Id.Should().Be(doc.Id);
    }

    [Theory]
    [InlineData("\"x\": 5")]
    [InlineData("\"x\": \"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\", \"alg\": \"\\uD800\"")]
    [InlineData("\"x\": \"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\", \"kid\": \"\\uD800\"")]
    public void Issue145_MalformedPublicKeyJwk_ThrowsJsonException(string members)
    {
        // IdentityModel's JsonWebKey reports a malformed key as ArgumentException (IDX10805);
        // the consumption boundary's documented error is JsonException.
        var json = Doctor(PublicKeyMultibase,
            "\"publicKeyJwk\": {\"kty\": \"OKP\", \"crv\": \"Ed25519\", " + members + "}");

        var act = () => DidDocumentSerializer.Deserialize(json);

        act.Should().Throw<JsonException>();
    }

    [Fact]
    public void Issue145_Control_WellFormedPublicKeyJwk_StillDeserializes()
    {
        var json = Doctor(PublicKeyMultibase,
            "\"publicKeyJwk\": {\"kty\": \"OKP\", \"crv\": \"Ed25519\", " +
            "\"x\": \"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}");

        var doc = DidDocumentSerializer.Deserialize(json);

        doc.VerificationMethod![0].PublicKeyJwk!.X.Should().Be("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo");
    }

    #endregion

    #region Issue145_MalformedShapes (round-3 adversarial review, pre-existing)

    private const string RootAnchor = "\"id\": \"did:example:123\",";

    // Shapes DID Core does not allow. Before the fix each one either leaked a raw
    // KeyNotFoundException / InvalidOperationException / ArgumentException from the public
    // Deserialize, or was accepted and later crashed Serialize (NullReferenceException, or an
    // "object cycle" for nested serviceEndpoint sets).
    public static TheoryData<string, string> MalformedShapes => new()
    {
        { "\"type\": \"Multikey\",", "\"type\": null," },
        { "\"type\": \"Multikey\",", "" },
        { "\"id\": \"did:example:123#key-1\",", "\"id\": 5," },
        { "\"id\": \"did:example:123#key-1\",", "" },
        { "\"type\": \"Example\",", "\"type\": null," },
        { "\"verificationMethod\": [{", "\"verificationMethod\": [null, {" },
        { "\"service\": [{", "\"service\": [null, {" },
        { RootAnchor, "\"verificationMethod\": {}, " + RootAnchor },
        { RootAnchor, "\"alsoKnownAs\": \"https://a.example\", " + RootAnchor },
        { RootAnchor, "\"alsoKnownAs\": [1], " + RootAnchor },
        { RootAnchor, "\"alsoKnownAs\": [null], " + RootAnchor },
        { RootAnchor, "\"authentication\": [\"\"], " + RootAnchor },
        { RootAnchor, "\"authentication\": [null], " + RootAnchor },
        { RootAnchor, "\"authentication\": [5], " + RootAnchor },
        { RootAnchor, "\"authentication\": [{\"id\": \"did:example:123#k2\", \"type\": null, " +
            "\"controller\": \"did:example:123\"}], " + RootAnchor },
        { "\"serviceEndpoint\": \"https://example.com\"", "\"x-ext\": 1" },
        { "\"serviceEndpoint\": \"https://example.com\"", "\"serviceEndpoint\": \"\"" },
        { "\"serviceEndpoint\": \"https://example.com\"", "\"serviceEndpoint\": []" },
        { "\"serviceEndpoint\": \"https://example.com\"", "\"serviceEndpoint\": [[\"https://a.example\"]]" },
        { "\"serviceEndpoint\": \"https://example.com\"", "\"serviceEndpoint\": [5]" },
    };

    [Theory]
    [MemberData(nameof(MalformedShapes))]
    public void Issue145_MalformedShape_ThrowsJsonException(string find, string replace)
    {
        var json = Doctor(find, replace);
        var utf8 = System.Text.Encoding.UTF8.GetBytes(json);

        var fromString = () => DidDocumentSerializer.Deserialize(json);
        var fromUtf8 = () => DidDocumentSerializer.Deserialize(utf8.AsSpan());

        fromString.Should().Throw<JsonException>();
        fromUtf8.Should().Throw<JsonException>();
    }

    [Theory]
    [InlineData("\"serviceEndpoint\": {\"uri\": \"https://a.example\", \"accept\": [\"didcomm/v2\"]}")]
    [InlineData("\"serviceEndpoint\": [\"https://a.example\", {\"uri\": \"https://b.example\"}]")]
    public void Issue145_Control_ConformantServiceEndpoint_RoundTrips(string endpoint)
    {
        var json = Doctor("\"serviceEndpoint\": \"https://example.com\"", endpoint);

        var doc = DidDocumentSerializer.Deserialize(json);
        var again = DidDocumentSerializer.Deserialize(DidDocumentSerializer.Serialize(doc));

        again.Service![0].ServiceEndpoint.IsUri.Should().BeFalse();
    }

    #endregion

    #region Issue145_WriterRejectsUnpairedSurrogates (round-4, writer side)

    private const string Did = "did:example:123";

    // Utf8JsonWriter silently replaces an unpaired surrogate with U+FFFD, so Serialize published
    // bytes that differ from the caller's model while reporting success. Each position below is a
    // string the serializer writes; {text} is placed there.
    public static TheoryData<string> WritePositions => new()
    {
        "vm-id", "vm-type", "vm-multibase", "vm-jwk-x", "vm-blockchain", "vm-extension-key",
        "service-id", "service-type", "endpoint-uri", "endpoint-map-key", "endpoint-set-uri",
        "service-extension-key", "also-known-as", "context", "document-extension-key",
        "relationship-reference",
    };

    private static DidDocument DocumentWith(string position, string text)
    {
        var extension = JsonSerializer.SerializeToElement(1);
        var vm = new VerificationMethod
        {
            Id = position == "vm-id" ? $"{Did}#{text}" : $"{Did}#key-1",
            Type = position == "vm-type" ? text : "Multikey",
            Controller = new Did(Did),
            PublicKeyMultibase = position == "vm-multibase" ? text
                : position is "vm-jwk-x" or "vm-blockchain" ? null
                : "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
            PublicKeyJwk = position == "vm-jwk-x"
                ? new JsonWebKey { Kty = "OKP", Crv = "Ed25519", X = text }
                : null,
            BlockchainAccountId = position == "vm-blockchain" ? text : null,
            AdditionalProperties = position == "vm-extension-key"
                ? new Dictionary<string, JsonElement> { [text] = extension }
                : null,
        };
        var endpoint = position switch
        {
            "endpoint-uri" => ServiceEndpointValue.FromUri(text),
            "endpoint-map-key" => ServiceEndpointValue.FromMap(
                new Dictionary<string, JsonElement> { [text] = extension }),
            "endpoint-set-uri" => ServiceEndpointValue.FromSet(
                [ServiceEndpointValue.FromUri("https://a.example"), ServiceEndpointValue.FromUri(text)]),
            _ => ServiceEndpointValue.FromUri("https://example.com"),
        };
        var service = new Service
        {
            Id = position == "service-id" ? $"{Did}#{text}" : $"{Did}#svc",
            Type = position == "service-type" ? text : "Example",
            ServiceEndpoint = endpoint,
            AdditionalProperties = position == "service-extension-key"
                ? new Dictionary<string, JsonElement> { [text] = extension }
                : null,
        };
        return new DidDocument
        {
            Id = new Did(Did),
            AlsoKnownAs = position == "also-known-as" ? [text] : null,
            Context = position == "context" ? ["https://www.w3.org/ns/did/v1", text] : null,
            VerificationMethod = [vm],
            Authentication = position == "relationship-reference"
                ? [VerificationRelationshipEntry.FromReference($"{Did}#{text}")]
                : null,
            Service = [service],
            AdditionalProperties = position == "document-extension-key"
                ? new Dictionary<string, JsonElement> { [text] = extension }
                : null,
        };
    }

    [Theory]
    [MemberData(nameof(WritePositions))]
    public void Issue145_Serialize_UnpairedSurrogate_ThrowsArgumentException(string position)
    {
        var doc = DocumentWith(position, "x\uD800y");

        var jsonLd = () => DidDocumentSerializer.Serialize(doc);
        var json = () => DidDocumentSerializer.Serialize(doc, DidContentTypes.Json);
        var utf8 = () => DidDocumentSerializer.SerializeToUtf8(doc);
        var incomplete = () => DidDocumentSerializer.SerializeAllowingIncompleteVerificationMethods(
            doc, DidContentTypes.JsonLd);

        jsonLd.Should().Throw<ArgumentException>()
            .Which.Message.Should().NotContain("\uD800", "the offending text is never echoed");
        if (position == "context")
            json.Should().NotThrow("plain JSON omits @context, so nothing is altered");
        else
            json.Should().Throw<ArgumentException>();
        utf8.Should().Throw<ArgumentException>();
        incomplete.Should().Throw<ArgumentException>();
    }

    [Theory]
    [MemberData(nameof(WritePositions))]
    public void Issue145_Control_SurrogatePair_SerializesFaithfully(string position)
    {
        const string text = "x\uD83D\uDE00y";
        var doc = DocumentWith(position, text);

        var serialized = DidDocumentSerializer.Serialize(doc);

        serialized.Should().NotContain("\\uFFFD").And.NotContain("\uFFFD",
            "a well-formed surrogate pair must be written as itself, not replaced");
    }

    #endregion
}
