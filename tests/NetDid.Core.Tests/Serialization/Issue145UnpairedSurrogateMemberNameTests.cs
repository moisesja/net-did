using System.Text.Json;
using AwesomeAssertions;
using Microsoft.IdentityModel.Tokens;
using NetDid.Core.Model;
using NetDid.Core.Parsing;
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

    // Free-text positions only: an id, reference, endpoint or alsoKnownAs value must be an
    // RFC 3986 URI (DID Core §3.2, §5.1.3, §5.2, §5.4), where raw non-ASCII is not allowed at all;
    // Issue145_Serialize_RawNonAsciiInUriPosition_ThrowsArgumentException pins those.
    public static TheoryData<string> FreeTextPositions => new()
    {
        "vm-type", "vm-multibase", "vm-jwk-x", "vm-blockchain", "vm-extension-key",
        "service-type", "endpoint-map-key", "service-extension-key", "context", "document-extension-key",
    };

    [Theory]
    [MemberData(nameof(FreeTextPositions))]
    public void Issue145_Control_SurrogatePair_SerializesFaithfully(string position)
    {
        const string text = "x\uD83D\uDE00y";
        var doc = DocumentWith(position, text);

        var serialized = DidDocumentSerializer.Serialize(doc);

        serialized.Should().NotContain("\\uFFFD").And.NotContain("\uFFFD",
            "a well-formed surrogate pair must be written as itself, not replaced");
    }

    #endregion

    #region Issue145_PrReview1 (PR #149 review 5684631583 + final adversarial pass)

    // ── Nested serviceEndpoint sets: the model now rejects the shape DID Core §5.4 forbids ──

    [Fact]
    public void Issue145_FromSet_NestedSet_ThrowsArgumentException()
    {
        var act = () => ServiceEndpointValue.FromSet(
            [ServiceEndpointValue.FromSet([ServiceEndpointValue.FromUri("https://example.com")])]);

        act.Should().Throw<ArgumentException>(
            "a set may hold only strings and maps (W3C DID Core §5.4); the reader rejects a nested set, " +
            "so a producer must never be able to build one");
    }

    [Fact]
    public void Issue145_FromSet_NullEntry_ThrowsArgumentException()
    {
        var act = () => ServiceEndpointValue.FromSet([ServiceEndpointValue.FromUri("https://a.example"), null!]);

        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Issue145_FromSet_SnapshotsItsInput()
    {
        var source = new List<ServiceEndpointValue> { ServiceEndpointValue.FromUri("https://a.example") };
        var value = ServiceEndpointValue.FromSet(source);

        source.Add(ServiceEndpointValue.FromUri("https://b.example"));

        value.Set.Should().HaveCount(1, "a validated set must not change after construction");
    }

    [Fact]
    public void Issue145_Control_FlatMixedSet_RoundTrips()
    {
        var doc = new DidDocument
        {
            Id = new Did(Did),
            Service =
            [
                new Service
                {
                    Id = $"{Did}#svc",
                    Type = "Example",
                    ServiceEndpoint = ServiceEndpointValue.FromSet(
                    [
                        ServiceEndpointValue.FromUri("https://a.example"),
                        ServiceEndpointValue.FromMap(new Dictionary<string, JsonElement>
                        {
                            ["uri"] = JsonSerializer.SerializeToElement("https://b.example")
                        })
                    ])
                }
            ]
        };

        var again = DidDocumentSerializer.Deserialize(DidDocumentSerializer.Serialize(doc));

        again.Service![0].ServiceEndpoint.Set.Should().HaveCount(2);
        again.Service[0].ServiceEndpoint.Set![1].IsMap.Should().BeTrue();
    }

    // ── Caller JsonElement contents: Utf8JsonWriter replaced ill-formed text with U+FFFD ──

    private static JsonElement ElementFromBytes(byte[] utf8)
    {
        using var document = JsonDocument.Parse(utf8);
        return document.RootElement.Clone();
    }

    private static byte[] Bytes(string before, byte[] raw, string after) =>
        [.. System.Text.Encoding.ASCII.GetBytes(before), .. raw, .. System.Text.Encoding.ASCII.GetBytes(after)];

    private static JsonElement HostileElement(string kind) => kind switch
    {
        // A WTF-8 lone surrogate inside a string value (System.Text.Json does not validate it on parse).
        "wtf8-value" => ElementFromBytes(Bytes("\"a", [0xED, 0xA0, 0x80], "b\"")),
        // An ill-formed byte inside a nested member name.
        "wtf8-name" => ElementFromBytes(Bytes("{\"ok\":{\"", [0xFF], "\":1}}")),
        // An escaped lone surrogate.
        "escaped-surrogate" => ElementFromBytes(System.Text.Encoding.ASCII.GetBytes("[\"a\\uD800b\"]")),
        // A well-formed escaped surrogate pair (positive control).
        "surrogate-pair" => ElementFromBytes(System.Text.Encoding.ASCII.GetBytes("{\"k\\uD83D\\uDE00\":\"v\\uD83D\\uDE00\"}")),
        _ => throw new ArgumentOutOfRangeException(nameof(kind)),
    };

    public static TheoryData<string, string> ElementPositions
    {
        get
        {
            var data = new TheoryData<string, string>();
            foreach (var position in new[] { "document-extension", "vm-extension", "service-extension", "context", "endpoint-map" })
                foreach (var kind in new[] { "wtf8-value", "wtf8-name", "escaped-surrogate" })
                    data.Add(position, kind);
            return data;
        }
    }

    private static DidDocument DocumentWithElement(string position, JsonElement element)
    {
        var vm = new VerificationMethod
        {
            Id = $"{Did}#key-1",
            Type = "Multikey",
            Controller = new Did(Did),
            PublicKeyMultibase = "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
            AdditionalProperties = position == "vm-extension"
                ? new Dictionary<string, JsonElement> { ["x-ext"] = element }
                : null,
        };
        var service = new Service
        {
            Id = $"{Did}#svc",
            Type = "Example",
            ServiceEndpoint = position == "endpoint-map"
                ? ServiceEndpointValue.FromMap(new Dictionary<string, JsonElement> { ["uri"] = element })
                : ServiceEndpointValue.FromUri("https://example.com"),
            AdditionalProperties = position == "service-extension"
                ? new Dictionary<string, JsonElement> { ["x-ext"] = element }
                : null,
        };
        return new DidDocument
        {
            Id = new Did(Did),
            Context = position == "context" ? ["https://www.w3.org/ns/did/v1", element] : null,
            VerificationMethod = [vm],
            Service = [service],
            AdditionalProperties = position == "document-extension"
                ? new Dictionary<string, JsonElement> { ["x-ext"] = element }
                : null,
        };
    }

    [Theory]
    [MemberData(nameof(ElementPositions))]
    public void Issue145_Serialize_UndecodableJsonElement_ThrowsArgumentException(string position, string kind)
    {
        var doc = DocumentWithElement(position, HostileElement(kind));

        var jsonLd = () => DidDocumentSerializer.Serialize(doc);
        var utf8 = () => DidDocumentSerializer.SerializeToUtf8(doc);
        var incomplete = () => DidDocumentSerializer.SerializeAllowingIncompleteVerificationMethods(
            doc, DidContentTypes.JsonLd);
        var json = () => DidDocumentSerializer.Serialize(doc, DidContentTypes.Json);

        jsonLd.Should().Throw<ArgumentException>();
        utf8.Should().Throw<ArgumentException>();
        incomplete.Should().Throw<ArgumentException>();
        if (position == "context")
            json.Should().NotThrow("plain JSON omits @context, so nothing is written or altered");
        else
            json.Should().Throw<ArgumentException>();
    }

    [Theory]
    [InlineData("document-extension")]
    [InlineData("vm-extension")]
    [InlineData("service-extension")]
    [InlineData("context")]
    [InlineData("endpoint-map")]
    public void Issue145_Control_SurrogatePairJsonElement_SerializesFaithfully(string position)
    {
        var serialized = DidDocumentSerializer.Serialize(
            DocumentWithElement(position, HostileElement("surrogate-pair")));

        serialized.Should().NotContain("\\uFFFD").And.NotContain("\uFFFD");
    }

    // ── @context entries of other types were written via ToString() ──

    [Fact]
    public void Issue145_Serialize_ContextEntryOfOtherType_ThrowsArgumentException()
    {
        // ToString() on a JsonObject both replaces lone surrogates before any check and writes the
        // object as a string. Only strings and JsonElement values are representable.
        var doc = new DidDocument
        {
            Id = new Did(Did),
            Context = ["https://www.w3.org/ns/did/v1", new System.Text.Json.Nodes.JsonObject { ["@vocab"] = "https://e.example/" }]
        };

        var act = () => DidDocumentSerializer.Serialize(doc);

        act.Should().Throw<ArgumentException>();
    }

    // ── Reserved names in Service.AdditionalProperties produced a duplicate member ──

    [Theory]
    [InlineData("id")]
    [InlineData("type")]
    [InlineData("serviceEndpoint")]
    public void Issue145_Serialize_ServiceExtensionWithReservedName_ThrowsArgumentException(string key)
    {
        var doc = new DidDocument
        {
            Id = new Did(Did),
            Service =
            [
                new Service
                {
                    Id = $"{Did}#svc",
                    Type = "Example",
                    ServiceEndpoint = ServiceEndpointValue.FromUri("https://example.com"),
                    AdditionalProperties = new Dictionary<string, JsonElement>
                    {
                        [key] = JsonSerializer.SerializeToElement("https://evil.example")
                    }
                }
            ]
        };

        var act = () => DidDocumentSerializer.Serialize(doc);

        act.Should().Throw<ArgumentException>(
            "a duplicate member makes output NetDid's own Deserialize rejects (issue #121)");
    }

    #endregion

    #region Issue145_PrReview1_FinalPass (non-blocking adversarial pass on the review fixes)

    // F1: RequireDecodable recursed once per nesting level, so a deeply nested caller JsonElement
    // overflowed the stack and killed the process, where Serialize used to throw a catchable
    // exception. Run on a thread with a fixed 1 MB stack so the outcome does not depend on the host.
    private static Exception? RunOnSmallStack(Action action)
    {
        Exception? caught = null;
        var thread = new Thread(() =>
        {
            try { action(); }
            catch (Exception ex) { caught = ex; }
        }, maxStackSize: 1 << 20);
        thread.Start();
        thread.Join();
        return caught;
    }

    private static JsonElement DeeplyNestedArray(int depth)
    {
        var json = new string('[', depth) + new string(']', depth);
        using var document = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = depth + 1 });
        return document.RootElement.Clone();
    }

    [Fact]
    public void Issue145_RequireDecodable_DeeplyNestedElement_DoesNotOverflowTheStack()
    {
        var element = DeeplyNestedArray(20_000);

        var caught = RunOnSmallStack(() => Utf16Text.RequireDecodable(element));

        caught.Should().BeNull("a well-formed element is decodable at any depth");
    }

    [Fact]
    public void Issue145_Serialize_DeeplyNestedElement_ThrowsCatchably()
    {
        var doc = new DidDocument
        {
            Id = new Did(Did),
            AdditionalProperties = new Dictionary<string, JsonElement> { ["x-ext"] = DeeplyNestedArray(20_000) }
        };

        var caught = RunOnSmallStack(() => DidDocumentSerializer.Serialize(doc));

        caught.Should().BeOfType<JsonException>("the writer's depth limit applies, as before the review fixes");
    }

    // F2: FromSet stored the copied array itself, so the validated set could still be changed.
    [Fact]
    public void Issue145_FromSet_SetIsNotWritable()
    {
        var value = ServiceEndpointValue.FromSet([ServiceEndpointValue.FromUri("https://a.example")]);
        var nested = ServiceEndpointValue.FromSet([ServiceEndpointValue.FromUri("https://b.example")]);

        if (value.Set is IList<ServiceEndpointValue> list)
        {
            var act = () => list[0] = nested;
            act.Should().Throw<NotSupportedException>();
        }

        value.Set![0].IsUri.Should().BeTrue();
    }

    // A caller list whose CopyTo keeps the destination array, so it can rewrite it later.
    private sealed class RetainingList(ServiceEndpointValue item)
        : IReadOnlyList<ServiceEndpointValue>, ICollection<ServiceEndpointValue>
    {
        public ServiceEndpointValue[]? Retained { get; private set; }
        public ServiceEndpointValue this[int index] => item;
        public int Count => 1;
        public bool IsReadOnly => true;
        public void CopyTo(ServiceEndpointValue[] array, int arrayIndex)
        {
            array[arrayIndex] = item;
            Retained = array;
        }
        public IEnumerator<ServiceEndpointValue> GetEnumerator() { yield return item; }
        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();
        public void Add(ServiceEndpointValue value) => throw new NotSupportedException();
        public void Clear() => throw new NotSupportedException();
        public bool Contains(ServiceEndpointValue value) => value == item;
        public bool Remove(ServiceEndpointValue value) => throw new NotSupportedException();
    }

    [Fact]
    public void Issue145_FromSet_CallerCannotRewriteTheSnapshot()
    {
        var source = new RetainingList(ServiceEndpointValue.FromUri("https://a.example"));
        var value = ServiceEndpointValue.FromSet(source);

        if (source.Retained is { } retained)
            retained[0] = ServiceEndpointValue.FromSet([ServiceEndpointValue.FromUri("https://b.example")]);

        value.Set![0].IsUri.Should().BeTrue("the library fills its own copy");
    }

    [Fact]
    public void Issue145_Serialize_NestedSetBuiltBypassingTheFactory_ThrowsArgumentException()
    {
        // The writer also enforces the shape (the reviewer asked for a production-boundary check),
        // so a nested set built by reflection still cannot be published.
        var ctor = typeof(ServiceEndpointValue).GetConstructor(
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance,
            [typeof(string), typeof(IReadOnlyDictionary<string, JsonElement>), typeof(IReadOnlyList<ServiceEndpointValue>)])!;
        var inner = ServiceEndpointValue.FromSet([ServiceEndpointValue.FromUri("https://a.example")]);
        var nested = (ServiceEndpointValue)ctor.Invoke([null, null, new[] { inner }]);
        var doc = new DidDocument
        {
            Id = new Did(Did),
            Service = [new Service { Id = $"{Did}#svc", Type = "Example", ServiceEndpoint = nested }]
        };

        var act = () => DidDocumentSerializer.Serialize(doc);

        act.Should().Throw<ArgumentException>();
    }

    // F3: default(JsonElement) escaped as a raw InvalidOperationException from WriteTo.
    [Theory]
    [InlineData("document-extension")]
    [InlineData("context")]
    [InlineData("endpoint-map")]
    public void Issue145_Serialize_DefaultJsonElement_ThrowsArgumentException(string position)
    {
        var act = () => DidDocumentSerializer.Serialize(DocumentWithElement(position, default));

        act.Should().Throw<ArgumentException>();
    }

    #endregion

    #region Issue145_NullMembersAndDuplicateNames (final pass, F5)

    [Theory]
    [InlineData("vm-id")]
    [InlineData("vm-type")]
    [InlineData("service-id")]
    [InlineData("service-type")]
    [InlineData("also-known-as")]
    public void Issue145_Serialize_NullRequiredMember_ThrowsArgumentException(string position)
    {
        // Text(null) passed, so Serialize emitted e.g. "type": null, which Deserialize rejects.
        var doc = new DidDocument
        {
            Id = new Did(Did),
            AlsoKnownAs = position == "also-known-as" ? [null!] : null,
            VerificationMethod =
            [
                new VerificationMethod
                {
                    Id = position == "vm-id" ? null! : $"{Did}#key-1",
                    Type = position == "vm-type" ? null! : "Multikey",
                    Controller = new Did(Did),
                    PublicKeyMultibase = "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
                }
            ],
            Service =
            [
                new Service
                {
                    Id = position == "service-id" ? null! : $"{Did}#svc",
                    Type = position == "service-type" ? null! : "Example",
                    ServiceEndpoint = ServiceEndpointValue.FromUri("https://example.com")
                }
            ]
        };

        var act = () => DidDocumentSerializer.Serialize(doc);

        act.Should().Throw<ArgumentException>();
    }

    // Two distinct string instances with the same text are different keys to this comparer.
    private sealed class ByReference : IEqualityComparer<string>
    {
        public bool Equals(string? x, string? y) => ReferenceEquals(x, y);
        public int GetHashCode(string obj) => System.Runtime.CompilerServices.RuntimeHelpers.GetHashCode(obj);
    }

    private static Dictionary<string, JsonElement> DuplicateNames(string name)
    {
        var map = new Dictionary<string, JsonElement>(new ByReference())
        {
            [name] = JsonSerializer.SerializeToElement("https://a.example"),
            [new string(name.AsSpan())] = JsonSerializer.SerializeToElement("https://b.example")
        };
        map.Should().HaveCount(2, "the comparer must admit the duplicate for this test to mean anything");
        return map;
    }

    [Theory]
    [InlineData("document-extension")]
    [InlineData("vm-extension")]
    [InlineData("service-extension")]
    [InlineData("endpoint-map")]
    public void Issue145_Serialize_DuplicateNamesFromCustomComparer_ThrowsArgumentException(string position)
    {
        var doc = new DidDocument
        {
            Id = new Did(Did),
            VerificationMethod =
            [
                new VerificationMethod
                {
                    Id = $"{Did}#key-1",
                    Type = "Multikey",
                    Controller = new Did(Did),
                    PublicKeyMultibase = "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
                    AdditionalProperties = position == "vm-extension" ? DuplicateNames("x-ext") : null
                }
            ],
            Service =
            [
                new Service
                {
                    Id = $"{Did}#svc",
                    Type = "Example",
                    ServiceEndpoint = position == "endpoint-map"
                        ? ServiceEndpointValue.FromMap(DuplicateNames("uri"))
                        : ServiceEndpointValue.FromUri("https://example.com"),
                    AdditionalProperties = position == "service-extension" ? DuplicateNames("x-ext") : null
                }
            ],
            AdditionalProperties = position == "document-extension" ? DuplicateNames("x-ext") : null
        };

        var act = () => DidDocumentSerializer.Serialize(doc);

        act.Should().Throw<ArgumentException>(
            "a duplicate member is output NetDid's own Deserialize rejects (issue #121)");
    }

    [Theory]
    [InlineData("verificationMethod")]
    [InlineData("service")]
    [InlineData("authentication")]
    public void Issue145_Serialize_NullListEntry_ThrowsArgumentException(string member)
    {
        // The reader rejects these null entries; the writer crashed on them (NullReferenceException).
        var doc = new DidDocument
        {
            Id = new Did(Did),
            VerificationMethod = member == "verificationMethod" ? [null!] : null,
            Service = member == "service" ? [null!] : null,
            Authentication = member == "authentication" ? [null!] : null
        };

        var act = () => DidDocumentSerializer.Serialize(doc);

        act.Should().Throw<ArgumentException>();
    }

    #endregion

    #region Issue145_FollowUps (fixed here instead of filed: caller options, JWK members, DID anchors)

    // (a) Caller JsonSerializerOptions bypassed NetDid's internal converters, so Serialize produced
    // reflection output of the internal wrapper ({"Document":{"Id":{"Value":...) with no production
    // rules and no #145 UTF-16 checks.
    private static DidDocument SimpleDocument(string alias = "https://a.example") => new()
    {
        Id = new Did(Did),
        AlsoKnownAs = [alias],
        VerificationMethod =
        [
            new VerificationMethod
            {
                Id = $"{Did}#key-1",
                Type = "Multikey",
                Controller = new Did(Did),
                PublicKeyMultibase = "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
            }
        ]
    };

    [Fact]
    public void Issue145_Serialize_CallerOptions_StillProduceADidDocument()
    {
        var options = new JsonSerializerOptions { WriteIndented = true };

        var json = DidDocumentSerializer.Serialize(SimpleDocument(), DidContentTypes.JsonLd, options);
        var utf8 = DidDocumentSerializer.SerializeToUtf8(SimpleDocument(), DidContentTypes.JsonLd, options);
        var again = DidDocumentSerializer.Serialize(SimpleDocument(), DidContentTypes.JsonLd, options);

        json.Should().Contain("\"@context\"").And.Contain("\"id\": \"did:example:123\"")
            .And.Contain("\n", "WriteIndented from the caller's options is honored");
        json.Should().NotContain("\"Document\"");
        DidDocumentSerializer.Deserialize(json).VerificationMethod.Should().HaveCount(1);
        System.Text.Encoding.UTF8.GetString(utf8).Should().Be(json);
        again.Should().Be(json, "the same options instance can be reused");
    }

    [Fact]
    public void Issue145_Serialize_CallerOptions_StillRejectUnpairedSurrogates()
    {
        var act = () => DidDocumentSerializer.Serialize(
            SimpleDocument("https://a.example/\uD800"), DidContentTypes.JsonLd, new JsonSerializerOptions());

        act.Should().Throw<ArgumentException>();
    }

    // (b) WriteJwk kept only kty/crv/x/y, so an RSA key lost n and e.
    private static DidDocument DocumentWithJwk(JsonWebKey jwk) => new()
    {
        Id = new Did(Did),
        VerificationMethod =
        [
            new VerificationMethod
            {
                Id = $"{Did}#jwk",
                Type = "JsonWebKey2020",
                Controller = new Did(Did),
                PublicKeyJwk = jwk
            }
        ]
    };

    [Fact]
    public void Issue145_Serialize_RsaJwk_KeepsEveryPublicMember()
    {
        var jwk = new JsonWebKey
        {
            Kty = "RSA",
            N = "sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1WlUzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDprecbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBIY2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw",
            E = "AQAB",
            Kid = "rsa-1",
            Alg = "RS256",
            Use = "sig",
            X5tS256 = "thumb"
        };
        jwk.KeyOps.Add("verify");
        jwk.X5c.Add("MIIBIjANBg");

        var json = DidDocumentSerializer.Serialize(DocumentWithJwk(jwk));
        var read = DidDocumentSerializer.Deserialize(json).VerificationMethod![0].PublicKeyJwk!;

        read.N.Should().Be(jwk.N);
        read.E.Should().Be("AQAB");
        read.Kid.Should().Be("rsa-1");
        read.Alg.Should().Be("RS256");
        read.Use.Should().Be("sig");
        read.KeyOps.Should().Equal("verify");
        read.X5c.Should().Equal("MIIBIjANBg");
        read.X5tS256.Should().Be("thumb");
    }

    [Theory]
    [InlineData("RSA")]
    [InlineData("EC")]
    [InlineData("OKP")]
    [InlineData("oct")]
    public void Issue145_Serialize_Jwk_NeverEmitsPrivateMembers(string kty)
    {
        var jwk = new JsonWebKey
        {
            Kty = kty, Crv = kty == "EC" ? "P-256" : kty == "OKP" ? "Ed25519" : null,
            X = kty is "EC" or "OKP" ? "pubx" : null, Y = kty == "EC" ? "puby" : null,
            N = kty == "RSA" ? "pubn" : null, E = kty == "RSA" ? "AQAB" : null,
            D = "PRIVATE-D", P = "PRIVATE-P", Q = "PRIVATE-Q", DP = "PRIVATE-DP", DQ = "PRIVATE-DQ",
            QI = "PRIVATE-QI", K = "PRIVATE-K"
        };

        var json = DidDocumentSerializer.Serialize(DocumentWithJwk(jwk));

        json.Should().NotContain("PRIVATE");
    }

    [Fact]
    public void Issue145_Serialize_JwkWithoutKty_ThrowsArgumentException()
    {
        var act = () => DidDocumentSerializer.Serialize(
            DocumentWithJwk(new JsonWebKey { Crv = "Ed25519", X = "pubx" }));

        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Issue145_Deserialize_JwkWithoutKty_ThrowsJsonException()
    {
        var json = Doctor(PublicKeyMultibase,
            "\"publicKeyJwk\": {\"crv\": \"Ed25519\", \"x\": \"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}");

        var act = () => DidDocumentSerializer.Deserialize(json);

        act.Should().Throw<JsonException>("kty is REQUIRED in a JWK (RFC 7517 §4.1)");
    }

    // (c) DidParser anchored with $, which also matches before a trailing newline.
    [Theory]
    [InlineData("did:example:123\n")]
    [InlineData("did:example:123\r\n")]
    public void Issue145_Did_TrailingNewline_IsRejected(string value)
    {
        DidParser.IsValid(value).Should().BeFalse();
        var act = () => new Did(value);
        act.Should().Throw<NetDid.Core.Exceptions.InvalidDidException>();
    }

    [Theory]
    [InlineData("did:example:123#key-1\n")]
    [InlineData("did:example:123/path\n")]
    [InlineData("did:example:123?versionId=1\n")]
    public void Issue145_DidUrl_TrailingNewline_IsRejected(string value)
    {
        DidParser.ParseDidUrl(value).Should().BeNull();
        DidParser.IsValidDidReference(value).Should().BeFalse();
    }

    [Theory]
    [InlineData("did:example:123/pa th")]
    [InlineData("did:example:123/path\nX")]
    [InlineData("did:example:123?q=a\tb")]
    [InlineData("did:example:123;p=a\rb")]
    [InlineData("did:example:123#fr ag")]
    public void Issue145_DidUrl_EmbeddedWhitespaceOrControl_IsRejected(string value)
    {
        // RFC 3986 allows no raw whitespace or control characters in any URI component.
        DidParser.ParseDidUrl(value).Should().BeNull();
        DidParser.IsValidDidReference(value).Should().BeFalse();
    }

    [Theory]
    [InlineData("did:example:123")]
    [InlineData("did:example:123#key-1")]
    [InlineData("did:example:123/path/to?versionId=1#frag")]
    public void Issue145_Control_ValidDidsAndUrls_StillParse(string value)
    {
        DidParser.ParseDidUrl(value).Should().NotBeNull();
        DidParser.IsValidDidReference(value).Should().BeTrue();
    }

    [Fact]
    public void Issue145_Deserialize_IdWithTrailingNewline_ThrowsInvalidDidException()
    {
        var act = () => DidDocumentSerializer.Deserialize("{\"id\": \"did:example:123\\n\"}");

        act.Should().Throw<NetDid.Core.Exceptions.InvalidDidException>();
    }

    #endregion

    #region Issue145_FinalPassBeforePush

    // F1: the cached copy ignored later changes to the caller's options, which were no longer locked.
    [Fact]
    public void Issue145_Serialize_CallerOptions_AreLockedOnFirstUse()
    {
        var options = new JsonSerializerOptions { WriteIndented = true };
        DidDocumentSerializer.Serialize(SimpleDocument(), DidContentTypes.JsonLd, options);

        var act = () => options.WriteIndented = false;

        act.Should().Throw<InvalidOperationException>(
            "as with System.Text.Json itself, options are locked on first use, so a later change " +
            "cannot be silently ignored by the cached copy");
    }

    // F6: a caller TypeInfoResolver could bypass NetDid's converters or fail to describe its types.
    [Fact]
    public void Issue145_Serialize_CallerTypeInfoResolver_CannotBypassTheConverters()
    {
        var options = new JsonSerializerOptions
        {
            TypeInfoResolver = System.Text.Json.Serialization.Metadata.JsonTypeInfoResolver.Combine()
        };

        var json = DidDocumentSerializer.Serialize(SimpleDocument(), DidContentTypes.JsonLd, options);

        json.Should().Contain("\"@context\"").And.Contain("\"id\":\"did:example:123\"");
    }

    // F2: null entries in key_ops/x5c were accepted on read and then rejected by the writer.
    [Theory]
    [InlineData("\"key_ops\": [null]")]
    [InlineData("\"x5c\": [null]")]
    public void Issue145_Deserialize_JwkListWithNullEntry_ThrowsJsonException(string member)
    {
        var json = Doctor(PublicKeyMultibase,
            "\"publicKeyJwk\": {\"kty\": \"OKP\", \"crv\": \"Ed25519\", " +
            "\"x\": \"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\", " + member + "}");

        var act = () => DidDocumentSerializer.Deserialize(json);

        act.Should().Throw<JsonException>();
    }

    // F3: an empty kty was written, then rejected by the reader.
    [Fact]
    public void Issue145_Serialize_JwkWithEmptyKty_ThrowsArgumentException()
    {
        var act = () => DidDocumentSerializer.Serialize(
            DocumentWithJwk(new JsonWebKey { Kty = "", Crv = "Ed25519", X = "pubx" }));

        act.Should().Throw<ArgumentException>();
    }

    // F5: a null serviceEndpoint or a default(Did) controller was emitted as JSON null.
    [Fact]
    public void Issue145_Serialize_NullServiceEndpoint_ThrowsArgumentException()
    {
        var doc = new DidDocument
        {
            Id = new Did(Did),
            Service = [new Service { Id = $"{Did}#svc", Type = "Example", ServiceEndpoint = null! }]
        };

        var act = () => DidDocumentSerializer.Serialize(doc);

        act.Should().Throw<ArgumentException>();
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    public void Issue145_Serialize_DefaultDidController_ThrowsArgumentException(int count)
    {
        var doc = new DidDocument
        {
            Id = new Did(Did),
            Controller = count == 1 ? [default] : [new Did(Did), default]
        };

        var act = () => DidDocumentSerializer.Serialize(doc);

        act.Should().Throw<ArgumentException>();
    }

    // F7: the relative-reference branch of IsValidDidReference never reached the anchored regex.
    [Theory]
    [InlineData("#a\n")]
    [InlineData("#a b")]
    [InlineData("#\t")]
    [InlineData("#key\u0000")]
    public void Issue145_RelativeReference_WhitespaceOrControl_IsRejected(string reference)
    {
        DidParser.IsValidDidReference(reference).Should().BeFalse();
    }

    [Fact]
    public void Issue145_Control_RelativeReference_StillValid()
    {
        DidParser.IsValidDidReference("#key-1").Should().BeTrue();
    }

    #endregion

    #region Issue145_IdAndUriSyntax (DID Core §3.2 / §5.1.3 / §5.2 / §5.4)

    // DID URL path, query and fragment are RFC 3986 components: no raw non-ASCII, no invisible
    // format characters, no characters outside the RFC 3986 set, and only well-formed %HH.
    [Theory]
    [InlineData("did:example:123/a‮b")]
    [InlineData("did:example:123?q=​")]
    [InlineData("did:example:123#f﻿")]
    [InlineData("did:example:123/café")]
    [InlineData("did:example:123#<script>")]
    [InlineData("did:example:123/a\"b")]
    [InlineData("did:example:123/a%zz")]
    [InlineData("did:example:123/a%4")]
    [InlineData("did:example:123?q={x}")]
    [InlineData("did:example:123#a|b")]
    [InlineData("did:example:123/a\\b")]
    [InlineData("did:example:123#a`b")]
    public void Issue145_DidUrl_OutsideRfc3986_IsRejected(string value)
    {
        DidParser.ParseDidUrl(value).Should().BeNull();
        DidParser.IsValidDidReference(value).Should().BeFalse();
    }

    [Theory]
    [InlineData("#a‮")]
    [InlineData("#<x>")]
    [InlineData("#%zz")]
    [InlineData("#café")]
    public void Issue145_RelativeReference_OutsideRfc3986_IsRejected(string reference)
    {
        DidParser.IsValidDidReference(reference).Should().BeFalse();
    }

    [Theory]
    [InlineData("did:example:123/caf%C3%A9")]
    [InlineData("did:example:123/a!$&'()*+,=:@~")]
    [InlineData("did:example:123?versionTime=2024-01-01T00:00:00Z")]
    [InlineData("did:example:123?service=files&relativeRef=/a%20b")]
    [InlineData("did:example:123#frag/with?query:and@")]
    [InlineData("did:example:123;service=files")]
    [InlineData("did:web:example.com:user:alice/path/to/doc.json")]
    [InlineData("#key-1")]
    [InlineData("#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")]
    public void Issue145_Control_Rfc3986DidUrls_StillValid(string value)
    {
        DidParser.IsValidDidReference(value).Should().BeTrue();
    }

    // Consumption: DID Core requires these to be URIs / DID URLs, and §5.4 says a consumer MUST
    // produce an error for duplicate service ids.
    public static TheoryData<string, string> InvalidIdentifierShapes => new()
    {
        { "\"service\": [{", "\"service\": [{\"id\": \"did:example:123#svc\", \"type\": \"Dup\", \"serviceEndpoint\": \"https://d.example\"}, {" },
        { "\"service\": [{", "\"service\": [{\"id\": \"#svc\", \"type\": \"Dup\", \"serviceEndpoint\": \"https://d.example\"}, {" },
        { "\"id\": \"did:example:123#key-1\",", "\"id\": \"key 1\"," },
        { RootAnchor, "\"authentication\": [\"did:example:123#key 1\"], " + RootAnchor },
        { RootAnchor, "\"authentication\": [\"did:example:123#k‮\"], " + RootAnchor },
        { "\"id\": \"did:example:123#svc\",", "\"id\": \"svc with space\"," },
        { "\"id\": \"did:example:123#svc\",", "\"id\": \"1x:y\"," },
        { "\"serviceEndpoint\": \"https://example.com\"", "\"serviceEndpoint\": \"not a uri\"" },
        { "\"serviceEndpoint\": \"https://example.com\"", "\"serviceEndpoint\": \"/relative/path\"" },
        { "\"serviceEndpoint\": \"https://example.com\"", "\"serviceEndpoint\": [\"https://a.example\", \"not a uri\"]" },
        { RootAnchor, "\"alsoKnownAs\": [\"not a uri\"], " + RootAnchor },
        // The bare shorthand "svc" names the same service as "did:example:123#svc" (issue #136).
        { "\"service\": [{", "\"service\": [{\"id\": \"svc\", \"type\": \"Dup\", \"serviceEndpoint\": \"https://d.example\"}, {" },
    };

    [Theory]
    [MemberData(nameof(InvalidIdentifierShapes))]
    public void Issue145_Deserialize_InvalidIdentifierOrUri_ThrowsJsonException(string find, string replace)
    {
        var json = Doctor(find, replace);
        var utf8 = System.Text.Encoding.UTF8.GetBytes(json);

        var fromString = () => DidDocumentSerializer.Deserialize(json);
        var fromUtf8 = () => DidDocumentSerializer.Deserialize(utf8.AsSpan());

        fromString.Should().Throw<JsonException>();
        fromUtf8.Should().Throw<JsonException>();
    }

    [Theory]
    [InlineData("\"id\": \"did:example:123#svc\",", "\"id\": \"#svc\",")]
    [InlineData("\"id\": \"did:example:123#svc\",", "\"id\": \"files\",")]
    [InlineData("\"id\": \"did:example:123#key-1\",", "\"id\": \"key-1\",")]
    [InlineData("\"serviceEndpoint\": \"https://example.com\"", "\"serviceEndpoint\": \"didcomm:transport/queue\"")]
    [InlineData("\"id\": \"did:example:123\",", "\"alsoKnownAs\": [\"did:web:example.com\", \"https://a.example/b?c=d#e\"], \"id\": \"did:example:123\",")]
    public void Issue145_Control_ConformantIdentifiers_StillDeserialize(string find, string replace)
    {
        var act = () => DidDocumentSerializer.Deserialize(Doctor(find, replace));

        act.Should().NotThrow();
    }

    // Production: a conforming producer MUST NOT emit these either (§5.4 for duplicates).
    [Theory]
    [InlineData("vm-id")]
    [InlineData("service-id")]
    [InlineData("endpoint-uri")]
    [InlineData("endpoint-set-uri")]
    [InlineData("also-known-as")]
    [InlineData("relationship-reference")]
    public void Issue145_Serialize_InvalidIdentifierOrUri_ThrowsArgumentException(string position)
    {
        var act = () => DidDocumentSerializer.Serialize(DocumentWith(position, "a b"));

        act.Should().Throw<ArgumentException>();
    }

    [Theory]
    [InlineData("vm-id")]
    [InlineData("service-id")]
    [InlineData("endpoint-uri")]
    [InlineData("also-known-as")]
    [InlineData("relationship-reference")]
    public void Issue145_Serialize_RawNonAsciiInUriPosition_ThrowsArgumentException(string position)
    {
        var act = () => DidDocumentSerializer.Serialize(DocumentWith(position, "x😀y"));

        act.Should().Throw<ArgumentException>("RFC 3986 URIs carry non-ASCII only percent-encoded");
    }

    [Theory]
    [InlineData("did:example:123#svc", "did:example:123#svc")]
    [InlineData("#svc", "did:example:123#svc")]
    [InlineData("svc", "#svc")]
    public void Issue145_Serialize_DuplicateServiceIds_ThrowsArgumentException(string first, string second)
    {
        var doc = new DidDocument
        {
            Id = new Did(Did),
            Service =
            [
                new Service { Id = first, Type = "A", ServiceEndpoint = ServiceEndpointValue.FromUri("https://a.example") },
                new Service { Id = second, Type = "B", ServiceEndpoint = ServiceEndpointValue.FromUri("https://b.example") }
            ]
        };

        var act = () => DidDocumentSerializer.Serialize(doc);

        act.Should().Throw<ArgumentException>();
    }

    #endregion

    #region Issue145_IdAndUriSyntax_FinalPass

    // F5: "[" and "]" are only allowed around an IP-literal host (RFC 3986 §3.2.2).
    [Theory]
    [InlineData("https://ex[ample.com", false)]
    [InlineData("https://example.com/a[b]", false)]
    [InlineData("http://[::1", false)]
    [InlineData("http://host:abc", false)]      // "//" starts an authority, never a path
    [InlineData("http://user@[::1]x", false)]
    [InlineData("http://[::1]:8080/x", true)]
    [InlineData("file:///etc/hosts", true)]
    [InlineData("urn:a//b", true)]
    [InlineData("https://user:pw@host.example:443/p?q=1#f", true)]
    [InlineData("didcomm:transport/queue", true)]
    [InlineData("urn:uuid:6e8bc430-9c3a-11d9-9669-0800200c9a66", true)]
    [InlineData("mailto:a@b.example", true)]
    public void Issue145_IsAbsoluteUri_BracketsOnlyAroundAnIpLiteralHost(string value, bool expected)
    {
        DidParser.IsAbsoluteUri(value).Should().Be(expected);
    }

    // F6: the bare shorthand must not swallow real RFC 3986 relative references.
    [Theory]
    [InlineData("//evil.example/x", false)]
    [InlineData("/files", false)]
    [InlineData("?service=x", false)]
    [InlineData("a/b", false)]
    [InlineData("files", true)]
    [InlineData("key-1", true)]
    public void Issue145_IsBareShorthand_RejectsRelativeReferences(string value, bool expected)
    {
        DidParser.IsBareShorthand(value).Should().Be(expected);
    }

    [Fact]
    public void Issue145_Deserialize_NetworkPathServiceId_ThrowsJsonException()
    {
        var act = () => DidDocumentSerializer.Deserialize(
            Doctor("\"id\": \"did:example:123#svc\",", "\"id\": \"//evil.example/x\","));

        act.Should().Throw<JsonException>();
    }

    #endregion
}

