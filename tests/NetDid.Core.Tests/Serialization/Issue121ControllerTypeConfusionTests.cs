using System.Text.Json;
using FluentAssertions;
using NetDid.Core.Model;
using NetDid.Core.Serialization;

namespace NetDid.Core.Tests.Serialization;

/// <summary>
/// Issue #121: a verification method's 'controller' is authorization-relevant, and W3C DID Core
/// §5.2 makes it REQUIRED — it MUST be a single string and does NOT default to (nor can it be
/// inferred as) the DID subject. Two forgery payloads must both fail closed on consumption:
/// a present-but-malformed controller (e.g. an array), and an OMITTED controller. Neither may
/// be silently accepted as "self-controlled". Duplicate 'controller' members must also be
/// rejected so a decoy cannot smuggle an unvalidated value past the guard.
/// </summary>
public class Issue121ControllerTypeConfusionTests
{
    private static string DocWithVmController(string controllerProperty) => $$"""
    {
      "id": "did:example:victim",
      "verificationMethod": [{
        "id": "did:example:victim#key-1",
        "type": "Multikey",
        {{controllerProperty}}
        "publicKeyMultibase": "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
      }]
    }
    """;

    #region Issue121_VerificationMethodController_Rejected

    [Theory]
    [InlineData("""["did:example:attacker"]""")]
    [InlineData("{}")]
    [InlineData("42")]
    [InlineData("true")]
    [InlineData("null")]
    public void Issue121_VmController_PresentNonString_IsRejected(string controllerJson)
    {
        var act = () => DidDocumentSerializer.Deserialize(
            DocWithVmController($"\"controller\": {controllerJson},"));

        act.Should().Throw<JsonException>(
            "a present-but-malformed VM controller must fail closed (W3C DID Core §5.2), " +
            "not be silently reinterpreted as omitted/self-controlled");
    }

    [Fact]
    public void Issue121_VmController_Omitted_IsRejected()
    {
        // The simpler forgery payload: just delete `controller`. §5.2 makes it required and says
        // it cannot be inferred from the document, so an omitted controller is invalid input —
        // NOT a spec-defined "controller = subject" state. It must be rejected, not accepted.
        var act = () => DidDocumentSerializer.Deserialize(DocWithVmController(""));

        act.Should().Throw<JsonException>(
            "an omitted VM controller is invalid per §5.2 and must not resolve to a self-controlled key");
    }

    [Fact]
    public void Issue121_EmbeddedVm_OmittedController_IsRejected()
    {
        // Embedded verification methods inside relationships must enforce the same rule.
        var act = () => DidDocumentSerializer.Deserialize("""
        {
          "id": "did:example:victim",
          "authentication": [{
            "id": "did:example:victim#key-1",
            "type": "Multikey",
            "publicKeyMultibase": "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
          }]
        }
        """);

        act.Should().Throw<JsonException>();
    }

    [Fact]
    public void Issue121_EmbeddedVm_ArrayController_IsRejected()
    {
        var act = () => DidDocumentSerializer.Deserialize("""
        {
          "id": "did:example:victim",
          "authentication": [{
            "id": "did:example:victim#key-1",
            "type": "Multikey",
            "controller": ["did:example:attacker"],
            "publicKeyMultibase": "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
          }]
        }
        """);

        act.Should().Throw<JsonException>();
    }

    [Fact]
    public void Issue121_ArrayAndOmitted_BothRejected_NeitherIsSelfControlled()
    {
        // The security property: both spellings of the forgery — the array form and the
        // omitted form — must be refused. Previously the array form was silently dropped and
        // the omitted form silently accepted; both mapped a foreign/absent controller onto the
        // subject. Now both throw.
        var arrayForm = () => DidDocumentSerializer.Deserialize(
            DocWithVmController("\"controller\": [\"did:example:attacker\"],"));
        var omittedForm = () => DidDocumentSerializer.Deserialize(DocWithVmController(""));

        arrayForm.Should().Throw<JsonException>();
        omittedForm.Should().Throw<JsonException>();
    }

    #endregion

    #region Issue121_VerificationMethodController_ConformantPath

    [Fact]
    public void Issue121_VmController_String_ParsesExactly()
    {
        // The conformant path (§5.2: MUST be a single string) — byte-for-byte unchanged.
        var doc = DidDocumentSerializer.Deserialize(
            DocWithVmController("\"controller\": \"did:example:controller\","));

        doc.VerificationMethod![0].Controller.Value.Should().Be("did:example:controller");
    }

    [Fact]
    public void Issue121_VmController_String_RoundTripsIntact()
    {
        var json = DocWithVmController("\"controller\": \"did:example:controller\",");
        var doc = DidDocumentSerializer.Deserialize(json);
        var reserialized = DidDocumentSerializer.Serialize(doc, DidContentTypes.Json);

        using var parsed = JsonDocument.Parse(reserialized);
        parsed.RootElement.GetProperty("verificationMethod")[0]
            .GetProperty("controller").GetString().Should().Be("did:example:controller",
                "a document that parses successfully must re-serialize with its controller intact");
    }

    #endregion

    #region Issue121_DuplicateMembers

    [Fact]
    public void Issue121_VmDuplicateController_IsRejected()
    {
        // A decoy duplicate keeps the LAST value under default JsonDocument parsing, smuggling an
        // unvalidated controller past a per-property guard. Reject duplicates at the boundary.
        var act = () => DidDocumentSerializer.Deserialize("""
        {
          "id": "did:example:victim",
          "verificationMethod": [{
            "id": "did:example:victim#key-1",
            "type": "Multikey",
            "controller": ["did:example:attacker"],
            "controller": "did:example:victim",
            "publicKeyMultibase": "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
          }]
        }
        """);

        act.Should().Throw<JsonException>();
    }

    [Fact]
    public void Issue121_DocumentDuplicateController_IsRejected()
    {
        var act = () => DidDocumentSerializer.Deserialize("""
        {
          "id": "did:example:victim",
          "controller": ["did:example:attacker"],
          "controller": "did:example:victim"
        }
        """);

        act.Should().Throw<JsonException>();
    }

    #endregion

    #region Issue121_DocumentLevelController

    [Theory]
    [InlineData("42")]
    [InlineData("{}")]
    [InlineData("true")]
    [InlineData("null")]
    public void Issue121_DocController_NonStringNonArray_IsRejected(string controllerJson)
    {
        // Same silent-drop class at document level: these previously collapsed to an EMPTY
        // list, which consumers read as "no controller". §5.1.2: MUST be a string or a set
        // of strings.
        var act = () => DidDocumentSerializer.Deserialize(
            $$"""{"id":"did:example:123","controller":{{controllerJson}}}""");

        act.Should().Throw<JsonException>();
    }

    [Theory]
    [InlineData("""["did:example:c1", 42]""")]
    [InlineData("""[["did:example:c1"]]""")]
    [InlineData("""[null]""")]
    public void Issue121_DocController_NonStringArrayElement_ThrowsJsonException(string controllerJson)
    {
        // A non-string element previously escaped as InvalidOperationException from
        // JsonElement.GetString() — a raw JSON-access failure leaking through the parse
        // trust boundary instead of the boundary's own exception type.
        var act = () => DidDocumentSerializer.Deserialize(
            $$"""{"id":"did:example:123","controller":{{controllerJson}}}""");

        act.Should().Throw<JsonException>();
    }

    [Fact]
    public void Issue121_DocController_String_StillAccepted()
    {
        // §5.1.2 permits a single string at DOCUMENT level. The verification-method restriction
        // (§5.2, single string only) is intentionally distinct — pin the asymmetry.
        var doc = DidDocumentSerializer.Deserialize(
            """{"id":"did:example:123","controller":"did:example:c1"}""");

        doc.Controller.Should().ContainSingle().Which.Value.Should().Be("did:example:c1");
    }

    [Fact]
    public void Issue121_DocController_ArrayOfStrings_StillAccepted()
    {
        // §5.1.2 permits a set of strings at DOCUMENT level, while §5.2 forbids it on a
        // verification method. The asymmetry is intentional — pin it.
        var doc = DidDocumentSerializer.Deserialize(
            """{"id":"did:example:123","controller":["did:example:c1","did:example:c2"]}""");

        doc.Controller.Should().HaveCount(2);
    }

    #endregion

    #region Issue121_PublicWriterFailsClosed

    private static DidDocument DocWithControllerlessVm() => new()
    {
        Id = new Did("did:example:123"),
        VerificationMethod =
        [
            new VerificationMethod { Id = "did:example:123#k1", Type = "Multikey", PublicKeyMultibase = "z6Mk..." }
        ]
    };

    [Fact]
    public void Issue121_PublicSerialize_MissingController_Throws()
    {
        // Enforcement is symmetric: NetDid must not publicly AUTHOR the omitted-controller shape
        // it rejects on consumption. The public string serializer fails closed (W3C DID Core §5.2).
        var act = () => DidDocumentSerializer.Serialize(DocWithControllerlessVm(), DidContentTypes.Json);

        act.Should().Throw<ArgumentException>().WithMessage("*controller*");
    }

    [Fact]
    public void Issue121_PublicSerializeToUtf8_MissingController_Throws()
    {
        var act = () => DidDocumentSerializer.SerializeToUtf8(DocWithControllerlessVm(), DidContentTypes.Json);

        act.Should().Throw<ArgumentException>().WithMessage("*controller*");
    }

    [Fact]
    public void Issue121_PublicSerialize_MissingEmbeddedController_Throws()
    {
        // The same rule applies to a verification method embedded in a relationship.
        var doc = new DidDocument
        {
            Id = new Did("did:example:123"),
            Authentication =
            [
                VerificationRelationshipEntry.FromEmbedded(
                    new VerificationMethod { Id = "did:example:123#k1", Type = "Multikey", PublicKeyMultibase = "z6Mk..." })
            ]
        };

        var act = () => DidDocumentSerializer.Serialize(doc, DidContentTypes.Json);

        act.Should().Throw<ArgumentException>().WithMessage("*controller*");
    }

    [Fact]
    public void Issue121_PublicSerialize_WithController_Succeeds()
    {
        // The conformant document still serializes with its controller intact.
        var doc = new DidDocument
        {
            Id = new Did("did:example:123"),
            VerificationMethod =
            [
                new VerificationMethod
                {
                    Id = "did:example:123#k1", Type = "Multikey",
                    Controller = new Did("did:example:123"), PublicKeyMultibase = "z6Mk..."
                }
            ]
        };

        var json = DidDocumentSerializer.Serialize(doc, DidContentTypes.Json);

        using var parsed = JsonDocument.Parse(json);
        parsed.RootElement.GetProperty("verificationMethod")[0]
            .GetProperty("controller").GetString().Should().Be("did:example:123");
    }

    [Fact]
    public void Issue121_InternalTemplateSerializer_OmitsController_NotNull_AndRoundTrips()
    {
        // The method-internal tolerant serializer (did:peer:4 template) emits an ABSENT
        // controller — never "controller": null — and its output round-trips through the
        // matching tolerant deserializer.
        var json = DidDocumentSerializer.SerializeAllowingIncompleteVerificationMethods(
            DocWithControllerlessVm(), DidContentTypes.Json);

        json.Should().NotContain("\"controller\":null").And.NotContain("\"controller\": null");
        using (var parsed = JsonDocument.Parse(json))
            parsed.RootElement.GetProperty("verificationMethod")[0]
                .TryGetProperty("controller", out _).Should().BeFalse();

        // Strict consumption still rejects the omitted-controller output; tolerant accepts it.
        var strict = () => DidDocumentSerializer.Deserialize(json);
        strict.Should().Throw<JsonException>();
        DidDocumentSerializer.DeserializeAllowingIncompleteVerificationMethods(json)
            .VerificationMethod![0].Controller.Value.Should().BeNull();
    }

    #endregion

    #region Issue121_WriterTrustBoundary

    // A hostile IReadOnlyList that returns a controller-bearing VM on its FIRST enumeration and a
    // controllerless VM on every subsequent one — the classic validate-then-emit TOCTOU. The fix
    // snapshots the collection exactly once, so validation and emission read identical data.
    private sealed class SwitchingVmList : IReadOnlyList<VerificationMethod>
    {
        private int _enumerations;
        private static VerificationMethod Vm(bool withController) => new()
        {
            Id = "did:example:123#k1",
            Type = "Multikey",
            Controller = withController ? new Did("did:example:123") : default,
            PublicKeyMultibase = "z6Mk..."
        };
        private VerificationMethod Current => Vm(withController: _enumerations == 0);
        public IEnumerator<VerificationMethod> GetEnumerator()
        {
            var vm = Current;
            _enumerations++;
            yield return vm;
        }
        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();
        public int Count => 1;
        public VerificationMethod this[int index] => Current;
    }

    [Fact]
    public void Issue121_Serialize_SwitchingVmList_NeverEmitsControllerlessVm()
    {
        // Whichever enumeration the snapshot freezes, the output must never contain a
        // controllerless verification method: either Serialize throws, or it emits the controller
        // it validated — never validate one shape and write another.
        var doc = new DidDocument { Id = new Did("did:example:123"), VerificationMethod = new SwitchingVmList() };

        string? json = null;
        var ex = Record.Exception(() => json = DidDocumentSerializer.Serialize(doc, DidContentTypes.Json));

        if (ex is null)
        {
            // Emitted output is self-consistent: it re-parses under the strict boundary.
            var act = () => DidDocumentSerializer.Deserialize(json!);
            act.Should().NotThrow("the writer must emit the same controller-bearing VM it validated");
            json!.Should().Contain("\"controller\":\"did:example:123\"");
        }
        else
        {
            ex.Should().BeOfType<ArgumentException>();
        }
    }

    [Fact]
    public void Issue121_SerializeToUtf8_SwitchingVmList_NeverEmitsControllerlessVm()
    {
        var doc = new DidDocument { Id = new Did("did:example:123"), VerificationMethod = new SwitchingVmList() };

        byte[]? bytes = null;
        var ex = Record.Exception(() => bytes = DidDocumentSerializer.SerializeToUtf8(doc, DidContentTypes.Json));

        if (ex is null)
        {
            var act = () => DidDocumentSerializer.Deserialize(bytes!);
            act.Should().NotThrow();
        }
        else
        {
            ex.Should().BeOfType<ArgumentException>();
        }
    }

    [Theory]
    [InlineData("verificationMethod")]
    [InlineData("authentication")]
    [InlineData("assertionMethod")]
    [InlineData("controller")]
    [InlineData("service")]
    public void Issue121_Serialize_ReservedAdditionalProperty_IsRejected(string reservedName)
    {
        // AdditionalProperties must not carry a reserved member name — e.g. a raw controllerless
        // `verificationMethod` array — because the writer would otherwise emit it unvalidated,
        // re-injecting the exact shape strict consumption rejects.
        var rawVmArray = JsonSerializer.SerializeToElement(new[]
        {
            new { id = "did:example:123#k1", type = "Multikey", publicKeyMultibase = "z6Mk..." }
        });
        var doc = new DidDocument
        {
            Id = new Did("did:example:123"),
            AdditionalProperties = new Dictionary<string, JsonElement> { [reservedName] = rawVmArray }
        };

        var stringWriter = () => DidDocumentSerializer.Serialize(doc, DidContentTypes.Json);
        var utf8Writer = () => DidDocumentSerializer.SerializeToUtf8(doc, DidContentTypes.Json);

        stringWriter.Should().Throw<ArgumentException>().WithMessage($"*{reservedName}*");
        utf8Writer.Should().Throw<ArgumentException>().WithMessage($"*{reservedName}*");
    }

    #endregion
}
