using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using FluentAssertions;
using NetDid.Core.Model;
using NetDid.Method.WebVh.Model;

namespace NetDid.Method.WebVh.Tests;

public sealed class LogEntryWireProvenanceTests
{
    private const string EntryJson = """
        {
          "versionId": "1-zWireProvenanceTest",
          "versionTime": "2026-07-13T12:00:00Z",
          "parameters": {},
          "state": {
            "@context": "https://www.w3.org/ns/did/v1",
            "id": "did:example:wire-provenance",
            "verificationMethod": [{
              "id": "did:example:wire-provenance#key-1",
              "type": "Multikey",
              "controller": "did:example:wire-provenance",
              "publicKeyMultibase": "z6MkhWireProvenanceTest",
              "x-wire-extension": {
                "nested": true
              }
            }],
            "x-mutable-extension": {
              "value": "original"
            }
          },
          "proof": {
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-jcs-2022",
            "verificationMethod": "did:key:z6MkhWireProvenanceTest#z6MkhWireProvenanceTest",
            "created": "2026-07-13T12:00:00Z",
            "proofPurpose": "assertionMethod",
            "proofValue": "zWireProvenanceProof",
            "x-proof-extension": {
              "retained": true
            }
          }
        }
        """;

    [Fact]
    public void ParsedUnknownNestedVerificationMethodMember_SerializePreservesMember()
    {
        var entry = ParseEntry();

        var serialized = JsonNode.Parse(LogEntrySerializer.Serialize(entry))!;
        var extension = serialized["state"]!["verificationMethod"]![0]!["x-wire-extension"];

        extension.Should().NotBeNull(
                "every fetched nested member must remain in controller-proof verification and republishing input");
        extension!["nested"]!.GetValue<bool>().Should().BeTrue();
    }

    [Fact]
    public void ParsedUnknownNestedVerificationMethodMember_SerializeWithoutProofPreservesMember()
    {
        var entry = ParseEntry();

        var serialized = JsonNode.Parse(LogEntrySerializer.SerializeWithoutProof(entry))!;

        serialized["proof"].Should().BeNull();
        var extension = serialized["state"]!["verificationMethod"]![0]!["x-wire-extension"];
        extension.Should().NotBeNull(
                "entry hashes and witness proofs must cover every fetched nested member");
        extension!["nested"]!.GetValue<bool>().Should().BeTrue();
    }

    [Fact]
    public void ParsedUnknownNestedVerificationMethodMember_VersionIdOverridePreservesMember()
    {
        var entry = ParseEntry();

        var serialized = JsonNode.Parse(LogEntrySerializer.SerializeWithoutProof(
            entry,
            "previous-version-id"))!;

        serialized["versionId"]!.GetValue<string>().Should().Be("previous-version-id");
        serialized["proof"].Should().BeNull();
        serialized["state"]!["verificationMethod"]![0]!["x-wire-extension"]!["nested"]!
            .GetValue<bool>().Should().BeTrue(
                "entry-hash overrides must change only versionId, not reduce fetched state");
    }

    [Fact]
    public void ParsedSingleProofObject_SerializeStillNormalizesContainerToArray()
    {
        var entry = ParseEntry();

        var serialized = JsonNode.Parse(LogEntrySerializer.Serialize(entry))!;

        var proofs = serialized["proof"].Should().BeOfType<JsonArray>().Subject;
        proofs.Should().ContainSingle();
        proofs[0]!["x-proof-extension"]!["retained"]!.GetValue<bool>().Should().BeTrue();
    }

    [Fact]
    public void ParsedEntry_WithChangedState_SerializesModeledChangeInsteadOfStaleWireJson()
    {
        var entry = ParseEntry();
        var changed = entry with
        {
            State = entry.State with { Id = new Did("did:example:changed") }
        };

        var serialized = JsonNode.Parse(LogEntrySerializer.Serialize(changed))!;

        // The deliberate id edit wins — proving the MODELED path produced this output, not
        // stale wire JSON (which still carries the original id).
        serialized["state"]!["id"]!.GetValue<string>().Should().Be("did:example:changed");

        // Verification-method extensions now round-trip through the model
        // (VerificationMethodJsonConverter captures AdditionalProperties — the did:ethr
        // publicKeyHex fix), so a nested member is no longer silently dropped on modeled
        // fallback. This strengthens #101's intent (never drop signed nested members): the
        // consumer's id edit wins AND the untouched nested member survives.
        serialized["state"]!["verificationMethod"]![0]!["x-wire-extension"]!["nested"]!
            .GetValue<bool>().Should().BeTrue(
                "verification-method extensions are modeled and must survive modeled serialization");
    }

    [Fact]
    public void ParsedEntry_InPlaceNestedModelMutation_SerializesMutationInsteadOfStaleWireJson()
    {
        var entry = ParseEntry();
        var additionalProperties = entry.State.AdditionalProperties
            .Should().BeOfType<Dictionary<string, JsonElement>>().Subject;
        additionalProperties["x-mutable-extension"] = JsonSerializer.SerializeToElement(
            new Dictionary<string, string> { ["value"] = "changed" });

        var serialized = JsonNode.Parse(LogEntrySerializer.Serialize(entry))!;

        serialized["state"]!["x-mutable-extension"]!["value"]!.GetValue<string>()
            .Should().Be("changed",
                "an in-place mutation must invalidate parsed-wire provenance before serialization");
    }

    private static LogEntry ParseEntry()
        => LogEntrySerializer.ParseJsonLines(Encoding.UTF8.GetBytes(
            JsonNode.Parse(EntryJson)!.ToJsonString())).Single();
}
