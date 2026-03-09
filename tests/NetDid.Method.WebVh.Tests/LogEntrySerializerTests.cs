using System.Text;
using FluentAssertions;
using NetDid.Core.Model;
using NetDid.Method.WebVh;
using NetDid.Method.WebVh.Model;

namespace NetDid.Method.WebVh.Tests;

public class LogEntrySerializerTests
{
    [Fact]
    public void Serialize_RoundTrip_Preserves()
    {
        var entry = CreateSampleEntry();

        var json = LogEntrySerializer.Serialize(entry);
        var parsed = LogEntrySerializer.DeserializeEntry(json);

        parsed.VersionId.Should().Be(entry.VersionId);
        parsed.VersionNumber.Should().Be(1);
        parsed.Parameters.Method.Should().Be("did:webvh:1.0");
        parsed.Parameters.Scid.Should().Be("QmTest");
        parsed.State.Id.Value.Should().Be("did:webvh:QmTest:example.com");
        parsed.Proof.Should().HaveCount(1);
        parsed.Proof![0].Type.Should().Be("DataIntegrityProof");
    }

    [Fact]
    public void SerializeWithoutProof_ExcludesProof()
    {
        var entry = CreateSampleEntry();

        var json = LogEntrySerializer.SerializeWithoutProof(entry);

        json.Should().NotContain("proof");
        json.Should().NotContain("proofValue");
        json.Should().Contain("versionId");
        json.Should().Contain("state");
    }

    [Fact]
    public void ToJsonLines_MultipleEntries_ProducesSeparateLines()
    {
        var entry1 = CreateSampleEntry();
        var entry2 = CreateSampleEntry("2-Hash2");

        var bytes = LogEntrySerializer.ToJsonLines([entry1, entry2]);
        var text = Encoding.UTF8.GetString(bytes);

        var lines = text.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        lines.Should().HaveCount(2);
    }

    [Fact]
    public void ParseJsonLines_RoundTrip()
    {
        var entry = CreateSampleEntry();
        var bytes = LogEntrySerializer.ToJsonLines([entry]);

        var parsed = LogEntrySerializer.ParseJsonLines(bytes);

        parsed.Should().HaveCount(1);
        parsed[0].VersionId.Should().Be(entry.VersionId);
    }

    [Fact]
    public void ParseJsonLines_EmptyContent_ReturnsEmpty()
    {
        var parsed = LogEntrySerializer.ParseJsonLines(Array.Empty<byte>());
        parsed.Should().BeEmpty();
    }

    [Fact]
    public void Serialize_WithWitnessConfig_Includes()
    {
        var entry = CreateSampleEntry();
        entry = new LogEntry
        {
            VersionId = entry.VersionId,
            VersionTime = entry.VersionTime,
            Parameters = new LogEntryParameters
            {
                Method = "did:webvh:1.0",
                Scid = "QmTest",
                UpdateKeys = ["z6MkTest"],
                Witness = new WitnessConfig
                {
                    Threshold = 2,
                    Witnesses =
                    [
                        new WitnessEntry { Id = "did:key:z6MkWitness1", Weight = 1 },
                        new WitnessEntry { Id = "did:key:z6MkWitness2", Weight = 2 }
                    ]
                }
            },
            State = entry.State,
            Proof = entry.Proof
        };

        var json = LogEntrySerializer.Serialize(entry);
        json.Should().Contain("witness");
        json.Should().Contain("threshold");

        var parsed = LogEntrySerializer.DeserializeEntry(json);
        parsed.Parameters.Witness.Should().NotBeNull();
        parsed.Parameters.Witness!.Threshold.Should().Be(2);
        parsed.Parameters.Witness.Witnesses.Should().HaveCount(2);
    }

    private static LogEntry CreateSampleEntry(string versionId = "1-QmTest")
    {
        return new LogEntry
        {
            VersionId = versionId,
            VersionTime = new DateTimeOffset(2026, 3, 1, 0, 0, 0, TimeSpan.Zero),
            Parameters = new LogEntryParameters
            {
                Method = "did:webvh:1.0",
                Scid = "QmTest",
                UpdateKeys = ["z6MkTestKey"],
                Deactivated = false
            },
            State = new DidDocument
            {
                Id = new Did("did:webvh:QmTest:example.com"),
                VerificationMethod =
                [
                    new VerificationMethod
                    {
                        Id = "did:webvh:QmTest:example.com#z6MkTestKey",
                        Type = "Multikey",
                        Controller = new Did("did:webvh:QmTest:example.com"),
                        PublicKeyMultibase = "z6MkTestKey"
                    }
                ]
            },
            Proof =
            [
                new DataIntegrityProofValue
                {
                    Type = "DataIntegrityProof",
                    Cryptosuite = "eddsa-jcs-2022",
                    VerificationMethod = "did:key:z6MkTestKey#z6MkTestKey",
                    Created = "2026-03-01T00:00:00Z",
                    ProofPurpose = "assertionMethod",
                    ProofValue = "zTestProofValue"
                }
            ]
        };
    }
}
