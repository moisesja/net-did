using System.Globalization;
using System.Text;
using FluentAssertions;
using NetDid.Core.Model;
using NetDid.Method.WebVh;
using NetDid.Method.WebVh.Model;

namespace NetDid.Method.WebVh.Tests;

[Collection("Culture-sensitive")]
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
    public void DeserializeAndSerialize_PreservesExplicitUtcOffsetWireValue()
    {
        var json = LogEntrySerializer.Serialize(CreateSampleEntry())
            .Replace("2026-03-01T00:00:00Z", "2026-03-01T00:00:00+00:00");

        var parsed = LogEntrySerializer.DeserializeEntry(json);
        var reserialized = LogEntrySerializer.Serialize(parsed);

        using var document = System.Text.Json.JsonDocument.Parse(reserialized);
        document.RootElement.GetProperty("versionTime").GetString()
            .Should().Be("2026-03-01T00:00:00+00:00");
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
        json.Should().NotContain("weight", "did:webvh 1.0 no longer emits weighted policies");

        var parsed = LogEntrySerializer.DeserializeEntry(json);
        parsed.Parameters.Witness.Should().NotBeNull();
        parsed.Parameters.Witness!.Threshold.Should().Be(2);
        parsed.Parameters.Witness.Witnesses.Should().HaveCount(2);
    }

    [Fact]
    public void DeserializeAndSerialize_PreservesLegacyWitnessWeightForHashing()
    {
        var entry = CreateSampleEntry();
        entry = entry with
        {
            Parameters = new LogEntryParameters
            {
                Method = entry.Parameters.Method,
                Scid = entry.Parameters.Scid,
                UpdateKeys = entry.Parameters.UpdateKeys,
                Witness = new WitnessConfig
                {
                    Threshold = 1,
                    Witnesses = [new WitnessEntry { Id = "did:key:z6MkLegacy", Weight = 7 }]
                }
            }
        };
        var currentJson = LogEntrySerializer.Serialize(entry);
        var legacyJson = currentJson.Replace(
            "\"id\":\"did:key:z6MkLegacy\"",
            "\"id\":\"did:key:z6MkLegacy\",\"weight\":7",
            StringComparison.Ordinal);

        var parsed = LogEntrySerializer.DeserializeEntry(legacyJson);

        LogEntrySerializer.Serialize(parsed).Should().Be(legacyJson);
    }

    [Fact]
    public void SerializeAndDeserialize_EmptyWitnessObject_PreservesDisableTransition()
    {
        var entry = CreateSampleEntry() with
        {
            Parameters = new LogEntryParameters
            {
                Witness = new WitnessConfig()
            }
        };

        var json = LogEntrySerializer.Serialize(entry);
        var parsed = LogEntrySerializer.DeserializeEntry(json);

        json.Should().Contain("\"witness\":{}");
        parsed.Parameters.Witness.Should().NotBeNull();
        parsed.Parameters.Witness!.IsDisabled.Should().BeTrue();
        LogEntrySerializer.Serialize(parsed).Should().Be(json);
    }

    [Fact]
    public void Serialize_WholeSecond_KeepsLegacyWireRepresentation()
    {
        var json = LogEntrySerializer.SerializeWithoutProof(CreateSampleEntry());

        json.Should().Contain("\"versionTime\":\"2026-03-01T00:00:00Z\"");
    }

    [Fact]
    public void Serialize_RoundTrip_PreservesFractionalPrecision()
    {
        var timestamp = new DateTimeOffset(2026, 3, 1, 2, 0, 0, TimeSpan.FromHours(2))
            .AddTicks(1_234_567);
        var entry = CreateSampleEntry() with { VersionTime = timestamp };

        var json = LogEntrySerializer.SerializeWithoutProof(entry);
        var parsed = LogEntrySerializer.DeserializeEntry(json);

        json.Should().Contain("\"versionTime\":\"2026-03-01T00:00:00.1234567Z\"");
        parsed.VersionTime.Should().Be(timestamp.ToUniversalTime());
    }

    [Fact]
    public void SerializeAndDeserialize_AreIndependentOfCurrentCulture()
    {
        var entry = CreateSampleEntry() with
        {
            VersionTime = new DateTimeOffset(2026, 3, 1, 0, 0, 0, TimeSpan.Zero)
                .AddTicks(1_234_567)
        };
        var originalCulture = CultureInfo.CurrentCulture;
        var originalUiCulture = CultureInfo.CurrentUICulture;

        try
        {
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo("th-TH");
            CultureInfo.CurrentUICulture = CultureInfo.GetCultureInfo("th-TH");
            var json = LogEntrySerializer.SerializeWithoutProof(entry);

            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo("ar-SA");
            CultureInfo.CurrentUICulture = CultureInfo.GetCultureInfo("ar-SA");
            var parsed = LogEntrySerializer.DeserializeEntry(json);

            json.Should().Contain("\"versionTime\":\"2026-03-01T00:00:00.1234567Z\"");
            parsed.VersionTime.Should().Be(entry.VersionTime);
            LogEntrySerializer.SerializeWithoutProof(parsed).Should().Be(json);
        }
        finally
        {
            CultureInfo.CurrentCulture = originalCulture;
            CultureInfo.CurrentUICulture = originalUiCulture;
        }
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

[CollectionDefinition("Culture-sensitive", DisableParallelization = true)]
public sealed class CultureSensitiveCollection;
