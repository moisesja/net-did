using System.Text.Json;
using FluentAssertions;
using NetDid.Core.Model;
using NetDid.Core.Serialization;
using Xunit;

namespace NetDid.Core.Tests.Serialization;

/// <summary>
/// Issue #117 (PR #126 review): the externally consumed representations of
/// DidDocumentMetadata timestamps must be the canonical DID Resolution form — ISO 8601
/// normalized UTC without sub-second precision (e.g. <c>2021-03-22T18:14:29Z</c>) —
/// matching the reference ethr-did-resolver. Default System.Text.Json serialization of
/// a bare <see cref="DateTimeOffset"/> renders <c>+00:00</c> instead, so both the JSON
/// serialization and the dereferencing property map need the canonical converter.
/// </summary>
public class Issue117MetadataCanonicalTimestampTests
{
    private static readonly DidDocumentMetadata Metadata = new()
    {
        Created     = DateTimeOffset.FromUnixTimeSeconds(100),
        Updated     = DateTimeOffset.FromUnixTimeSeconds(200),
        VersionId   = "20",
        VersionTime = DateTimeOffset.FromUnixTimeSeconds(150),
        NextVersionId = "30",
        NextUpdate  = "1970-01-01T00:05:00Z",
    };

    [Fact]
    public void Issue117_DefaultJsonSerialization_EmitsCanonicalZForm()
    {
        // The PR-review repro: default serialization previously produced
        // "updated":"1970-01-01T00:03:20+00:00" next to "nextUpdate":"...Z".
        var json = JsonSerializer.Serialize(Metadata,
            new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase });

        json.Should().Contain("\"updated\":\"1970-01-01T00:03:20Z\"");
        json.Should().Contain("\"created\":\"1970-01-01T00:01:40Z\"");
        json.Should().Contain("\"versionTime\":\"1970-01-01T00:02:30Z\"");
        json.Should().Contain("\"nextUpdate\":\"1970-01-01T00:05:00Z\"");
        json.Should().NotContain("+00:00");
    }

    [Fact]
    public void Issue117_JsonSerialization_RoundTrips()
    {
        var options = new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
        var json = JsonSerializer.Serialize(Metadata, options);

        var back = JsonSerializer.Deserialize<DidDocumentMetadata>(json, options)!;

        back.Should().Be(Metadata);
    }

    [Fact]
    public void Issue117_CanonicalConverter_ReadsNonUtcOffsetsNormalized()
    {
        // Reading tolerates any ISO 8601 offset form and normalizes to the same instant.
        var json = "{\"updated\":\"1970-01-01T02:03:20+02:00\"}";

        var back = JsonSerializer.Deserialize<DidDocumentMetadata>(json,
            new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase })!;

        back.Updated.Should().Be(DateTimeOffset.FromUnixTimeSeconds(200));
    }

    [Fact]
    public void Issue117_ToPropertyDictionary_ExposesCanonicalStrings()
    {
        // The dereferencing ContentMetadata map is an externally consumed representation:
        // timestamps must surface as canonical strings, not DateTimeOffset objects.
        var dict = Metadata.ToPropertyDictionary();

        dict["created"].Should().Be("1970-01-01T00:01:40Z");
        dict["updated"].Should().Be("1970-01-01T00:03:20Z");
        dict["versionTime"].Should().Be("1970-01-01T00:02:30Z");
        dict["nextUpdate"].Should().Be("1970-01-01T00:05:00Z");
    }

    [Fact]
    public void Issue117_CanonicalFormat_TruncatesSubSecondPrecision()
    {
        // DID Resolution: "without sub-second decimal precision".
        var value = DateTimeOffset.FromUnixTimeSeconds(200).AddMilliseconds(987);

        CanonicalUtcDateTimeOffsetJsonConverter.Format(value)
            .Should().Be("1970-01-01T00:03:20Z");
    }
}
