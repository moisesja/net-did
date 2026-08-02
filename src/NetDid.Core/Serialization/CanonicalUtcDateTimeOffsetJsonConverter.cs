using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace NetDid.Core.Serialization;

/// <summary>
/// Serializes a <see cref="DateTimeOffset"/> in the canonical form the DID Resolution
/// specification requires for document-metadata timestamps (<c>created</c>,
/// <c>updated</c>, <c>versionTime</c>): ISO 8601 normalized to UTC, without sub-second
/// decimal precision — e.g. <c>2021-03-22T18:14:29Z</c>. The default System.Text.Json
/// representation (<c>2021-03-22T18:14:29+00:00</c>) is spec-valid XML datetime but does
/// not match the normalized form reference resolvers emit and compare against.
/// Reading accepts any ISO 8601 offset form and normalizes to UTC.
/// </summary>
public sealed class CanonicalUtcDateTimeOffsetJsonConverter : JsonConverter<DateTimeOffset>
{
    private const string CanonicalFormat = "yyyy'-'MM'-'dd'T'HH':'mm':'ss'Z'";

    /// <summary>Format a timestamp in the canonical UTC whole-second form.</summary>
    public static string Format(DateTimeOffset value)
        => value.UtcDateTime.ToString(CanonicalFormat, CultureInfo.InvariantCulture);

    public override DateTimeOffset Read(
        ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        => reader.GetDateTimeOffset();

    public override void Write(
        Utf8JsonWriter writer, DateTimeOffset value, JsonSerializerOptions options)
        => writer.WriteStringValue(Format(value));
}
