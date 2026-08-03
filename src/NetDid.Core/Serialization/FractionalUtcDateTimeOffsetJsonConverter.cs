using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace NetDid.Core.Serialization;

/// <summary>
/// Serializes a <see cref="DateTimeOffset"/> as UTC while preserving meaningful
/// fractional-second precision. This is intended for metadata such as
/// <c>versionTime</c>, where fractional precision can identify a distinct version.
/// Reading requires an explicit UTC or numeric offset and normalizes it to UTC.
/// </summary>
public sealed class FractionalUtcDateTimeOffsetJsonConverter : JsonConverter<DateTimeOffset>
{
    private const string CanonicalFormat = "yyyy'-'MM'-'dd'T'HH':'mm':'ss.FFFFFFF'Z'";

    /// <summary>Format a timestamp in UTC while preserving meaningful fractional digits.</summary>
    public static string Format(DateTimeOffset value)
        => value.UtcDateTime.ToString(CanonicalFormat, CultureInfo.InvariantCulture);

    public override DateTimeOffset Read(
        ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        => CanonicalUtcDateTimeOffsetJsonConverter.ReadUtc(ref reader);

    public override void Write(
        Utf8JsonWriter writer, DateTimeOffset value, JsonSerializerOptions options)
        => writer.WriteStringValue(Format(value));
}
