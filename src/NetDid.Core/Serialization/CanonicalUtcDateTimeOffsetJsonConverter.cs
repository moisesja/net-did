using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace NetDid.Core.Serialization;

/// <summary>
/// Serializes a <see cref="DateTimeOffset"/> in the canonical form the DID Resolution
/// specification requires for whole-second document-metadata timestamps such as
/// <c>created</c> and <c>updated</c>: ISO 8601 normalized to UTC, without sub-second
/// decimal precision — e.g. <c>2021-03-22T18:14:29Z</c>. The default System.Text.Json
/// representation (<c>2021-03-22T18:14:29+00:00</c>) is spec-valid XML datetime but does
/// not match the normalized form reference resolvers emit and compare against.
/// Reading requires an explicit UTC or numeric offset and normalizes it to UTC.
/// </summary>
public sealed class CanonicalUtcDateTimeOffsetJsonConverter : JsonConverter<DateTimeOffset>
{
    private const string CanonicalFormat = "yyyy'-'MM'-'dd'T'HH':'mm':'ss'Z'";

    /// <summary>Format a timestamp in the canonical UTC whole-second form.</summary>
    public static string Format(DateTimeOffset value)
        => value.UtcDateTime.ToString(CanonicalFormat, CultureInfo.InvariantCulture);

    public override DateTimeOffset Read(
        ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        => ReadUtc(ref reader);

    public override void Write(
        Utf8JsonWriter writer, DateTimeOffset value, JsonSerializerOptions options)
        => writer.WriteStringValue(Format(value));

    internal static DateTimeOffset ReadUtc(ref Utf8JsonReader reader)
    {
        if (reader.TokenType != JsonTokenType.String)
            throw new JsonException("Expected an ISO 8601 timestamp string with an explicit UTC or numeric offset.");

        var value = reader.GetString();
        if (value is null || !HasExplicitOffset(value) ||
            !reader.TryGetDateTimeOffset(out var parsed))
        {
            throw new JsonException(
                "Expected an ISO 8601 timestamp with an explicit UTC or numeric offset.");
        }

        return parsed.ToUniversalTime();
    }

    private static bool HasExplicitOffset(string value)
    {
        if (value.EndsWith('Z'))
            return true;

        if (value.Length < 6)
            return false;

        var offset = value.AsSpan(value.Length - 6);
        return (offset[0] is '+' or '-') &&
               IsAsciiDigit(offset[1]) &&
               IsAsciiDigit(offset[2]) &&
               offset[3] == ':' &&
               IsAsciiDigit(offset[4]) &&
               IsAsciiDigit(offset[5]);
    }

    private static bool IsAsciiDigit(char value) => value is >= '0' and <= '9';
}
