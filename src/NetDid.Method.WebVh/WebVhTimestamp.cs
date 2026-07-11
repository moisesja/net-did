using System.Globalization;

namespace NetDid.Method.WebVh;

/// <summary>
/// Provides the canonical timestamp representation used by did:webvh log entries and proofs.
/// </summary>
internal static class WebVhTimestamp
{
    // Optional fractional digits preserve every authenticated DateTimeOffset tick while retaining
    // the exact whole-second representation emitted by earlier NetDid releases.
    private const string WireFormat = "yyyy-MM-dd'T'HH:mm:ss.FFFFFFF'Z'";
    private static readonly string[] AcceptedWireFormats =
    [
        "yyyy-MM-dd'T'HH:mm:ss'Z'",
        "yyyy-MM-dd'T'HH:mm:ss.f'Z'",
        "yyyy-MM-dd'T'HH:mm:ss.ff'Z'",
        "yyyy-MM-dd'T'HH:mm:ss.fff'Z'",
        "yyyy-MM-dd'T'HH:mm:ss.ffff'Z'",
        "yyyy-MM-dd'T'HH:mm:ss.fffff'Z'",
        "yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'",
        "yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'",
        "yyyy-MM-dd'T'HH:mm:sszzz",
        "yyyy-MM-dd'T'HH:mm:ss.fzzz",
        "yyyy-MM-dd'T'HH:mm:ss.ffzzz",
        "yyyy-MM-dd'T'HH:mm:ss.fffzzz",
        "yyyy-MM-dd'T'HH:mm:ss.ffffzzz",
        "yyyy-MM-dd'T'HH:mm:ss.fffffzzz",
        "yyyy-MM-dd'T'HH:mm:ss.ffffffzzz",
        "yyyy-MM-dd'T'HH:mm:ss.fffffffzzz"
    ];

    public static string Format(DateTimeOffset value)
        => value.ToUniversalTime().ToString(WireFormat, CultureInfo.InvariantCulture);

    /// <summary>
    /// Return the exact parsed wire representation when it still denotes the entry's timestamp.
    /// Hash/proof verification must preserve the authenticated JSON string instead of normalizing
    /// an attacker-supplied, semantically equivalent replacement before recomputing the hash.
    /// </summary>
    public static bool Matches(DateTimeOffset value, string? parsedWireValue)
    {
        return parsedWireValue is not null
            && TryParse(parsedWireValue, out var parsed)
            && parsed == value.ToUniversalTime();
    }

    public static DateTimeOffset Parse(string value)
        => TryParse(value, out var result)
            ? result
            : throw new FormatException("versionTime must be an explicit UTC ISO 8601 timestamp.");

    public static bool TryParse(string value, out DateTimeOffset result)
    {
        var hasExplicitUtcZone = value.EndsWith('Z')
            || value.EndsWith("+00:00", StringComparison.Ordinal);
        if (hasExplicitUtcZone
            && DateTimeOffset.TryParseExact(
                value,
                AcceptedWireFormats,
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                out var parsed)
            && parsed.Offset == TimeSpan.Zero)
        {
            result = parsed.ToUniversalTime();
            return true;
        }

        result = default;
        return false;
    }
}
