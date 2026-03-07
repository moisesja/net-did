using System.Globalization;
using System.Text.Json;
using StringBuilder = System.Text.StringBuilder;

namespace NetDid.Core.Crypto.Jcs;

/// <summary>
/// JSON Canonicalization Scheme (JCS) per RFC 8785.
/// Produces deterministic JSON serialization for Data Integrity Proofs.
/// </summary>
public static class JsonCanonicalization
{
    /// <summary>Canonicalize a JSON string per RFC 8785.</summary>
    public static string Canonicalize(string json)
    {
        using var doc = JsonDocument.Parse(json);
        return Canonicalize(doc.RootElement);
    }

    /// <summary>Canonicalize a JsonElement per RFC 8785.</summary>
    public static string Canonicalize(JsonElement element)
    {
        var sb = new StringBuilder();
        WriteCanonical(sb, element);
        return sb.ToString();
    }

    /// <summary>Canonicalize a JSON string and return UTF-8 bytes.</summary>
    public static byte[] CanonicalizeToUtf8(string json)
    {
        return System.Text.Encoding.UTF8.GetBytes(Canonicalize(json));
    }

    private static void WriteCanonical(StringBuilder sb, JsonElement element)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                WriteObject(sb, element);
                break;
            case JsonValueKind.Array:
                WriteArray(sb, element);
                break;
            case JsonValueKind.String:
                WriteString(sb, element.GetString()!);
                break;
            case JsonValueKind.Number:
                WriteNumber(sb, element);
                break;
            case JsonValueKind.True:
                sb.Append("true");
                break;
            case JsonValueKind.False:
                sb.Append("false");
                break;
            case JsonValueKind.Null:
                sb.Append("null");
                break;
        }
    }

    private static void WriteObject(StringBuilder sb, JsonElement element)
    {
        sb.Append('{');

        // RFC 8785: properties sorted by Unicode code point
        var properties = element.EnumerateObject()
            .OrderBy(p => p.Name, StringComparer.Ordinal)
            .ToList();

        for (int i = 0; i < properties.Count; i++)
        {
            if (i > 0) sb.Append(',');
            WriteString(sb, properties[i].Name);
            sb.Append(':');
            WriteCanonical(sb, properties[i].Value);
        }

        sb.Append('}');
    }

    private static void WriteArray(StringBuilder sb, JsonElement element)
    {
        sb.Append('[');
        int i = 0;
        foreach (var item in element.EnumerateArray())
        {
            if (i > 0) sb.Append(',');
            WriteCanonical(sb, item);
            i++;
        }
        sb.Append(']');
    }

    private static void WriteString(StringBuilder sb, string value)
    {
        sb.Append('"');
        foreach (var c in value)
        {
            switch (c)
            {
                case '"': sb.Append("\\\""); break;
                case '\\': sb.Append("\\\\"); break;
                case '\b': sb.Append("\\b"); break;
                case '\f': sb.Append("\\f"); break;
                case '\n': sb.Append("\\n"); break;
                case '\r': sb.Append("\\r"); break;
                case '\t': sb.Append("\\t"); break;
                default:
                    if (c < 0x20)
                        sb.Append($"\\u{(int)c:x4}");
                    else
                        sb.Append(c);
                    break;
            }
        }
        sb.Append('"');
    }

    private static void WriteNumber(StringBuilder sb, JsonElement element)
    {
        // RFC 8785: numbers serialized per ES6 Number.prototype.toString()
        // This means IEEE 754 double-precision, no trailing zeros,
        // scientific notation for very large/small numbers.
        var value = element.GetDouble();

        if (double.IsNaN(value) || double.IsInfinity(value))
            throw new JsonException("JCS does not support NaN or Infinity.");

        // Use ES6-style number formatting
        sb.Append(FormatEs6Number(value));
    }

    /// <summary>
    /// Format a number according to ES6 Number.prototype.toString() semantics.
    /// </summary>
    internal static string FormatEs6Number(double value)
    {
        if (value == 0.0)
            return double.IsNegative(value) ? "-0" : "0";

        // Check if value is an integer
        if (value == Math.Truncate(value) && Math.Abs(value) < 1e21)
            return ((decimal)value).ToString("0", CultureInfo.InvariantCulture);

        // Use R format to get round-trippable representation
        var str = value.ToString("R", CultureInfo.InvariantCulture);

        // ES6 uses lowercase 'e' for exponents
        return str.Replace('E', 'e');
    }
}
