using System.Text.Json;

namespace NetDid.Core.Serialization;

/// <summary>
/// UTF-16 well-formedness check for text NetDid publishes. <c>Utf8JsonWriter</c>,
/// <c>JsonSerializer</c> and <c>Encoding.UTF8</c> all silently replace an unpaired surrogate with
/// U+FFFD, so writing such a string would publish bytes that differ from the caller's input while
/// the operation reports success (issue #145). Writers check with this first and reject instead.
/// </summary>
internal static class Utf16Text
{
    public static bool IsWellFormed(ReadOnlySpan<char> text)
    {
        for (var i = 0; i < text.Length; i++)
        {
            if (char.IsHighSurrogate(text[i]))
            {
                if (i + 1 == text.Length || !char.IsLowSurrogate(text[i + 1]))
                    return false;
                i++;
            }
            else if (char.IsLowSurrogate(text[i]))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Decodes every member name and string value in <paramref name="element"/>, throwing
    /// <see cref="InvalidOperationException"/> when one is ill-formed UTF-8 or holds an unpaired
    /// surrogate escape. <c>System.Text.Json</c> parses such text without complaint and decodes
    /// it only when read, so a reader would otherwise fail outside its boundary and a writer
    /// (<c>JsonElement.WriteTo</c>) would silently emit U+FFFD instead (issue #145).
    /// </summary>
    public static void RequireDecodable(JsonElement element)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                foreach (var property in element.EnumerateObject())
                {
                    _ = property.Name;
                    RequireDecodable(property.Value);
                }
                break;
            case JsonValueKind.Array:
                foreach (var item in element.EnumerateArray())
                    RequireDecodable(item);
                break;
            case JsonValueKind.String:
                _ = element.GetString();
                break;
        }
    }
}
