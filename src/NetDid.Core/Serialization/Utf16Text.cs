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
}
