using System.Diagnostics.CodeAnalysis;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using NetDid.Core.Model;
using NetDid.Core.Parsing;
using NetDid.Core.Serialization;

namespace NetDid.Method.Ethr.Resolution;

/// <summary>
/// Decodes a <c>did/svc/*</c> attribute value the way ethr-did-resolver does: strict UTF-8 (the
/// service is skipped otherwise), then <c>JSON.parse</c>, falling back to the raw string. Only what
/// W3C DID Core §5.4 can represent is kept: a URI string, a map, or a non-empty set of URI strings
/// and maps. Anything else drops that one service, never the whole document (issue #145).
/// </summary>
internal static partial class EthrServiceEndpoint
{
    // ethr-did-resolver: event.name.match(/^did\/(pub|svc)\/(\w+)(\/(\w+))?(\/(\w+))?$/), with the
    // service typed by the first segment. JavaScript's \w is ASCII-only.
    [GeneratedRegex(@"^did/svc/([A-Za-z0-9_]+)(?:/[A-Za-z0-9_]+)?(?:/[A-Za-z0-9_]+)?\z")]
    private static partial Regex ServiceNameRegex();

    /// <summary>
    /// The service type ethr-did-resolver gives a <c>did/svc/</c> attribute name, or null when the
    /// reference resolver does not turn that name into a service (it still counts it).
    /// </summary>
    public static string? ServiceType(string? name)
    {
        if (name is null)
            return null;
        var match = ServiceNameRegex().Match(name);
        return match.Success ? match.Groups[1].Value : null;
    }

    private static readonly UTF8Encoding StrictUtf8 = new(false, throwOnInvalidBytes: true);

    // The value becomes a serviceEndpoint three levels below the document root, and the document
    // must stay within the serializer's 64 levels to be written again.
    private const int MaxDepth = 61;

    public static bool TryDecode(byte[] value, out string text)
    {
        try
        {
            text = StrictUtf8.GetString(value);
            return true;
        }
        catch (DecoderFallbackException)
        {
            text = string.Empty;
            return false;
        }
    }

    public static bool TryParse(string value, [NotNullWhen(true)] out ServiceEndpointValue? endpoint)
    {
        endpoint = null;
        JsonDocument parsed;
        try
        {
            parsed = JsonDocument.Parse(value, new JsonDocumentOptions { MaxDepth = MaxDepth });
        }
        catch (JsonException)
        {
            // Not JSON: the reference resolver keeps the raw string.
            if (DidParser.IsAbsoluteUri(value))
                endpoint = ServiceEndpointValue.FromUri(value);
            return endpoint is not null;
        }

        JsonDocument normalized;
        using (parsed)
        {
            try
            {
                Utf16Text.RequireDecodable(parsed.RootElement);
            }
            catch (InvalidOperationException)
            {
                return false; // an unpaired surrogate or ill-formed text
            }

            // JSON.parse keeps a duplicate member's LAST value at its FIRST position. Rebuild the
            // value that way, so the published map never carries a duplicate member.
            var buffer = new System.Buffers.ArrayBufferWriter<byte>();
            using (var writer = new Utf8JsonWriter(buffer, new JsonWriterOptions { MaxDepth = MaxDepth + 1 }))
                WriteLastWins(writer, parsed.RootElement);
            normalized = JsonDocument.Parse(buffer.WrittenMemory, new JsonDocumentOptions { MaxDepth = MaxDepth });
        }

        using (normalized)
        {
            endpoint = FromElement(normalized.RootElement, allowSet: true);
            return endpoint is not null;
        }
    }

    private static void WriteLastWins(Utf8JsonWriter writer, JsonElement element)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                var order = new List<string>();
                var members = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
                foreach (var property in element.EnumerateObject())
                {
                    if (!members.ContainsKey(property.Name))
                        order.Add(property.Name);
                    members[property.Name] = property.Value;
                }
                writer.WriteStartObject();
                foreach (var name in order)
                {
                    writer.WritePropertyName(name);
                    WriteLastWins(writer, members[name]);
                }
                writer.WriteEndObject();
                break;
            case JsonValueKind.Array:
                writer.WriteStartArray();
                foreach (var item in element.EnumerateArray())
                    WriteLastWins(writer, item);
                writer.WriteEndArray();
                break;
            default:
                element.WriteTo(writer);
                break;
        }
    }

    private static ServiceEndpointValue? FromElement(JsonElement element, bool allowSet)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.String:
                var uri = element.GetString()!;
                return DidParser.IsAbsoluteUri(uri) ? ServiceEndpointValue.FromUri(uri) : null;
            case JsonValueKind.Object:
                return ServiceEndpointValue.FromMap(element.EnumerateObject()
                    .ToDictionary(p => p.Name, p => p.Value.Clone(), StringComparer.Ordinal));
            case JsonValueKind.Array when allowSet:
                var items = new List<ServiceEndpointValue>();
                foreach (var item in element.EnumerateArray())
                {
                    if (FromElement(item, allowSet: false) is not { } entry)
                        return null;
                    items.Add(entry);
                }
                return items.Count > 0 ? ServiceEndpointValue.FromSet(items) : null;
            default:
                return null;
        }
    }
}
