using System.Diagnostics.CodeAnalysis;
using System.Text;
using System.Text.Json;
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
internal static class EthrServiceEndpoint
{
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
        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(value, new JsonDocumentOptions
            {
                AllowDuplicateProperties = false,
                MaxDepth = MaxDepth
            });
        }
        catch (JsonException)
        {
            // Not JSON (or not acceptable JSON): the reference resolver keeps the raw string.
            if (DidParser.IsAbsoluteUri(value))
                endpoint = ServiceEndpointValue.FromUri(value);
            return endpoint is not null;
        }
        catch (InvalidOperationException)
        {
            // An undecodable member name: duplicate rejection decodes names while parsing.
            return false;
        }

        using (document)
        {
            try
            {
                Utf16Text.RequireDecodable(document.RootElement);
            }
            catch (InvalidOperationException)
            {
                return false;
            }

            endpoint = FromElement(document.RootElement, allowSet: true);
            return endpoint is not null;
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
