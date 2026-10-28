using System.Text;
using System.Text.Json;
using NetDid.Core.Model;
using NetDid.Core.Serialization;

namespace NetDid.Method.Peer;

/// <summary>
/// Encodes and decodes service blocks for did:peer numalgo 2.
/// Uses the DIF-specified abbreviation scheme for compact DID strings.
/// </summary>
internal static class Numalgo2ServiceEncoder
{
    // Abbreviation map per DIF did:peer spec
    private static readonly Dictionary<string, string> AbbreviateMap = new()
    {
        ["type"] = "t",
        ["serviceEndpoint"] = "s",
        ["routingKeys"] = "r",
        ["accept"] = "a",
        ["DIDCommMessaging"] = "dm"
    };

    private static readonly UTF8Encoding StrictUtf8 = new(false, throwOnInvalidBytes: true);

    private static readonly Dictionary<string, string> ExpandMap =
        AbbreviateMap.ToDictionary(kv => kv.Value, kv => kv.Key);

    /// <summary>
    /// Encode a service as an abbreviated JSON string, then base64url-encode it (no padding).
    /// </summary>
    public static string Encode(Service service)
    {
        var abbreviated = new Dictionary<string, object>();

        // Preserve explicit service ID in the encoded block
        if (!string.IsNullOrEmpty(service.Id) && service.Id.StartsWith('#'))
            abbreviated["id"] = Text(service.Id);

        // Type
        var type = AbbreviateMap.TryGetValue(service.Type, out var abbrevType)
            ? abbrevType
            : Text(service.Type);
        abbreviated["t"] = type;

        // ServiceEndpoint
        abbreviated["s"] = SerializeEndpoint(service.ServiceEndpoint);

        // Additional properties (routingKeys, accept, etc.)
        if (service.AdditionalProperties is not null)
        {
            foreach (var (key, value) in service.AdditionalProperties)
            {
                var abbrevKey = AbbreviateMap.TryGetValue(key, out var ak) ? ak : Text(key);
                // A colliding key would overwrite an encoded member, so the DID would encode a
                // different service than the caller's (e.g. "serviceEndpoint" replacing "s"), and
                // "id" would become the resolved service id (issue #145).
                if (abbrevKey == "id" || !abbreviated.TryAdd(abbrevKey, Element(value)))
                    throw new ArgumentException(
                        "A did:peer:2 service extension member collides with an encoded member " +
                        "(id, type/t, serviceEndpoint/s, or another extension after abbreviation).");
            }
        }

        var json = JsonSerializer.Serialize(abbreviated, new JsonSerializerOptions
        {
            WriteIndented = false
        });

        return Convert.ToBase64String(Encoding.UTF8.GetBytes(json))
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    /// <summary>
    /// Decode a base64url-encoded abbreviated service JSON back to a Service.
    /// Per spec: if encoded JSON contains an explicit "id", preserve it;
    /// otherwise auto-generate: first = "#service", subsequent = "#service-1", etc.
    /// </summary>
    public static Service Decode(string encoded, ref int autoServiceIndex)
    {
        var base64 = encoded.Replace('-', '+').Replace('_', '/');
        // Add padding
        switch (base64.Length % 4)
        {
            case 2: base64 += "=="; break;
            case 3: base64 += "="; break;
        }

        // Strict: ill-formed UTF-8 must fail, not resolve as U+FFFD (issue #145).
        var json = StrictUtf8.GetString(Convert.FromBase64String(base64));
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        // Expand type
        var type = root.GetProperty("t").GetString()!;
        if (ExpandMap.TryGetValue(type, out var expandedType))
            type = expandedType;

        // Expand service endpoint
        var endpointElement = root.GetProperty("s");
        var endpoint = DeserializeEndpoint(endpointElement);

        // Check for explicit service ID
        string serviceId;
        if (root.TryGetProperty("id", out var idElement))
        {
            serviceId = idElement.GetString()!;
        }
        else
        {
            serviceId = autoServiceIndex == 0 ? "#service" : $"#service-{autoServiceIndex}";
            autoServiceIndex++;
        }

        // Collect additional expanded properties
        Dictionary<string, JsonElement>? additional = null;
        foreach (var prop in root.EnumerateObject())
        {
            if (prop.Name is "t" or "s" or "id") continue;
            var expandedKey = ExpandMap.TryGetValue(prop.Name, out var ek) ? ek : prop.Name;
            additional ??= new Dictionary<string, JsonElement>();
            additional[expandedKey] = prop.Value.Clone();
        }

        return new Service
        {
            Id = serviceId,
            Type = type,
            ServiceEndpoint = endpoint,
            AdditionalProperties = additional
        };
    }

    // JsonSerializer silently replaces an unpaired surrogate with U+FFFD, so the DID would encode
    // a service that differs from the caller's while Create reported success (issue #145).
    private static string Text(string value)
        => Utf16Text.IsWellFormed(value)
            ? value
            : throw new ArgumentException(
                "A did:peer:2 service contains a string with an unpaired UTF-16 surrogate, which " +
                "cannot be encoded as UTF-8 without altering it.");

    // JsonSerializer would rewrite ill-formed UTF-8 inside a caller JsonElement as U+FFFD (issue #145).
    private static JsonElement Element(JsonElement value)
    {
        if (value.ValueKind == JsonValueKind.Undefined)
            throw new ArgumentException("A did:peer:2 service contains an undefined JSON value.");

        try
        {
            Utf16Text.RequireDecodable(value);
            return value;
        }
        catch (InvalidOperationException ex)
        {
            throw new ArgumentException(
                "A did:peer:2 service contains a JSON value that cannot be read, or whose text is " +
                "not well-formed UTF-8 or UTF-16, so it cannot be encoded without altering it.",
                ex);
        }
    }

    private static object SerializeEndpoint(ServiceEndpointValue endpoint)
    {
        if (endpoint.IsUri) return Text(endpoint.Uri!);
        if (endpoint.IsMap)
        {
            var map = new Dictionary<string, object>();
            foreach (var (key, value) in endpoint.Map!)
                map[Text(key)] = Element(value);
            return map;
        }
        if (endpoint.IsSet)
        {
            // W3C DID Core §5.4: set entries are URIs or maps (the model forbids nesting too).
            return endpoint.Set!
                .Select(item => item is null || item.IsSet
                    ? throw new ArgumentException(
                        "A did:peer:2 serviceEndpoint set entry must be a URI or a map.")
                    : SerializeEndpoint(item))
                .ToList();
        }
        throw new InvalidOperationException("Invalid ServiceEndpointValue");
    }

    private static ServiceEndpointValue DeserializeEndpoint(JsonElement element)
    {
        return element.ValueKind switch
        {
            JsonValueKind.String => ServiceEndpointValue.FromUri(element.GetString()!),
            JsonValueKind.Object => ServiceEndpointValue.FromMap(
                element.EnumerateObject().ToDictionary(p => p.Name, p => p.Value.Clone())),
            JsonValueKind.Array => ServiceEndpointValue.FromSet(
                element.EnumerateArray().Select(DeserializeEndpoint).ToList()),
            _ => throw new JsonException($"Unexpected endpoint value kind: {element.ValueKind}")
        };
    }
}
