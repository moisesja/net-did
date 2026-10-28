using System.Buffers;
using System.Text;
using System.Text.Json;
using NetDid.Core.Model;
using NetDid.Core.Parsing;
using NetDid.Core.Serialization;

namespace NetDid.Method.Peer;

/// <summary>
/// Encodes and decodes service blocks for did:peer numalgo 2.
/// Uses the DIF-specified abbreviation scheme for compact DID strings.
/// </summary>
internal static class Numalgo2ServiceEncoder
{
    // DIF did:peer spec: "Recursively replace common strings in key names and type value with
    // abbreviations". Member names are abbreviated at every depth (also inside serviceEndpoint);
    // the only abbreviated value is the type DIDCommMessaging. The two tables never mix: a type
    // "t" is not "type", and a member "dm" is not "DIDCommMessaging" (issue #145).
    private static readonly Dictionary<string, string> NameAbbreviations = new(StringComparer.Ordinal)
    {
        ["type"] = "t",
        ["serviceEndpoint"] = "s",
        ["routingKeys"] = "r",
        ["accept"] = "a"
    };

    private static readonly Dictionary<string, string> NameExpansions =
        NameAbbreviations.ToDictionary(kv => kv.Value, kv => kv.Key, StringComparer.Ordinal);

    private const string DidCommMessaging = "DIDCommMessaging";
    private const string DidCommMessagingAbbreviation = "dm";

    // The block's root becomes a service object two levels below the document root, and the
    // document must stay within the serializer's 64 levels (issue #145).
    private const int MaxBlockDepth = 62;

    private static readonly UTF8Encoding StrictUtf8 = new(false, throwOnInvalidBytes: true);

    /// <summary>
    /// Encode a service as an abbreviated JSON string, then base64url-encode it (no padding).
    /// </summary>
    public static string Encode(Service service)
    {
        ArgumentNullException.ThrowIfNull(service);
        // A null type or endpoint crashed below (ArgumentNullException / NullReferenceException).
        if (service.Type is null || service.ServiceEndpoint is null)
            throw new ArgumentException("A did:peer:2 service requires a type and a serviceEndpoint.");

        var abbreviated = new Dictionary<string, object>();

        // "For use with did:peer:2, service id attributes MUST be relative" (DIF spec). An explicit
        // id is kept as written; only a missing one is generated on resolution. A relative id
        // without a leading '#' used to be dropped and replaced silently (issue #145).
        if (!string.IsNullOrEmpty(service.Id))
        {
            if (!DidParser.IsRelativeDidUrl(service.Id))
                throw new ArgumentException(
                    "A did:peer:2 service id must be a relative DID URL (DIF did:peer: \"service id " +
                    "attributes MUST be relative\").");
            abbreviated["id"] = Text(service.Id);
        }

        // Type: only the value DIDCommMessaging is abbreviated. A type of "dm" would resolve as
        // DIDCommMessaging, so it cannot be published as written.
        if (service.Type == DidCommMessagingAbbreviation)
            throw new ArgumentException(
                "A did:peer:2 service type of 'dm' resolves as DIDCommMessaging; use the full type.");
        abbreviated["t"] = service.Type == DidCommMessaging ? DidCommMessagingAbbreviation : Text(service.Type);

        // ServiceEndpoint
        abbreviated["s"] = AbbreviateEndpoint(service.ServiceEndpoint, depth: 2);

        // Additional properties (routingKeys, accept, etc.)
        if (service.AdditionalProperties is not null)
        {
            foreach (var (key, value) in service.AdditionalProperties)
            {
                var abbrevKey = AbbreviateName(key);
                // A colliding key would overwrite an encoded member, so the DID would encode a
                // different service than the caller's (e.g. "serviceEndpoint" replacing "s"), and
                // "id" would become the resolved service id (issue #145).
                if (abbrevKey == "id" || !abbreviated.TryAdd(abbrevKey, AbbreviateValue(Element(value), depth: 2)))
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
        // The same consumption rules as Core (issues #121, #145): duplicate members fail closed
        // and every member name and string must decode, so a resolved service is always one the
        // writer can publish again.
        // MaxDepth 62: the block's root becomes a service object two levels below the document
        // root, and the document must stay within the serializer's 64 levels, or the resolved
        // document could not be written again (issue #145).
        using var doc = JsonDocument.Parse(json, new JsonDocumentOptions
        {
            AllowDuplicateProperties = false,
            MaxDepth = MaxBlockDepth
        });
        var root = doc.RootElement;
        Utf16Text.RequireDecodable(root);

        // Expand the type value: only "dm" is an abbreviated value
        var type = RequireString(root, "t");
        if (type == DidCommMessagingAbbreviation)
            type = DidCommMessaging;

        // Expand service endpoint (member names at every depth)
        if (!root.TryGetProperty("s", out var endpointElement))
            throw new JsonException("A did:peer:2 service block is missing 's'.");
        var endpoint = DeserializeEndpoint(ExpandNames(endpointElement));

        // Check for explicit service ID ("service id attributes MUST be relative")
        string serviceId;
        if (root.TryGetProperty("id", out _))
        {
            serviceId = RequireString(root, "id");
            if (!DidParser.IsRelativeDidUrl(serviceId))
                throw new JsonException("A did:peer:2 service id must be a relative DID URL.");
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
            var expandedKey = NameExpansions.TryGetValue(prop.Name, out var ek) ? ek : prop.Name;
            // A reserved or colliding key (e.g. "serviceEndpoint" beside "s", or "r" beside
            // "routingKeys") must not silently shadow or replace a member (issue #145).
            if (expandedKey is "id" or "type" or "serviceEndpoint")
                throw new JsonException("A did:peer:2 service block uses a reserved member name.");
            additional ??= new Dictionary<string, JsonElement>();
            if (!additional.TryAdd(expandedKey, ExpandNames(prop.Value)))
                throw new JsonException("A did:peer:2 service block has colliding member names.");
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

    private static object AbbreviateEndpoint(ServiceEndpointValue endpoint, int depth)
    {
        if (endpoint.IsUri) return Text(endpoint.Uri!);
        if (endpoint.IsMap)
        {
            var map = new Dictionary<string, object>();
            foreach (var (key, value) in endpoint.Map!)
            {
                if (!map.TryAdd(AbbreviateName(key), AbbreviateValue(Element(value), depth + 1)))
                    throw new ArgumentException("A did:peer:2 serviceEndpoint map has a duplicate key.");
            }
            return map;
        }
        if (endpoint.IsSet)
        {
            // W3C DID Core §5.4: set entries are URIs or maps (the model forbids nesting too).
            return endpoint.Set!
                .Select(item => item is null || item.IsSet
                    ? throw new ArgumentException(
                        "A did:peer:2 serviceEndpoint set entry must be a URI or a map.")
                    : AbbreviateEndpoint(item, depth + 1))
                .ToList();
        }
        throw new InvalidOperationException("Invalid ServiceEndpointValue");
    }

    // A member name as encoded: type/serviceEndpoint/routingKeys/accept become t/s/r/a. A name
    // that IS one of those abbreviations would resolve as the long name, so it is refused rather
    // than published as something else (issue #145).
    private static string AbbreviateName(string name)
    {
        Text(name);
        if (NameExpansions.TryGetValue(name, out var expanded))
            throw new ArgumentException(
                $"A did:peer:2 service member named '{name}' resolves as '{expanded}'; use the full name.");
        return NameAbbreviations.TryGetValue(name, out var abbreviation) ? abbreviation : name;
    }

    // A caller JSON value with its member names abbreviated at every depth. The recursion is
    // bounded: a block deeper than MaxBlockDepth could not be resolved anyway.
    private static object AbbreviateValue(JsonElement value, int depth)
    {
        if (depth > MaxBlockDepth)
            throw new ArgumentException(
                $"A did:peer:2 service is nested deeper than {MaxBlockDepth} levels.");
        switch (value.ValueKind)
        {
            case JsonValueKind.Object:
                var map = new Dictionary<string, object>();
                foreach (var property in value.EnumerateObject())
                {
                    if (!map.TryAdd(AbbreviateName(property.Name), AbbreviateValue(property.Value, depth + 1)))
                        throw new ArgumentException("A did:peer:2 service value has a duplicate member name.");
                }
                return map;
            case JsonValueKind.Array:
                return value.EnumerateArray().Select(item => AbbreviateValue(item, depth + 1)).ToList();
            default:
                return value;
        }
    }

    // The decoded value with abbreviated member names expanded at every depth. Two names that
    // expand to one ("a" beside "accept") fail closed. Depth is bounded by the block's MaxDepth.
    private static JsonElement ExpandNames(JsonElement element)
    {
        var buffer = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(buffer))
            WriteExpanded(writer, element);
        using var expanded = JsonDocument.Parse(buffer.WrittenMemory, new JsonDocumentOptions { MaxDepth = MaxBlockDepth });
        return expanded.RootElement.Clone();
    }

    private static void WriteExpanded(Utf8JsonWriter writer, JsonElement element)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                var names = new HashSet<string>(StringComparer.Ordinal);
                writer.WriteStartObject();
                foreach (var property in element.EnumerateObject())
                {
                    var name = NameExpansions.TryGetValue(property.Name, out var full) ? full : property.Name;
                    if (!names.Add(name))
                        throw new JsonException("A did:peer:2 service block has colliding member names.");
                    writer.WritePropertyName(name);
                    WriteExpanded(writer, property.Value);
                }
                writer.WriteEndObject();
                break;
            case JsonValueKind.Array:
                writer.WriteStartArray();
                foreach (var item in element.EnumerateArray())
                    WriteExpanded(writer, item);
                writer.WriteEndArray();
                break;
            default:
                element.WriteTo(writer);
                break;
        }
    }

    private static string RequireString(JsonElement root, string member)
        => root.TryGetProperty(member, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()!
            : throw new JsonException($"A did:peer:2 service block's '{member}' must be a string.");

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
