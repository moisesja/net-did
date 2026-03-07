using System.Text.Json;

namespace NetDid.Core.Model;

public sealed class Service
{
    /// <summary>DID URL (validated at deserialization).</summary>
    public required string Id { get; init; }

    public required string Type { get; init; }

    /// <summary>
    /// W3C DID Core §5.4: serviceEndpoint can be a URI string, a map (object),
    /// or an ordered set of URIs and/or maps.
    /// </summary>
    public required ServiceEndpointValue ServiceEndpoint { get; init; }

    public IReadOnlyDictionary<string, JsonElement>? AdditionalProperties { get; init; }
}
