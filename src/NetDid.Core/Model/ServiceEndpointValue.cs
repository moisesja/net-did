using System.Text.Json;

namespace NetDid.Core.Model;

/// <summary>
/// Represents the polymorphic serviceEndpoint value per W3C DID Core §5.4.
/// Exactly one variant is set — enforced by private constructor and factory methods.
/// </summary>
public sealed class ServiceEndpointValue
{
    public string? Uri { get; }
    public IReadOnlyDictionary<string, JsonElement>? Map { get; }
    public IReadOnlyList<ServiceEndpointValue>? Set { get; }

    public bool IsUri => Uri is not null;
    public bool IsMap => Map is not null;
    public bool IsSet => Set is not null;

    private ServiceEndpointValue(string? uri, IReadOnlyDictionary<string, JsonElement>? map,
        IReadOnlyList<ServiceEndpointValue>? set)
    {
        Uri = uri;
        Map = map;
        Set = set;
    }

    public static ServiceEndpointValue FromUri(string uri)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(uri);
        return new(uri, null, null);
    }

    public static ServiceEndpointValue FromMap(IReadOnlyDictionary<string, JsonElement> map)
    {
        ArgumentNullException.ThrowIfNull(map);
        return new(null, map, null);
    }

    public static ServiceEndpointValue FromSet(IReadOnlyList<ServiceEndpointValue> set)
    {
        ArgumentNullException.ThrowIfNull(set);
        if (set.Count == 0) throw new ArgumentException("Set must contain at least one entry.", nameof(set));
        return new(null, null, set);
    }

    /// <summary>Implicit conversion from string for ergonomic URI creation.</summary>
    public static implicit operator ServiceEndpointValue(string uri) => FromUri(uri);
}
