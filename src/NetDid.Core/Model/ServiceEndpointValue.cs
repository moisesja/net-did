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

    /// <summary>
    /// Creates a set endpoint. W3C DID Core §5.4 allows "a set composed of one or more strings
    /// and/or maps", so each entry must be a URI or a map, never another set or null. The reader
    /// rejects a nested set, so no producer may be able to build one (issue #145). The entries are
    /// copied once, so the validated set cannot change after construction.
    /// </summary>
    /// <exception cref="ArgumentException">The set is empty, or an entry is null or a set.</exception>
    public static ServiceEndpointValue FromSet(IReadOnlyList<ServiceEndpointValue> set)
    {
        ArgumentNullException.ThrowIfNull(set);
        var entries = set.ToArray();
        if (entries.Length == 0) throw new ArgumentException("Set must contain at least one entry.", nameof(set));
        foreach (var entry in entries)
        {
            if (entry is null || entry.IsSet)
                throw new ArgumentException(
                    "Set entries must be URIs or maps; a set may not contain null or another set " +
                    "(W3C DID Core §5.4).",
                    nameof(set));
        }
        return new(null, null, entries);
    }

    /// <summary>Implicit conversion from string for ergonomic URI creation.</summary>
    public static implicit operator ServiceEndpointValue(string uri) => FromUri(uri);
}
