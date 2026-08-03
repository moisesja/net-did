using System.Text.Json.Serialization;
using NetDid.Core.Serialization;

namespace NetDid.Core.Model;

public sealed record DidDocumentMetadata
{
    [JsonConverter(typeof(CanonicalUtcDateTimeOffsetJsonConverter))]
    public DateTimeOffset? Created { get; init; }

    [JsonConverter(typeof(CanonicalUtcDateTimeOffsetJsonConverter))]
    public DateTimeOffset? Updated { get; init; }

    public bool? Deactivated { get; init; }
    public string? VersionId { get; init; }

    [JsonConverter(typeof(FractionalUtcDateTimeOffsetJsonConverter))]
    public DateTimeOffset? VersionTime { get; init; }

    public string? NextVersionId { get; init; }
    public string? NextUpdate { get; init; }
    public IReadOnlyList<string>? EquivalentId { get; init; }
    public string? CanonicalId { get; init; }

    /// <summary>
    /// Convert to a property dictionary for use in DidUrlDereferencingResult.
    /// Timestamps are exposed as UTC strings. <c>created</c> and <c>updated</c> use
    /// canonical whole-second precision, while <c>versionTime</c> preserves fractional
    /// precision because it can identify a distinct method-specific version.
    /// </summary>
    public IReadOnlyDictionary<string, object> ToPropertyDictionary()
    {
        var dict = new Dictionary<string, object>();
        if (Created.HasValue)
            dict["created"] = CanonicalUtcDateTimeOffsetJsonConverter.Format(Created.Value);
        if (Updated.HasValue)
            dict["updated"] = CanonicalUtcDateTimeOffsetJsonConverter.Format(Updated.Value);
        if (Deactivated.HasValue) dict["deactivated"] = Deactivated.Value;
        if (VersionId is not null) dict["versionId"] = VersionId;
        if (VersionTime.HasValue)
            dict["versionTime"] = FractionalUtcDateTimeOffsetJsonConverter.Format(VersionTime.Value);
        if (NextVersionId is not null) dict["nextVersionId"] = NextVersionId;
        if (NextUpdate is not null) dict["nextUpdate"] = NextUpdate;
        if (EquivalentId is not null) dict["equivalentId"] = EquivalentId;
        if (CanonicalId is not null) dict["canonicalId"] = CanonicalId;
        return dict;
    }
}
