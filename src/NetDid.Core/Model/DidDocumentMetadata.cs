using System.Text.Json.Serialization;
using NetDid.Core.Serialization;

namespace NetDid.Core.Model;

public sealed record DidDocumentMetadata
{
    /// <summary>
    /// When the DID was created, as asserted by the method. Informational only: DID Core §7.3
    /// mandates that the serialized form is normalized to whole seconds, so for methods whose
    /// versions can differ sub-second (e.g. did:webvh logs authored by other implementations)
    /// this value cannot identify a version. Use <see cref="VersionId"/> or
    /// <see cref="VersionTime"/> as version selectors — never feed the serialized
    /// <c>created</c> back as a <c>versionTime</c> resolution query.
    /// </summary>
    [JsonConverter(typeof(CanonicalUtcDateTimeOffsetJsonConverter))]
    public DateTimeOffset? Created { get; init; }

    /// <summary>
    /// When the DID was last updated, as asserted by the method. Informational only and
    /// serialized whole-second per DID Core §7.3 — see <see cref="Created"/>; never feed the
    /// serialized <c>updated</c> back as a <c>versionTime</c> resolution query.
    /// </summary>
    [JsonConverter(typeof(CanonicalUtcDateTimeOffsetJsonConverter))]
    public DateTimeOffset? Updated { get; init; }

    public bool? Deactivated { get; init; }
    public string? VersionId { get; init; }

    /// <summary>
    /// The instant of the resolved version. Together with <see cref="VersionId"/> this is a
    /// version <em>selector</em>: it serializes with full fractional precision because
    /// method-specific versions (did:webvh log entries) can be distinct only sub-second, and
    /// the serialized value must re-select the same version when used as a resolution query.
    /// </summary>
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
