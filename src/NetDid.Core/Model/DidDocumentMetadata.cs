namespace NetDid.Core.Model;

public sealed record DidDocumentMetadata
{
    public DateTimeOffset? Created { get; init; }
    public DateTimeOffset? Updated { get; init; }
    public bool? Deactivated { get; init; }
    public string? VersionId { get; init; }
    public DateTimeOffset? VersionTime { get; init; }
    public string? NextVersionId { get; init; }
    public string? NextUpdate { get; init; }
    public IReadOnlyList<string>? EquivalentId { get; init; }
    public string? CanonicalId { get; init; }

    /// <summary>
    /// Convert to a property dictionary for use in DidUrlDereferencingResult.
    /// </summary>
    public IReadOnlyDictionary<string, object> ToPropertyDictionary()
    {
        var dict = new Dictionary<string, object>();
        if (Created.HasValue) dict["created"] = Created.Value;
        if (Updated.HasValue) dict["updated"] = Updated.Value;
        if (Deactivated.HasValue) dict["deactivated"] = Deactivated.Value;
        if (VersionId is not null) dict["versionId"] = VersionId;
        if (VersionTime.HasValue) dict["versionTime"] = VersionTime.Value;
        if (NextVersionId is not null) dict["nextVersionId"] = NextVersionId;
        if (NextUpdate is not null) dict["nextUpdate"] = NextUpdate;
        if (EquivalentId is not null) dict["equivalentId"] = EquivalentId;
        if (CanonicalId is not null) dict["canonicalId"] = CanonicalId;
        return dict;
    }
}
