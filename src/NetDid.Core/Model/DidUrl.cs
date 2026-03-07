namespace NetDid.Core.Model;

/// <summary>
/// A parsed DID URL: DID + optional path, query, and fragment.
/// </summary>
public sealed record DidUrl
{
    public required Did Did { get; init; }
    public string? Path { get; init; }
    public string? Query { get; init; }
    public string? Fragment { get; init; }

    public string FullUrl
    {
        get
        {
            var url = Did.Value;
            if (Path is not null) url += Path;
            if (Query is not null) url += "?" + Query;
            if (Fragment is not null) url += "#" + Fragment;
            return url;
        }
    }
}
