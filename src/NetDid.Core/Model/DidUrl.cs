namespace NetDid.Core.Model;

/// <summary>
/// A parsed DID URL: DID + optional path, parameters, query, and fragment.
/// </summary>
public sealed record DidUrl
{
    public required Did Did { get; init; }
    public string? Path { get; init; }

    /// <summary>DID parameters (the portion after ';' and before '?' or '#').</summary>
    public string? Parameters { get; init; }

    public string? Query { get; init; }
    public string? Fragment { get; init; }

    public string FullUrl
    {
        get
        {
            var url = Did.Value;
            if (Path is not null) url += Path;
            if (Parameters is not null) url += ";" + Parameters;
            if (Query is not null) url += "?" + Query;
            if (Fragment is not null) url += "#" + Fragment;
            return url;
        }
    }
}
