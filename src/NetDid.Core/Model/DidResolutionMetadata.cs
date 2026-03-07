namespace NetDid.Core.Model;

public sealed record DidResolutionMetadata
{
    /// <summary>"notFound", "invalidDid", "methodNotSupported", etc.</summary>
    public string? Error { get; init; }
    public string? ContentType { get; init; }
    public DateTimeOffset? Retrieved { get; init; }
    public IReadOnlyDictionary<string, object>? AdditionalProperties { get; init; }
}
