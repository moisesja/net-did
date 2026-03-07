namespace NetDid.Core.Model;

public sealed record DidDeactivateResult
{
    public required bool Success { get; init; }
    public IReadOnlyDictionary<string, object>? Artifacts { get; init; }
}
