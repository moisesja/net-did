namespace NetDid.Method.WebVh;

/// <summary>
/// Well-known artifact keys produced by <see cref="DidWebVhMethod"/> on
/// <see cref="Core.Model.DidCreateResult.Artifacts"/>,
/// <see cref="Core.Model.DidUpdateResult.Artifacts"/>,
/// <see cref="Core.Model.DidDeactivateResult.Artifacts"/>, and (when
/// <see cref="Core.Model.DidResolutionOptions.IncludeLog"/> is set)
/// <see cref="Core.Model.DidResolutionResult.Artifacts"/>.
/// </summary>
public static class DidWebVhArtifacts
{
    /// <summary>UTF-8 <see cref="string"/> contents of the <c>did.jsonl</c> log.</summary>
    public const string DidJsonl = "did.jsonl";

    /// <summary>UTF-8 <see cref="string"/> contents of the did:web-compatible <c>did.json</c> document.</summary>
    public const string DidJson = "did.json";

    /// <summary>UTF-8 <see cref="string"/> contents of the <c>did-witness.json</c> file (present only when witnesses are configured).</summary>
    public const string DidWitnessJson = "did-witness.json";

    /// <summary>Parsed log chain as <see cref="System.Collections.Generic.IReadOnlyList{T}"/> of <see cref="Model.LogEntry"/>, exposed by the resolver when <see cref="Core.Model.DidResolutionOptions.IncludeLog"/> is set.</summary>
    public const string LogEntries = "log.entries";
}
