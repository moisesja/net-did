namespace NetDid.Method.WebVh;

/// <summary>
/// Resource limits applied by <see cref="DefaultWebVhHttpClient"/> when fetching
/// did:webvh artifacts. Limits guard a resolver of untrusted DIDs against
/// memory exhaustion from oversized responses.
/// </summary>
public sealed record WebVhHttpClientOptions
{
    /// <summary>
    /// Maximum bytes accepted for <c>did.jsonl</c>. Default: 5 MiB.
    /// Responses with a larger <c>Content-Length</c> are rejected before
    /// the body is read; responses without <c>Content-Length</c> are
    /// streamed and aborted as soon as this many bytes are seen.
    /// </summary>
    public long MaxDidLogBytes { get; init; } = 5L * 1024 * 1024;

    /// <summary>
    /// Maximum bytes accepted for <c>did-witness.json</c>. Default: 1 MiB.
    /// Same enforcement as <see cref="MaxDidLogBytes"/>.
    /// </summary>
    public long MaxWitnessFileBytes { get; init; } = 1L * 1024 * 1024;
}
