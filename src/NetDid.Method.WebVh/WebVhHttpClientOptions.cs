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

    /// <summary>
    /// Maximum wall-clock time for a single fetch, covering both response
    /// headers and the full body read. Default: 30 seconds. A fetch that
    /// exceeds this is treated as a failed fetch (the DID resolves as
    /// <c>notFound</c>); cancellation requested by the caller's own token is
    /// unaffected and still propagates. Must be positive, or
    /// <see cref="System.Threading.Timeout.InfiniteTimeSpan"/> to disable.
    /// Disabling removes the body-read bound entirely: only
    /// <see cref="HttpClient.Timeout"/> (100 seconds unless configured) still
    /// bounds time-to-headers, and nothing bounds a host that drips the body
    /// slowly — a hostile host can then pin a fetch indefinitely.
    /// </summary>
    public TimeSpan Timeout
    {
        get => _timeout;
        init => _timeout = value > TimeSpan.Zero || value == System.Threading.Timeout.InfiniteTimeSpan
            ? value
            : throw new ArgumentOutOfRangeException(nameof(Timeout), value,
                "Timeout must be positive, or Timeout.InfiniteTimeSpan to disable.");
    }

    private readonly TimeSpan _timeout = TimeSpan.FromSeconds(30);
}
