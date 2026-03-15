namespace NetDid.Method.WebVh;

/// <summary>
/// HTTP client abstraction for fetching did:webvh log and witness files.
/// Default implementation uses HttpClient. Callers inject mocks for testing.
/// </summary>
public interface IWebVhHttpClient
{
    /// <summary>Fetch the did.jsonl log file from the given URL.</summary>
    Task<byte[]?> FetchDidLogAsync(Uri logUrl, CancellationToken ct = default);

    /// <summary>Fetch the did-witness.json witness file from the given URL.</summary>
    Task<byte[]?> FetchWitnessFileAsync(Uri witnessUrl, CancellationToken ct = default);
}
