namespace NetDid.Method.WebVh;

/// <summary>
/// Default HTTP implementation using <see cref="HttpClient"/>. Responses are
/// streamed with <see cref="HttpCompletionOption.ResponseHeadersRead"/> and
/// bounded by <see cref="WebVhHttpClientOptions"/> so a hostile did:webvh host
/// cannot exhaust the resolver's memory with an oversized response.
/// </summary>
public sealed class DefaultWebVhHttpClient : IWebVhHttpClient
{
    private readonly HttpClient _httpClient;
    private readonly WebVhHttpClientOptions _options;

    public DefaultWebVhHttpClient(
        HttpClient? httpClient = null,
        WebVhHttpClientOptions? options = null)
    {
        _httpClient = httpClient ?? new HttpClient();
        _options = options ?? new WebVhHttpClientOptions();
    }

    public Task<byte[]?> FetchDidLogAsync(Uri logUrl, CancellationToken ct = default)
        => FetchBoundedAsync(logUrl, _options.MaxDidLogBytes, ct);

    public Task<byte[]?> FetchWitnessFileAsync(Uri witnessUrl, CancellationToken ct = default)
        => FetchBoundedAsync(witnessUrl, _options.MaxWitnessFileBytes, ct);

    private async Task<byte[]?> FetchBoundedAsync(Uri url, long maxBytes, CancellationToken ct)
    {
        try
        {
            using var response = await _httpClient.GetAsync(
                url, HttpCompletionOption.ResponseHeadersRead, ct);

            if (!response.IsSuccessStatusCode)
                return null;

            if (response.Content.Headers.ContentLength is { } declared && declared > maxBytes)
                return null;

            await using var stream = await response.Content.ReadAsStreamAsync(ct);
            return await ReadAtMostAsync(stream, maxBytes, ct);
        }
        catch (HttpRequestException)
        {
            return null;
        }
    }

    /// <summary>
    /// Read at most <paramref name="maxBytes"/> from <paramref name="stream"/>.
    /// Returns null if the stream produces more than that many bytes.
    /// </summary>
    private static async Task<byte[]?> ReadAtMostAsync(
        Stream stream, long maxBytes, CancellationToken ct)
    {
        // Cap buffer growth at maxBytes. Use a small read buffer so a hostile
        // body that slow-trickles past the limit still terminates promptly.
        using var ms = new MemoryStream();
        var buffer = new byte[8192];
        long total = 0;

        while (true)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(), ct);
            if (read == 0) break;

            total += read;
            if (total > maxBytes)
                return null;

            ms.Write(buffer, 0, read);
        }

        return ms.ToArray();
    }
}
