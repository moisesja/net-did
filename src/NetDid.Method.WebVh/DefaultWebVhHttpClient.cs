namespace NetDid.Method.WebVh;

/// <summary>
/// Default HTTP implementation using System.Net.Http.HttpClient.
/// </summary>
public sealed class DefaultWebVhHttpClient : IWebVhHttpClient
{
    private readonly HttpClient _httpClient;

    public DefaultWebVhHttpClient(HttpClient? httpClient = null)
    {
        _httpClient = httpClient ?? new HttpClient();
    }

    public async Task<byte[]?> FetchDidLogAsync(Uri logUrl, CancellationToken ct = default)
    {
        try
        {
            var response = await _httpClient.GetAsync(logUrl, ct);
            if (!response.IsSuccessStatusCode) return null;
            return await response.Content.ReadAsByteArrayAsync(ct);
        }
        catch (HttpRequestException)
        {
            return null;
        }
    }

    public async Task<byte[]?> FetchWitnessFileAsync(Uri witnessUrl, CancellationToken ct = default)
    {
        try
        {
            var response = await _httpClient.GetAsync(witnessUrl, ct);
            if (!response.IsSuccessStatusCode) return null;
            return await response.Content.ReadAsByteArrayAsync(ct);
        }
        catch (HttpRequestException)
        {
            return null;
        }
    }
}
