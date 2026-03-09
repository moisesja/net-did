using NetDid.Method.WebVh;

namespace NetDid.Method.WebVh.Tests;

/// <summary>
/// In-memory mock for IWebVhHttpClient that returns pre-configured content.
/// </summary>
internal sealed class MockWebVhHttpClient : IWebVhHttpClient
{
    private readonly Dictionary<string, byte[]> _logResponses = new();
    private readonly Dictionary<string, byte[]> _witnessResponses = new();

    public void SetLogResponse(Uri url, byte[] content)
    {
        _logResponses[url.ToString()] = content;
    }

    public void SetWitnessResponse(Uri url, byte[] content)
    {
        _witnessResponses[url.ToString()] = content;
    }

    public Task<byte[]?> FetchDidLogAsync(Uri logUrl, CancellationToken ct = default)
    {
        _logResponses.TryGetValue(logUrl.ToString(), out var content);
        return Task.FromResult(content);
    }

    public Task<byte[]?> FetchWitnessFileAsync(Uri witnessUrl, CancellationToken ct = default)
    {
        _witnessResponses.TryGetValue(witnessUrl.ToString(), out var content);
        return Task.FromResult(content);
    }
}
