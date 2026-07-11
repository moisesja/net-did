using System.Net;
using System.Net.Sockets;

namespace NetDid.Method.WebVh;

/// <summary>
/// Default HTTP implementation using <see cref="HttpClient"/>. Responses are
/// streamed with <see cref="HttpCompletionOption.ResponseHeadersRead"/> and
/// bounded by <see cref="WebVhHttpClientOptions"/> so a hostile did:webvh host
/// cannot exhaust the resolver's memory with an oversized response. Its default
/// transport rejects non-public destinations, DNS rebinding, redirects, and proxies.
/// </summary>
public sealed class DefaultWebVhHttpClient : IWebVhHttpClient, IDisposable
{
    private readonly HttpClient _httpClient;
    private readonly bool _ownsHttpClient;
    private readonly WebVhHttpClientOptions _options;

    /// <summary>
    /// Create the default webvh HTTP client.
    /// </summary>
    /// <param name="httpClient">
    /// Optional caller-controlled client. When supplied, the caller is responsible
    /// for equivalent DNS pinning and for disabling redirects and untrusted proxies.
    /// HTTPS and literal-address checks are still applied before each request.
    /// </param>
    /// <param name="options">Response-size limits.</param>
    public DefaultWebVhHttpClient(
        HttpClient? httpClient = null,
        WebVhHttpClientOptions? options = null)
    {
        _ownsHttpClient = httpClient is null;
        // For an owned client, options.Timeout is the sole time authority:
        // HttpClient.Timeout (100s framework default) enforces itself
        // independently and would silently cap any configured value above it,
        // so neutralize it. An injected client's Timeout is left untouched as
        // the caller's own independent bound.
        _httpClient = httpClient ?? new HttpClient(CreateSecurePrimaryHandler())
        {
            Timeout = Timeout.InfiniteTimeSpan
        };
        _options = options ?? new WebVhHttpClientOptions();
    }

    /// <summary>
    /// Create the hardened primary handler used by the default and DI clients.
    /// </summary>
    public static SocketsHttpHandler CreateSecurePrimaryHandler()
        => CreateSecurePrimaryHandler(
            static (host, ct) => Dns.GetHostAddressesAsync(host, ct),
            ConnectSocketAsync);

    internal static SocketsHttpHandler CreateSecurePrimaryHandler(
        Func<string, CancellationToken, Task<IPAddress[]>> resolver,
        Func<IPAddress, int, CancellationToken, ValueTask<Stream>> connector)
    {
        return new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseProxy = false,
            ConnectCallback = (context, ct) => ResolveAndConnectAsync(
                context.DnsEndPoint, resolver, connector, ct)
        };
    }

    public Task<byte[]?> FetchDidLogAsync(Uri logUrl, CancellationToken ct = default)
        => FetchBoundedAsync(logUrl, _options.MaxDidLogBytes, ct);

    public Task<byte[]?> FetchWitnessFileAsync(Uri witnessUrl, CancellationToken ct = default)
        => FetchBoundedAsync(witnessUrl, _options.MaxWitnessFileBytes, ct);

    private async Task<byte[]?> FetchBoundedAsync(Uri url, long maxBytes, CancellationToken ct)
    {
        if (!IsSafeRequestUri(url))
            return null;

        // Bound the total fetch time (headers + body) with a linked token.
        // HttpClient.Timeout is not enough here: with ResponseHeadersRead it
        // stops applying once headers arrive, so a host that withholds headers
        // or drips the body slowly could otherwise pin the caller for the full
        // framework default of 100s — or indefinitely (issue #80).
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeoutCts.CancelAfter(_options.Timeout);

        try
        {
            using var response = await _httpClient.GetAsync(
                url, HttpCompletionOption.ResponseHeadersRead, timeoutCts.Token);

            if (!response.IsSuccessStatusCode)
                return null;

            if (response.Content.Headers.ContentLength is { } declared && declared > maxBytes)
                return null;

            await using var stream = await response.Content.ReadAsStreamAsync(timeoutCts.Token);
            return await ReadAtMostAsync(stream, maxBytes, timeoutCts.Token);
        }
        catch (HttpRequestException)
        {
            return null;
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            // Our per-fetch timeout (or HttpClient.Timeout on an injected
            // client) fired without the caller's token being cancelled:
            // normalize to a failed fetch, keeping the #81 contract that only
            // genuine caller cancellation propagates.
            return null;
        }
    }

    private static bool IsSafeRequestUri(Uri url)
    {
        if (!url.IsAbsoluteUri
            || !url.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
            || !string.IsNullOrEmpty(url.UserInfo))
        {
            return false;
        }

        var canonicalHost = url.IdnHost;
        if (WebVhNetworkPolicy.IsLocalhost(canonicalHost))
            return false;

        return !IPAddress.TryParse(canonicalHost, out var address)
            || WebVhNetworkPolicy.IsPublicAddress(address);
    }

    internal static async ValueTask<Stream> ResolveAndConnectAsync(
        DnsEndPoint endpoint,
        Func<string, CancellationToken, Task<IPAddress[]>> resolver,
        Func<IPAddress, int, CancellationToken, ValueTask<Stream>> connector,
        CancellationToken ct)
    {
        IPAddress[] addresses;
        if (IPAddress.TryParse(endpoint.Host, out var literal))
        {
            addresses = [literal];
        }
        else
        {
            addresses = await resolver(endpoint.Host, ct);
        }

        if (addresses.Length == 0 || addresses.Any(a => !WebVhNetworkPolicy.IsPublicAddress(a)))
        {
            throw new HttpRequestException(
                $"Refusing connection to non-public host '{endpoint.Host}'.");
        }

        Exception? lastError = null;
        foreach (var address in addresses)
        {
            try
            {
                // Connect to the exact address that passed policy validation. The
                // hostname remains on the HTTP request for TLS SNI/certificate checks.
                return await connector(address, endpoint.Port, ct);
            }
            catch (Exception ex) when (ex is SocketException or IOException)
            {
                lastError = ex;
            }
        }

        throw new HttpRequestException(
            $"Unable to connect to public host '{endpoint.Host}'.", lastError);
    }

    private static async ValueTask<Stream> ConnectSocketAsync(
        IPAddress address, int port, CancellationToken ct)
    {
        var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        try
        {
            socket.NoDelay = true;
            await socket.ConnectAsync(new IPEndPoint(address, port), ct);
            return new NetworkStream(socket, ownsSocket: true);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Read at most <paramref name="maxBytes"/> from <paramref name="stream"/>.
    /// Returns null if the stream produces more than that many bytes.
    /// </summary>
    private static async Task<byte[]?> ReadAtMostAsync(
        Stream stream, long maxBytes, CancellationToken ct)
    {
        // Count bytes as they arrive instead of buffering the whole body up
        // front: a hostile host can omit or understate Content-Length, so the
        // cap has to be enforced on bytes actually read.
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

    public void Dispose()
    {
        if (_ownsHttpClient)
            _httpClient.Dispose();
    }
}
