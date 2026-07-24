using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Nodes;
using NetDid.Core.Exceptions;

namespace NetDid.Method.Ethr.Rpc;

/// <summary>
/// Default Ethereum JSON-RPC 2.0 client backed by HttpClient.
/// Phase 2 methods throw <see cref="NotImplementedException"/>.
/// </summary>
public sealed class DefaultEthereumRpcClient : IEthereumRpcClient
{
    // Defensive bounds on an UNTRUSTED RPC endpoint. The response of a single
    // identity-filtered eth_getLogs for one block is small; these caps exist so a
    // hostile or compromised node cannot exhaust memory with a giant body or hang
    // resolution indefinitely. They only ever shorten behaviour — there is no
    // caller-configurable timeout on this client for them to silently override.
    private const long MaxResponseBytes = 16L * 1024 * 1024; // 16 MiB
    private static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(30);

    private readonly HttpClient _http;
    private static int _idCounter;

    public DefaultEthereumRpcClient(HttpClient http)
    {
        _http = http ?? throw new ArgumentNullException(nameof(http));
    }

    // ── Phase 1 ──────────────────────────────────────────────────────────────

    public async Task<string> CallAsync(string to, string data, CancellationToken ct = default)
    {
        var result = await SendAsync("eth_call",
            [new { to, data }, "latest"], ct);
        return result.GetValue<string>();
    }

    public async Task<IReadOnlyList<EthereumLogEntry>> GetLogsAsync(
        EthereumLogFilter filter, CancellationToken ct = default)
    {
        var filterParam = new
        {
            address = filter.Address,
            fromBlock = "0x" + filter.FromBlock.ToString("x"),
            toBlock   = "0x" + filter.ToBlock.ToString("x"),
            topics    = filter.Topics
        };

        var result = await SendAsync("eth_getLogs", [filterParam], ct);
        var logs = new List<EthereumLogEntry>();

        foreach (var node in result.AsArray())
        {
            if (node is null) continue;
            var obj = node.AsObject();
            var topicArray = obj["topics"]!.AsArray()
                .Select(t => t!.GetValue<string>())
                .ToList();

            logs.Add(new EthereumLogEntry
            {
                Address         = obj["address"]!.GetValue<string>(),
                Topics          = topicArray,
                Data            = obj["data"]!.GetValue<string>(),
                BlockNumber     = obj["blockNumber"]!.GetValue<string>(),
                TransactionHash = obj["transactionHash"]?.GetValue<string>(),
            });
        }

        return logs;
    }

    public async Task<ulong> GetBlockNumberAsync(CancellationToken ct = default)
    {
        var result = await SendAsync("eth_blockNumber", [], ct);
        return ParseHexUlong(result.GetValue<string>());
    }

    public async Task<ulong> GetChainIdAsync(CancellationToken ct = default)
    {
        var result = await SendAsync("eth_chainId", [], ct);
        return ParseHexUlong(result.GetValue<string>());
    }

    public async Task<ulong> GetBlockTimestampAsync(ulong blockNumber, CancellationToken ct = default)
    {
        var result = await SendAsync("eth_getBlockByNumber",
            ["0x" + blockNumber.ToString("x"), false], ct);
        var ts = result["timestamp"]!.GetValue<string>();
        return ParseHexUlong(ts);
    }

    // ── Phase 2 stubs ─────────────────────────────────────────────────────────

    public Task<string> SendRawTransactionAsync(byte[] signedTransaction, CancellationToken ct = default)
        => throw new NotImplementedException("Phase 2: SendRawTransaction not yet implemented.");

    public Task<ulong> GetTransactionCountAsync(string address, CancellationToken ct = default)
        => throw new NotImplementedException("Phase 2: GetTransactionCount not yet implemented.");

    public Task<ulong> GetGasPriceAsync(CancellationToken ct = default)
        => throw new NotImplementedException("Phase 2: GetGasPrice not yet implemented.");

    // ── JSON-RPC helpers ──────────────────────────────────────────────────────

    private async Task<JsonNode> SendAsync(string method, object[] @params, CancellationToken ct)
    {
        var id = Interlocked.Increment(ref _idCounter);
        var envelope = new { jsonrpc = "2.0", method, @params, id };

        // Own the timeout here: with ResponseHeadersRead the streaming body read
        // below is NOT covered by HttpClient.Timeout, so a slow-drip node could hang
        // it. A linked CTS bounds the whole round-trip (headers + body).
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeoutCts.CancelAfter(RequestTimeout);
        var token = timeoutCts.Token;

        using var request = new HttpRequestMessage(HttpMethod.Post, (Uri?)null)
        {
            Content = JsonContent.Create(envelope, options: JsonSerializerOptions.Default),
        };

        using var response = await _http.SendAsync(
            request, HttpCompletionOption.ResponseHeadersRead, token);

        if (!response.IsSuccessStatusCode)
            throw new EthereumInteractionException(
                $"RPC HTTP error {(int)response.StatusCode} for method '{method}'.");

        // Reject an over-large body before buffering it — by declared Content-Length
        // if honest, and by a running byte count regardless (a hostile node can lie).
        if (response.Content.Headers.ContentLength is { } declared && declared > MaxResponseBytes)
            throw new EthereumInteractionException(
                $"RPC response for '{method}' declares {declared} bytes, exceeding the {MaxResponseBytes}-byte cap.");

        byte[] bytes;
        await using (var stream = await response.Content.ReadAsStreamAsync(token))
            bytes = await ReadAtMostAsync(stream, MaxResponseBytes, method, token);

        JsonNode? body;
        try
        {
            body = JsonNode.Parse(bytes);
        }
        catch (JsonException ex)
        {
            throw new EthereumInteractionException(
                $"Malformed JSON in RPC response for '{method}'.", ex);
        }

        if (body is null)
            throw new EthereumInteractionException($"Empty RPC response for method '{method}'.");

        if (body["error"] is JsonNode error)
            throw new EthereumInteractionException(
                $"RPC error for '{method}': {error}");

        return body["result"]
            ?? throw new EthereumInteractionException($"No 'result' field in RPC response for '{method}'.");
    }

    /// <summary>
    /// Read at most <paramref name="maxBytes"/> from the response stream, counting
    /// bytes as they arrive (a hostile node can omit or understate Content-Length).
    /// </summary>
    private static async Task<byte[]> ReadAtMostAsync(
        Stream stream, long maxBytes, string method, CancellationToken ct)
    {
        using var ms = new MemoryStream();
        var buffer = new byte[8192];
        long total = 0;

        while (true)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(), ct);
            if (read == 0) break;

            total += read;
            if (total > maxBytes)
                throw new EthereumInteractionException(
                    $"RPC response for '{method}' exceeded the {maxBytes}-byte cap.");

            ms.Write(buffer, 0, read);
        }

        return ms.ToArray();
    }

    private static ulong ParseHexUlong(string hex)
    {
        var clean = hex.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? hex[2..] : hex;
        return Convert.ToUInt64(clean, 16);
    }
}
