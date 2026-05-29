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

        using var response = await _http.PostAsJsonAsync(
            (Uri?)null, envelope, JsonSerializerOptions.Default, ct);

        if (!response.IsSuccessStatusCode)
            throw new EthereumInteractionException(
                $"RPC HTTP error {(int)response.StatusCode} for method '{method}'.");

        var body = await response.Content.ReadFromJsonAsync<JsonNode>(ct)
            ?? throw new EthereumInteractionException($"Empty RPC response for method '{method}'.");

        if (body["error"] is JsonNode error)
            throw new EthereumInteractionException(
                $"RPC error for '{method}': {error}");

        return body["result"]
            ?? throw new EthereumInteractionException($"No 'result' field in RPC response for '{method}'.");
    }

    private static ulong ParseHexUlong(string hex)
    {
        var clean = hex.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? hex[2..] : hex;
        return Convert.ToUInt64(clean, 16);
    }
}
