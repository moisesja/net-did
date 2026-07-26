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
        var value = GetRpcString(result, "eth_call result");
        if (!value.StartsWith("0x", StringComparison.Ordinal)
            || (value.Length - 2) % 2 != 0
            || !IsLowerHex(value.AsSpan(2)))
            throw new EthereumInteractionException(
                "Malformed eth_call result: expected canonical lowercase 0x-prefixed hex data.");
        return value;
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
        JsonArray resultArray;
        try
        {
            resultArray = result.AsArray();
        }
        catch (InvalidOperationException ex)
        {
            throw new EthereumInteractionException(
                "Malformed eth_getLogs result: expected an array.", ex);
        }

        for (var index = 0; index < resultArray.Count; index++)
        {
            var node = resultArray[index];
            if (node is null)
                throw new EthereumInteractionException(
                    $"Malformed eth_getLogs result: log entry {index} is null.");

            try
            {
                var obj = node.AsObject();
                var topicsNode = obj["topics"]
                    ?? throw new EthereumInteractionException(
                        $"Malformed eth_getLogs result: log entry {index} is missing 'topics'.");
                var topicArray = topicsNode.AsArray()
                    .Select((topic, topicIndex) => topic is null
                        ? throw new EthereumInteractionException(
                            $"Malformed eth_getLogs result: log entry {index} topic {topicIndex} is null.")
                        : GetString(topic, $"log entry {index} topic {topicIndex}"))
                    .ToList();
                var blockNumber = GetRequiredString(obj, "blockNumber", index);
                _ = ParseCanonicalHexQuantity(
                    blockNumber, $"eth_getLogs log entry {index} 'blockNumber'");
                var removed = GetOptionalBoolean(obj, "removed", index, defaultValue: false);
                if (removed)
                    throw new EthereumInteractionException(
                        $"Malformed eth_getLogs result: log entry {index} is marked 'removed' " +
                        "and cannot be replayed as canonical authorization state.");

                logs.Add(new EthereumLogEntry
                {
                    Address         = GetRequiredString(obj, "address", index),
                    Topics          = topicArray,
                    Data            = GetRequiredString(obj, "data", index),
                    BlockNumber     = blockNumber,
                    LogIndex        = GetRequiredHexUlong(obj, "logIndex", index),
                    TransactionHash = obj["transactionHash"] is { } transactionHash
                        ? GetString(transactionHash, $"log entry {index} 'transactionHash'")
                        : null,
                });
            }
            catch (EthereumInteractionException)
            {
                throw;
            }
            catch (Exception ex) when (ex is InvalidOperationException
                or FormatException or OverflowException or ArgumentException)
            {
                throw new EthereumInteractionException(
                    $"Malformed eth_getLogs result at log entry {index}.", ex);
            }
        }

        return logs;
    }

    public async Task<ulong> GetBlockNumberAsync(CancellationToken ct = default)
    {
        var result = await SendAsync("eth_blockNumber", [], ct);
        return ParseCanonicalHexQuantity(
            GetRpcString(result, "eth_blockNumber result"),
            "eth_blockNumber result");
    }

    public async Task<ulong> GetChainIdAsync(CancellationToken ct = default)
    {
        var result = await SendAsync("eth_chainId", [], ct);
        return ParseCanonicalHexQuantity(
            GetRpcString(result, "eth_chainId result"),
            "eth_chainId result");
    }

    public async Task<ulong> GetBlockTimestampAsync(ulong blockNumber, CancellationToken ct = default)
    {
        var result = await SendAsync("eth_getBlockByNumber",
            ["0x" + blockNumber.ToString("x"), false], ct);
        var block = GetRpcObject(result, "eth_getBlockByNumber result");
        var timestampNode = block["timestamp"]
            ?? throw new EthereumInteractionException(
                "Malformed eth_getBlockByNumber result: missing or null 'timestamp'.");
        return ParseCanonicalHexQuantity(
            GetRpcString(timestampNode, "eth_getBlockByNumber timestamp"),
            "eth_getBlockByNumber timestamp");
    }

    // ── Write (Update / Deactivate) ───────────────────────────────────────────

    public async Task<string> SendRawTransactionAsync(byte[] signedTransaction, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(signedTransaction);
        if (signedTransaction.Length == 0)
            throw new ArgumentException("Signed transaction must not be empty.", nameof(signedTransaction));

        var raw = "0x" + Convert.ToHexString(signedTransaction).ToLowerInvariant();
        var result = await SendAsync("eth_sendRawTransaction", [raw], ct);
        var hash = GetRpcString(result, "eth_sendRawTransaction result");

        // The node echoes keccak256(raw) — 32 bytes of canonical lowercase hex.
        if (hash.Length != 66
            || !hash.StartsWith("0x", StringComparison.Ordinal)
            || !IsLowerHex(hash.AsSpan(2)))
            throw new EthereumInteractionException(
                "Malformed eth_sendRawTransaction result: expected a canonical 32-byte transaction hash.");
        return hash;
    }

    public async Task<ulong> GetTransactionCountAsync(string address, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(address);
        var result = await SendAsync("eth_getTransactionCount", [address, "pending"], ct);
        return ParseCanonicalHexQuantity(
            GetRpcString(result, "eth_getTransactionCount result"),
            "eth_getTransactionCount result");
    }

    public async Task<ulong> GetGasPriceAsync(CancellationToken ct = default)
    {
        var result = await SendAsync("eth_gasPrice", [], ct);
        return ParseCanonicalHexQuantity(
            GetRpcString(result, "eth_gasPrice result"),
            "eth_gasPrice result");
    }

    public async Task<EthereumTransactionReceipt?> GetTransactionReceiptAsync(
        string transactionHash, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(transactionHash);

        // A pending/unknown transaction yields result: null — SendAsync treats a JSON null
        // result as absent, so probe the raw envelope through a dedicated call.
        var result = await SendAllowingNullResultAsync("eth_getTransactionReceipt", [transactionHash], ct);
        if (result is null)
            return null;

        var receipt = GetRpcObject(result, "eth_getTransactionReceipt result");

        var statusNode = receipt["status"]
            ?? throw new EthereumInteractionException(
                "Malformed eth_getTransactionReceipt result: missing or null 'status' " +
                "(pre-Byzantium receipts are not supported).");
        var status = GetRpcString(statusNode, "eth_getTransactionReceipt status");
        var succeeded = status switch
        {
            "0x1" => true,
            "0x0" => false,
            _ => throw new EthereumInteractionException(
                $"Malformed eth_getTransactionReceipt status '{status}': expected 0x0 or 0x1."),
        };

        var blockNumberNode = receipt["blockNumber"]
            ?? throw new EthereumInteractionException(
                "Malformed eth_getTransactionReceipt result: missing or null 'blockNumber'.");
        var blockNumber = ParseCanonicalHexQuantity(
            GetRpcString(blockNumberNode, "eth_getTransactionReceipt blockNumber"),
            "eth_getTransactionReceipt blockNumber");

        var hashNode = receipt["transactionHash"]
            ?? throw new EthereumInteractionException(
                "Malformed eth_getTransactionReceipt result: missing or null 'transactionHash'.");
        var reportedHash = GetRpcString(hashNode, "eth_getTransactionReceipt transactionHash");
        if (!string.Equals(reportedHash, transactionHash, StringComparison.OrdinalIgnoreCase))
            throw new EthereumInteractionException(
                $"eth_getTransactionReceipt returned a receipt for '{reportedHash}' " +
                $"instead of the requested '{transactionHash}'.");

        string? contractAddress = null;
        if (receipt.TryGetPropertyValue("contractAddress", out var contractNode) && contractNode is not null)
        {
            contractAddress = GetRpcString(contractNode, "eth_getTransactionReceipt contractAddress");
            if (contractAddress.Length != 42
                || !contractAddress.StartsWith("0x", StringComparison.Ordinal)
                || !IsLowerHex(contractAddress.AsSpan(2)))
                throw new EthereumInteractionException(
                    "Malformed eth_getTransactionReceipt contractAddress: expected a canonical " +
                    "lowercase 20-byte hex address.");
        }

        return new EthereumTransactionReceipt
        {
            TransactionHash = reportedHash,
            BlockNumber     = blockNumber,
            Succeeded       = succeeded,
            ContractAddress = contractAddress,
        };
    }

    public async Task<ulong> EstimateGasAsync(
        string from, string? to, string data, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(from);
        ArgumentNullException.ThrowIfNull(data);

        object call = to is null
            ? new { from, data }
            : new { from, to, data };
        var result = await SendAsync("eth_estimateGas", [call], ct);
        return ParseCanonicalHexQuantity(
            GetRpcString(result, "eth_estimateGas result"),
            "eth_estimateGas result");
    }

    // ── JSON-RPC helpers ──────────────────────────────────────────────────────

    private async Task<JsonNode> SendAsync(string method, object[] @params, CancellationToken ct)
    {
        return await SendAllowingNullResultAsync(method, @params, ct)
            ?? throw new EthereumInteractionException($"No 'result' field in RPC response for '{method}'.");
    }

    /// <summary>
    /// Like <see cref="SendAsync"/>, but a JSON-null / absent <c>result</c> returns
    /// <c>null</c> instead of throwing — required for eth_getTransactionReceipt, where
    /// null is the specified "still pending" answer.
    /// </summary>
    private async Task<JsonNode?> SendAllowingNullResultAsync(string method, object[] @params, CancellationToken ct)
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

        JsonObject responseObject;
        try
        {
            responseObject = body.AsObject();
        }
        catch (InvalidOperationException ex)
        {
            throw new EthereumInteractionException(
                $"Malformed RPC response for '{method}': the JSON envelope must be an object.",
                ex);
        }

        if (responseObject["error"] is JsonNode error)
            throw new EthereumInteractionException(
                $"RPC error for '{method}': {error}");

        return responseObject["result"];
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

    private static string GetRequiredString(JsonObject obj, string propertyName, int logIndex)
    {
        var node = obj[propertyName]
            ?? throw new EthereumInteractionException(
                $"Malformed eth_getLogs result: log entry {logIndex} is missing or has null '{propertyName}'.");
        return GetString(node, $"log entry {logIndex} '{propertyName}'");
    }

    private static string GetString(JsonNode node, string context)
    {
        if (node is JsonValue value && value.TryGetValue<string>(out var text) && text is not null)
            return text;

        throw new EthereumInteractionException(
            $"Malformed eth_getLogs result: {context} must be a string.");
    }

    private static ulong GetRequiredHexUlong(JsonObject obj, string propertyName, int logIndex)
    {
        var raw = GetRequiredString(obj, propertyName, logIndex);
        return ParseCanonicalHexQuantity(
            raw, $"eth_getLogs log entry {logIndex} '{propertyName}'");
    }

    private static ulong ParseCanonicalHexQuantity(string raw, string context)
    {
        try
        {
            if (!raw.StartsWith("0x", StringComparison.Ordinal)
                || raw.Length == 2
                || (raw.Length > 3 && raw[2] == '0')
                || !IsLowerHex(raw.AsSpan(2)))
                throw new FormatException("Ethereum quantities must use canonical 0x-prefixed form.");

            return Convert.ToUInt64(raw[2..], 16);
        }
        catch (Exception ex) when (ex is FormatException or OverflowException or ArgumentException)
        {
            throw new EthereumInteractionException(
                $"Malformed {context}: expected a canonical lowercase Ethereum hex quantity.",
                ex);
        }
    }

    private static bool GetOptionalBoolean(
        JsonObject obj, string propertyName, int logIndex, bool defaultValue)
    {
        if (!obj.TryGetPropertyValue(propertyName, out var node))
            return defaultValue;

        if (node is JsonValue value && value.TryGetValue<bool>(out var result))
            return result;

        throw new EthereumInteractionException(
            $"Malformed eth_getLogs result: log entry {logIndex} '{propertyName}' must be a boolean.");
    }

    private static string GetRpcString(JsonNode node, string context)
    {
        if (node is JsonValue value
            && value.TryGetValue<string>(out var result)
            && result is not null)
            return result;

        throw new EthereumInteractionException(
            $"Malformed {context}: expected a JSON string.");
    }

    private static JsonObject GetRpcObject(JsonNode node, string context)
    {
        if (node is JsonObject result)
            return result;

        throw new EthereumInteractionException(
            $"Malformed {context}: expected a JSON object.");
    }

    private static bool IsLowerHex(ReadOnlySpan<char> value)
    {
        foreach (var c in value)
        {
            if (!char.IsAsciiDigit(c) && c is not (>= 'a' and <= 'f'))
                return false;
        }
        return true;
    }
}
