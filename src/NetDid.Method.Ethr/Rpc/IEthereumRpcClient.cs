namespace NetDid.Method.Ethr.Rpc;

/// <summary>
/// Ethereum JSON-RPC client interface used by the did:ethr method — read methods for
/// Create + Resolve, write methods for the on-chain Update / Deactivate path.
/// </summary>
public interface IEthereumRpcClient
{
    // ── Read (Create + Resolve) ──────────────────────────────────────────────

    /// <summary>eth_call — call a read-only contract function.</summary>
    Task<string> CallAsync(string to, string data, CancellationToken ct = default);

    /// <summary>eth_getLogs — fetch matching event logs.</summary>
    Task<IReadOnlyList<EthereumLogEntry>> GetLogsAsync(EthereumLogFilter filter, CancellationToken ct = default);

    /// <summary>eth_blockNumber — latest block number.</summary>
    Task<ulong> GetBlockNumberAsync(CancellationToken ct = default);

    /// <summary>eth_chainId — chain ID as ulong.</summary>
    Task<ulong> GetChainIdAsync(CancellationToken ct = default);

    /// <summary>
    /// eth_getBlockByNumber — returns the Unix timestamp of a specific block.
    /// Required for VersionId / VersionTime resolution.
    /// </summary>
    Task<ulong> GetBlockTimestampAsync(ulong blockNumber, CancellationToken ct = default);

    // ── Write (Update / Deactivate) ──────────────────────────────────────────

    /// <summary>eth_sendRawTransaction — broadcast a signed transaction; returns the 0x-prefixed tx hash.</summary>
    Task<string> SendRawTransactionAsync(byte[] signedTransaction, CancellationToken ct = default);

    /// <summary>eth_getTransactionCount (pending) — next nonce for an address.</summary>
    Task<ulong> GetTransactionCountAsync(string address, CancellationToken ct = default);

    /// <summary>eth_gasPrice — current gas price in wei.</summary>
    Task<ulong> GetGasPriceAsync(CancellationToken ct = default);

    /// <summary>
    /// eth_getTransactionReceipt — the mined transaction's receipt, or <c>null</c>
    /// while the transaction is still pending / unknown.
    /// </summary>
    Task<EthereumTransactionReceipt?> GetTransactionReceiptAsync(string transactionHash, CancellationToken ct = default);

    /// <summary>
    /// eth_estimateGas — gas estimate for a call. <paramref name="to"/> is null for a
    /// contract-creation transaction.
    /// </summary>
    Task<ulong> EstimateGasAsync(string from, string? to, string data, CancellationToken ct = default);
}
