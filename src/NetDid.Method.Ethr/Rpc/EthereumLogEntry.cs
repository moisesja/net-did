namespace NetDid.Method.Ethr.Rpc;

/// <summary>A single entry from eth_getLogs.</summary>
public sealed record EthereumLogEntry
{
    public required string Address { get; init; }
    /// <summary>topics[0] = event signature hash; topics[1] = indexed identity address.</summary>
    public required IReadOnlyList<string> Topics { get; init; }
    /// <summary>ABI-encoded non-indexed event parameters (hex string, 0x-prefixed).</summary>
    public required string Data { get; init; }
    /// <summary>Block number as hex string (e.g., "0x1a4").</summary>
    public required string BlockNumber { get; init; }
    /// <summary>
    /// Block-global log index. Canonical intra-block ordering key: within a block the
    /// replay outcome depends on event order (a same-block add→revoke must apply in that
    /// order), so we sort by this rather than trusting the node's response array order.
    /// </summary>
    public ulong LogIndex { get; init; }
    public string? TransactionHash { get; init; }
}
