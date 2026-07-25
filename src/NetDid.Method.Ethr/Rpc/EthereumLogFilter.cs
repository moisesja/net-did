namespace NetDid.Method.Ethr.Rpc;

/// <summary>Filter parameters for eth_getLogs.</summary>
public sealed record EthereumLogFilter
{
    public required string Address { get; init; }
    public required ulong FromBlock { get; init; }
    public required ulong ToBlock { get; init; }
    /// <summary>
    /// Positional topic filter matching the eth_getLogs spec.
    /// Each element of the outer list corresponds to a topic position (0-indexed).
    /// A null element means "match any topic at this position".
    /// A non-null element is an OR-list: the log matches if topics[i] equals any entry.
    /// Example: [[sig1,sig2], [paddedAddress]] → topics[0] in {sig1,sig2} AND topics[1]=paddedAddress.
    /// </summary>
    public IReadOnlyList<string[]?>? Topics { get; init; }
}
