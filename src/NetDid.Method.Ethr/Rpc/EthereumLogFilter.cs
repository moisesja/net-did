namespace NetDid.Method.Ethr.Rpc;

/// <summary>Filter parameters for eth_getLogs.</summary>
public sealed record EthereumLogFilter
{
    public required string Address { get; init; }
    public required ulong FromBlock { get; init; }
    public required ulong ToBlock { get; init; }
    /// <summary>topics[0] = OR-list of event signatures to match.</summary>
    public IReadOnlyList<string[]>? Topics { get; init; }
}
