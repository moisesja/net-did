namespace NetDid.Method.Ethr.Rpc;

/// <summary>
/// The subset of an <c>eth_getTransactionReceipt</c> result the did:ethr write path needs.
/// A receipt exists only once the transaction has been mined; while pending,
/// <see cref="IEthereumRpcClient.GetTransactionReceiptAsync"/> returns <c>null</c>.
/// </summary>
public sealed record EthereumTransactionReceipt
{
    /// <summary>0x-prefixed transaction hash.</summary>
    public required string TransactionHash { get; init; }

    /// <summary>Block the transaction was mined in.</summary>
    public required ulong BlockNumber { get; init; }

    /// <summary>
    /// Post-Byzantium execution status: <c>true</c> for success (status 0x1),
    /// <c>false</c> for a reverted transaction (status 0x0).
    /// </summary>
    public required bool Succeeded { get; init; }

    /// <summary>
    /// For contract-creation transactions, the address of the deployed contract;
    /// null otherwise.
    /// </summary>
    public string? ContractAddress { get; init; }
}
