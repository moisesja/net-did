namespace NetDid.Method.Ethr.Rpc;

/// <summary>
/// Optional capability for RPC clients that can resolve Ethereum's <c>finalized</c>
/// block tag. did:ethr resolution remains fully functional when a client does not
/// implement this interface or returns <c>null</c>.
/// </summary>
public interface IEthereumFinalityRpcClient
{
    /// <summary>
    /// Return the most recent finalized block number, or <c>null</c> when the chain or
    /// endpoint does not support the <c>finalized</c> tag.
    /// </summary>
    Task<ulong?> GetFinalizedBlockNumberAsync(CancellationToken ct = default);
}
