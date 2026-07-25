namespace NetDid.Method.Ethr.Rpc;

/// <summary>
/// Creates or returns a cached <see cref="IEthereumRpcClient"/> for a given network.
/// Each network's client is configured with the correct RPC base URL so that
/// multi-network configurations never query the wrong chain.
/// </summary>
public interface IEthereumRpcClientFactory
{
    /// <summary>
    /// Returns the <see cref="IEthereumRpcClient"/> for <paramref name="network"/>,
    /// creating and caching it on first call.
    /// </summary>
    IEthereumRpcClient GetOrCreate(EthereumNetworkConfig network);
}
