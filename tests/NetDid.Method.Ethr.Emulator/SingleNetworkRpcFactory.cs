using NetDid.Method.Ethr.Rpc;

namespace NetDid.Method.Ethr.Emulator;

/// <summary>Maps one network name to one fixed <see cref="IEthereumRpcClient"/> (tests/samples).</summary>
public sealed class SingleNetworkRpcFactory(string networkName, IEthereumRpcClient client)
    : IEthereumRpcClientFactory
{
    public IEthereumRpcClient GetOrCreate(EthereumNetworkConfig network)
        => string.Equals(network.Name, networkName, StringComparison.OrdinalIgnoreCase)
            ? client
            : throw new InvalidOperationException(
                $"No RPC client configured for network '{network.Name}'.");
}
