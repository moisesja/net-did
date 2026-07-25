using System.Collections.Concurrent;

namespace NetDid.Method.Ethr.Rpc;

/// <summary>
/// Default implementation of <see cref="IEthereumRpcClientFactory"/>.
/// Uses <see cref="IHttpClientFactory"/> to obtain named <see cref="HttpClient"/> instances
/// whose base addresses are pre-configured via DI (see <c>NetDidBuilder.AddDidEthr</c>).
/// One <see cref="DefaultEthereumRpcClient"/> is created per network and cached for reuse.
/// </summary>
public sealed class DefaultEthereumRpcClientFactory : IEthereumRpcClientFactory
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ConcurrentDictionary<string, IEthereumRpcClient> _cache = new(StringComparer.OrdinalIgnoreCase);

    public DefaultEthereumRpcClientFactory(IHttpClientFactory httpClientFactory)
    {
        _httpClientFactory = httpClientFactory ?? throw new ArgumentNullException(nameof(httpClientFactory));
    }

    /// <inheritdoc/>
    public IEthereumRpcClient GetOrCreate(EthereumNetworkConfig network)
    {
        ArgumentNullException.ThrowIfNull(network);
        return _cache.GetOrAdd(network.Name, _ =>
        {
            // Named client "ethr-{networkName}" is registered by AddDidEthr with
            // BaseAddress = network.RpcUrl so each network talks to its own endpoint.
            var http = _httpClientFactory.CreateClient($"ethr-{network.Name}");
            return new DefaultEthereumRpcClient(http);
        });
    }

    /// <summary>
    /// Creates a factory for non-DI scenarios (samples, CLI tools, tests).
    /// Each network gets a dedicated <see cref="HttpClient"/> with its <see cref="EthereumNetworkConfig.RpcUrl"/>
    /// set as the base address. Prefer the DI path (<c>AddDidEthr</c>) in production.
    /// </summary>
    public static IEthereumRpcClientFactory CreateDirect(IEnumerable<EthereumNetworkConfig> networks)
    {
        var clients = networks.ToDictionary(
            n => n.Name,
            n => (IEthereumRpcClient)new DefaultEthereumRpcClient(
                new HttpClient { BaseAddress = new Uri(n.RpcUrl) }),
            StringComparer.OrdinalIgnoreCase);
        return new FixedClientFactory(clients);
    }

    // Used by CreateDirect — maps network name → pre-built client.
    private sealed class FixedClientFactory : IEthereumRpcClientFactory
    {
        private readonly IReadOnlyDictionary<string, IEthereumRpcClient> _clients;

        internal FixedClientFactory(Dictionary<string, IEthereumRpcClient> clients)
            => _clients = clients;

        public IEthereumRpcClient GetOrCreate(EthereumNetworkConfig network)
            => _clients.TryGetValue(network.Name, out var c) ? c
               : throw new InvalidOperationException(
                   $"No RPC client configured for network '{network.Name}'. "
                   + $"Known networks: {string.Join(", ", _clients.Keys)}");
    }
}
