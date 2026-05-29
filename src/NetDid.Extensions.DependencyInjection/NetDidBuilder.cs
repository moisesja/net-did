using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using NetDid.Core;
using NetDid.Core.Crypto;
using NetDid.Core.Resolution;
using NetDid.Method.Ethr;
using NetDid.Method.Ethr.Rpc;
using NetDid.Method.Key;
using NetDid.Method.Peer;
using NetDid.Method.WebVh;

namespace NetDid.Extensions.DependencyInjection;

/// <summary>
/// Builder for configuring NetDid services in a dependency injection container.
/// </summary>
public sealed class NetDidBuilder
{
    internal IServiceCollection Services { get; }
    internal bool CachingEnabled { get; private set; }
    internal TimeSpan CacheTtl { get; private set; }

    internal NetDidBuilder(IServiceCollection services)
    {
        Services = services;

        // Register shared infrastructure (idempotent via TryAdd)
        services.TryAddSingleton<IKeyGenerator, DefaultKeyGenerator>();
        services.TryAddSingleton<ICryptoProvider, DefaultCryptoProvider>();
    }

    /// <summary>Register the did:key method.</summary>
    public NetDidBuilder AddDidKey()
    {
        Services.AddSingleton<IDidMethod>(sp =>
            new DidKeyMethod(sp.GetRequiredService<IKeyGenerator>()));
        return this;
    }

    /// <summary>Register the did:peer method.</summary>
    public NetDidBuilder AddDidPeer()
    {
        Services.AddSingleton<IDidMethod>(sp =>
            new DidPeerMethod(sp.GetRequiredService<IKeyGenerator>()));
        return this;
    }

    /// <summary>Register the did:webvh method. Uses IHttpClientFactory for HTTP requests.</summary>
    public NetDidBuilder AddDidWebVh(WebVhHttpClientOptions? httpClientOptions = null)
    {
        Services.AddSingleton(httpClientOptions ?? new WebVhHttpClientOptions());
        Services.AddHttpClient<DefaultWebVhHttpClient>();
        Services.AddSingleton<IWebVhHttpClient>(sp =>
            sp.GetRequiredService<DefaultWebVhHttpClient>());
        Services.AddSingleton<IDidMethod>(sp =>
            new DidWebVhMethod(
                sp.GetRequiredService<IWebVhHttpClient>(),
                sp.GetRequiredService<ICryptoProvider>()));
        return this;
    }

    /// <summary>Enable resolution caching with the specified TTL.</summary>
    public NetDidBuilder AddCaching(TimeSpan ttl)
    {
        CachingEnabled = true;
        CacheTtl = ttl;
        return this;
    }

    /// <summary>
    /// Register the did:ethr method.
    /// Uses IHttpClientFactory for RPC HTTP requests.
    /// </summary>
    public NetDidBuilder AddDidEthr(IEnumerable<EthereumNetworkConfig> networks)
    {
        var networkList = networks.ToList();
        Services.AddHttpClient<DefaultEthereumRpcClient>();
        Services.AddSingleton<IEthereumRpcClient>(
            sp => sp.GetRequiredService<DefaultEthereumRpcClient>());
        Services.AddSingleton<IDidMethod>(sp =>
            new DidEthrMethod(
                sp.GetRequiredService<IEthereumRpcClient>(),
                networkList,
                sp.GetRequiredService<IKeyGenerator>(),
                sp.GetService<ILogger<DidEthrMethod>>()));
        return this;
    }

    /// <summary>
    /// Register the did:ethr method using well-known network metadata from <see cref="KnownNetworks"/>.
    /// The caller supplies only RPC URLs; registry addresses and chain IDs are looked up automatically.
    /// <code>
    /// builder.AddDidEthr(new Dictionary&lt;string, string&gt;
    /// {
    ///     ["mainnet"] = "https://mainnet.gateway.tenderly.co",
    ///     ["sepolia"] = "https://sepolia.drpc.org",
    /// });
    /// </code>
    /// Throws <see cref="InvalidOperationException"/> if a name is not found in <see cref="KnownNetworks.All"/>.
    /// </summary>
    public NetDidBuilder AddDidEthr(IReadOnlyDictionary<string, string> networkRpcUrls)
    {
        var configs = networkRpcUrls.Select(kv =>
        {
            var known = KnownNetworks.Find(kv.Key)
                ?? throw new InvalidOperationException(
                    $"Unknown did:ethr network '{kv.Key}'. " +
                    $"Use AddDidEthr(IEnumerable<EthereumNetworkConfig>) to supply a custom config.");
            return known with { RpcUrl = kv.Value };
        });
        return AddDidEthr(configs);
    }
}
