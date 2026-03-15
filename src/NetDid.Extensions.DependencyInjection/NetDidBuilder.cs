using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using NetDid.Core;
using NetDid.Core.Crypto;
using NetDid.Core.Resolution;
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
    public NetDidBuilder AddDidWebVh()
    {
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
}
