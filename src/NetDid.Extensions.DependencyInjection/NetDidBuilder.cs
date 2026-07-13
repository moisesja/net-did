using Microsoft.Extensions.DependencyInjection;
using NetDid.Core;
using NetCrypto;
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

        // Register shared crypto infrastructure (ICryptoProvider, IBbsCryptoProvider,
        // IKeyGenerator) from NetCrypto. Idempotent via TryAdd; IKeyStore is intentionally
        // not registered (matches prior behaviour).
        services.AddNetCrypto();
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

    /// <summary>
    /// Register the did:webvh method with the default controller-proof verification budget.
    /// Uses IHttpClientFactory for HTTP requests.
    /// </summary>
    public NetDidBuilder AddDidWebVh(WebVhHttpClientOptions? httpClientOptions = null)
        => AddDidWebVh(
            httpClientOptions,
            DidWebVhMethod.DefaultMaxControllerProofsPerEntry);

    /// <summary>
    /// Register the did:webvh method with a caller-specified upper bound on controller proofs
    /// verified per log entry. Uses IHttpClientFactory for HTTP requests.
    /// </summary>
    /// <param name="httpClientOptions">Resource limits for fetching did:webvh artifacts.</param>
    /// <param name="maxControllerProofsPerEntry">
    /// Maximum controller proofs verified per entry. Must be at least one. Raising this limit
    /// increases the canonicalization and signature-verification work an untrusted log can cause.
    /// </param>
    public NetDidBuilder AddDidWebVh(
        WebVhHttpClientOptions? httpClientOptions,
        int maxControllerProofsPerEntry)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(maxControllerProofsPerEntry, 1);

        Services.AddSingleton(httpClientOptions ?? new WebVhHttpClientOptions());
        // WebVhHttpClientOptions.Timeout is the sole time authority for this
        // library-owned client: neutralize HttpClient.Timeout (100s framework
        // default), which would otherwise silently cap configured values above it.
        Services.AddHttpClient<DefaultWebVhHttpClient>()
            .ConfigureHttpClient(c => c.Timeout = Timeout.InfiniteTimeSpan)
            .ConfigurePrimaryHttpMessageHandler(
                DefaultWebVhHttpClient.CreateSecurePrimaryHandler);
        Services.AddSingleton<IWebVhHttpClient>(sp =>
            sp.GetRequiredService<DefaultWebVhHttpClient>());
        Services.AddSingleton<IDidMethod>(sp =>
            new DidWebVhMethod(
                sp.GetRequiredService<IWebVhHttpClient>(),
                logger: null,
                maxControllerProofsPerEntry: maxControllerProofsPerEntry));
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
