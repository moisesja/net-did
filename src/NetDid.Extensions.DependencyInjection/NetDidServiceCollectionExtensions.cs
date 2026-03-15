using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using NetDid.Core;
using NetDid.Core.Resolution;

namespace NetDid.Extensions.DependencyInjection;

/// <summary>
/// Extension methods for registering NetDid services in <see cref="IServiceCollection"/>.
/// </summary>
public static class NetDidServiceCollectionExtensions
{
    /// <summary>
    /// Add NetDid services to the dependency injection container.
    /// Use the builder to register specific DID methods.
    /// </summary>
    public static IServiceCollection AddNetDid(this IServiceCollection services, Action<NetDidBuilder> configure)
    {
        var builder = new NetDidBuilder(services);
        configure(builder);

        // Register IDidResolver — either caching or direct
        if (builder.CachingEnabled)
        {
            services.AddMemoryCache();
            services.TryAddSingleton<IDidResolver>(sp =>
            {
                var methods = sp.GetServices<IDidMethod>();
                var composite = new CompositeDidResolver(methods);
                var cache = sp.GetRequiredService<Microsoft.Extensions.Caching.Memory.IMemoryCache>();
                return new CachingDidResolver(composite, cache, builder.CacheTtl);
            });
        }
        else
        {
            services.TryAddSingleton<IDidResolver>(sp =>
            {
                var methods = sp.GetServices<IDidMethod>();
                return new CompositeDidResolver(methods);
            });
        }

        // Register IDidManager
        services.TryAddSingleton<IDidManager>(sp =>
        {
            var methods = sp.GetServices<IDidMethod>();
            return new DidManager(methods);
        });

        return services;
    }
}
