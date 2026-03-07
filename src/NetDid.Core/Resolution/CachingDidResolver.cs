using Microsoft.Extensions.Caching.Memory;
using NetDid.Core.Model;

namespace NetDid.Core.Resolution;

/// <summary>
/// Caching decorator for any <see cref="IDidResolver"/>.
/// Uses <see cref="IMemoryCache"/> with configurable TTL.
/// </summary>
public sealed class CachingDidResolver : IDidResolver
{
    private readonly IDidResolver _inner;
    private readonly IMemoryCache _cache;
    private readonly TimeSpan _ttl;

    public CachingDidResolver(IDidResolver inner, IMemoryCache cache, TimeSpan? ttl = null)
    {
        _inner = inner;
        _cache = cache;
        _ttl = ttl ?? TimeSpan.FromMinutes(15);
    }

    public bool CanResolve(string did) => _inner.CanResolve(did);

    public async Task<DidResolutionResult> ResolveAsync(string did, DidResolutionOptions? options = null, CancellationToken ct = default)
    {
        var cacheKey = ComputeCacheKey(did, options);

        if (_cache.TryGetValue(cacheKey, out DidResolutionResult? cached))
            return cached!;

        var result = await _inner.ResolveAsync(did, options, ct);
        if (result.DidDocument is not null)
            _cache.Set(cacheKey, result, _ttl);

        return result;
    }

    private static string ComputeCacheKey(string did, DidResolutionOptions? options)
    {
        if (options is null) return did;
        return $"{did}|{options.GetCacheDiscriminator()}";
    }
}
