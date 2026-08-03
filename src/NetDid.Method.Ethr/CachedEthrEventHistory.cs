using Microsoft.Extensions.Caching.Memory;
using NetDid.Method.Ethr.Rpc;

namespace NetDid.Method.Ethr;

internal readonly record struct EthrEventHistoryCacheKey
{
    public EthrEventHistoryCacheKey(
        ulong chainId,
        string registryAddress,
        string identityAddress)
        : this(
            chainId.ToString(System.Globalization.CultureInfo.InvariantCulture),
            registryAddress,
            identityAddress)
    {
    }

    public EthrEventHistoryCacheKey(
        string chainId,
        string registryAddress,
        string identityAddress)
    {
        ChainId = chainId;
        RegistryAddress = registryAddress.ToLowerInvariant();
        IdentityAddress = identityAddress.ToLowerInvariant();
    }

    public string ChainId { get; }
    public string RegistryAddress { get; }
    public string IdentityAddress { get; }
}

/// <summary>
/// Raw, finalized ERC-1056 history. Raw logs are intentional: cache reads must pass
/// through the same parser and fail-closed validation as fresh RPC results.
/// </summary>
internal sealed record CachedEthrEventHistory(
    ulong FinalizedThroughBlock,
    IReadOnlyList<CachedEthrEventBlock> Blocks);

internal sealed record CachedEthrEventBlock(
    ulong BlockNumber,
    IReadOnlyList<EthereumLogEntry> Logs);

internal interface IEthrEventHistoryCache
{
    bool TryGet(
        EthrEventHistoryCacheKey key,
        out CachedEthrEventHistory? history);

    void SetIfNewer(
        EthrEventHistoryCacheKey key,
        CachedEthrEventHistory history,
        long sizeBytes);
}

/// <summary>
/// Resolver-owned cache. Keeping this seam internal prevents an unrelated shared-cache
/// writer from forging a structurally valid authorization history. The size limit is a
/// hard aggregate bound; individual entries retain the resolver's stricter per-history
/// bounds and can be evicted safely because a miss falls back to the full chain walk.
/// </summary>
internal sealed class BoundedEthrEventHistoryCache : IEthrEventHistoryCache, IDisposable
{
    internal const long DefaultSizeLimitBytes = 64L * 1024 * 1024;

    private readonly MemoryCache _cache = new(new MemoryCacheOptions
    {
        SizeLimit = DefaultSizeLimitBytes,
    });
    private readonly object _writeGate = new();

    internal int Count => _cache.Count;

    public bool TryGet(
        EthrEventHistoryCacheKey key,
        out CachedEthrEventHistory? history) =>
        _cache.TryGetValue(key, out history);

    public void SetIfNewer(
        EthrEventHistoryCacheKey key,
        CachedEthrEventHistory history,
        long sizeBytes)
    {
        lock (_writeGate)
        {
            if (_cache.TryGetValue(key, out CachedEthrEventHistory? current)
                && current is not null
                && current.FinalizedThroughBlock >= history.FinalizedThroughBlock)
                return;

            _cache.Set(
                key,
                history,
                new MemoryCacheEntryOptions().SetSize(Math.Max(1, sizeBytes)));
        }
    }

    public void Dispose() => _cache.Dispose();
}
