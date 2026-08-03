using FluentAssertions;
using NetCrypto;
using NetDid.Method.Ethr.Erc1056;
using NetDid.Method.Ethr.Rpc;
using NSubstitute;
using Xunit;

namespace NetDid.Method.Ethr.Tests;

public class Issue118FinalizedEventCacheTests
{
    private const string Identity = "0x001d3f1ef827552ae1114027bd3ecf1f086ba0f9";
    private const string Registry = "0xdCa7EF03e98e0DC2B855bE647C39ABe984fcF21B";
    private const string OwnerA = "0xdbf03b407c01e7cd3cbea99509d93f8dddc8c6fb";
    private const string OwnerB = "0x2036c6cd85692f0fb2c26e6c6b2eced9e4478dfd";
    private const string OwnerC = "0x1234567890abcdef1234567890abcdef12345678";
    private const ulong ChainId = 0xaa36a7;

    private static readonly EthereumNetworkConfig Sepolia = new()
    {
        Name = "sepolia",
        RpcUrl = "https://rpc.sepolia.example",
        ChainId = "0xaa36a7",
        RegistryAddress = Registry,
    };

    [Fact]
    public async Task Issue118_SecondUnchangedResolution_SkipsFinalizedGetLogsBlocks()
    {
        ulong latestChange = 20;
        var history = new Dictionary<ulong, IReadOnlyList<EthereumLogEntry>>
        {
            [10] = [OwnerChangedLog(Identity, OwnerA, block: 10, previousChange: 0)],
            [20] = [OwnerChangedLog(Identity, OwnerB, block: 20, previousChange: 10)],
        };
        var rpc = FinalityRpc(
            () => latestChange,
            block => history.GetValueOrDefault(block) ?? [],
            finalizedBlock: 100);
        using var cache = new BoundedEthrEventHistoryCache();
        var method = MakeMethod(rpc, cache);

        var first = await method.ResolveAsync($"did:ethr:sepolia:{Identity}");
        var callsAfterFirst = GetLogsCallCount(rpc);
        var second = await method.ResolveAsync($"did:ethr:sepolia:{Identity}");

        first.ResolutionMetadata.Error.Should().BeNull();
        second.ResolutionMetadata.Error.Should().BeNull();
        callsAfterFirst.Should().Be(2);
        GetLogsCallCount(rpc).Should().Be(callsAfterFirst,
            "the finalized blocks are immutable and should be replayed from cache");
        second.DocumentMetadata!.VersionId.Should().Be("20");
    }

    [Fact]
    public async Task Issue118_ChangeAfterCachedWatermark_IsFetchedAndAppliedOnNextResolution()
    {
        ulong latestChange = 20;
        var history = new Dictionary<ulong, IReadOnlyList<EthereumLogEntry>>
        {
            [10] = [OwnerChangedLog(Identity, OwnerA, block: 10, previousChange: 0)],
            [20] = [OwnerChangedLog(Identity, OwnerB, block: 20, previousChange: 10)],
        };
        var rpc = FinalityRpc(
            () => latestChange,
            block => history.GetValueOrDefault(block) ?? [],
            finalizedBlock: 100);
        using var cache = new BoundedEthrEventHistoryCache();
        var method = MakeMethod(rpc, cache);

        var first = await method.ResolveAsync($"did:ethr:sepolia:{Identity}");
        first.ResolutionMetadata.Error.Should().BeNull();
        GetLogsCallCount(rpc).Should().Be(2);

        latestChange = 120;
        history[120] = [OwnerChangedLog(Identity, OwnerC, block: 120, previousChange: 20)];

        var second = await method.ResolveAsync($"did:ethr:sepolia:{Identity}");

        second.ResolutionMetadata.Error.Should().BeNull();
        second.DocumentMetadata!.VersionId.Should().Be("120");
        Controller(second).Should().Contain(OwnerC[2..]);
        GetLogsCallCount(rpc).Should().Be(3,
            "only the new non-finalized head block should be fetched");

        var third = await method.ResolveAsync($"did:ethr:sepolia:{Identity}");

        third.ResolutionMetadata.Error.Should().BeNull();
        GetLogsCallCount(rpc).Should().Be(4,
            "the block above the finalized watermark must never enter the indefinite cache");
    }

    [Fact]
    public async Task Issue118_CacheIsDefaultOff()
    {
        var rpc = FinalityRpc(
            () => 20,
            block => block == 20
                ? [OwnerChangedLog(Identity, OwnerB, block: 20, previousChange: 0)]
                : [],
            finalizedBlock: 100);
        var method = MakeMethod(rpc, eventHistoryCache: null);

        await method.ResolveAsync($"did:ethr:sepolia:{Identity}");
        await method.ResolveAsync($"did:ethr:sepolia:{Identity}");

        GetLogsCallCount(rpc).Should().Be(2);
        await ((IEthereumFinalityRpcClient)rpc).DidNotReceiveWithAnyArgs()
            .GetFinalizedBlockNumberAsync(default);
    }

    [Fact]
    public async Task Issue118_UnsupportedFinalizedTag_FallsBackToFullWalk()
    {
        var rpc = FinalityRpc(
            () => 20,
            block => block == 20
                ? [OwnerChangedLog(Identity, OwnerB, block: 20, previousChange: 0)]
                : [],
            finalizedBlock: null);
        using var cache = new BoundedEthrEventHistoryCache();
        var method = MakeMethod(rpc, cache);

        var first = await method.ResolveAsync($"did:ethr:sepolia:{Identity}");
        var second = await method.ResolveAsync($"did:ethr:sepolia:{Identity}");

        first.ResolutionMetadata.Error.Should().BeNull();
        second.ResolutionMetadata.Error.Should().BeNull();
        GetLogsCallCount(rpc).Should().Be(2,
            "an endpoint without finalized-tag support must retain uncached behavior");
    }

    [Fact]
    public async Task Issue118_CacheWrite_RetainsOnlyBlocksAtOrBelowFinalizedWatermark()
    {
        var history = new Dictionary<ulong, IReadOnlyList<EthereumLogEntry>>
        {
            [10] = [OwnerChangedLog(Identity, OwnerA, block: 10, previousChange: 0)],
            [20] = [OwnerChangedLog(Identity, OwnerB, block: 20, previousChange: 10)],
            [120] = [OwnerChangedLog(Identity, OwnerC, block: 120, previousChange: 20)],
        };
        var rpc = FinalityRpc(
            () => 120,
            block => history.GetValueOrDefault(block) ?? [],
            finalizedBlock: 100);
        var cache = new RecordingEventHistoryCache();
        var method = MakeMethod(rpc, cache);

        var result = await method.ResolveAsync($"did:ethr:sepolia:{Identity}");

        result.ResolutionMetadata.Error.Should().BeNull();
        cache.WrittenHistory.Should().NotBeNull();
        cache.WrittenHistory!.Blocks.Select(block => block.BlockNumber)
            .Should().Equal(20, 10);
    }

    [Theory]
    [InlineData("foreign-registry")]
    [InlineData("foreign-identity")]
    [InlineData("duplicate-log-index")]
    [InlineData("invalid-previous-change")]
    public async Task Issue118_CorruptCachedHistory_FailsClosedThroughExistingValidators(
        string corruption)
    {
        var rpc = FinalityRpc(() => 20, _ => [], finalizedBlock: 100);
        using var cache = new BoundedEthrEventHistoryCache();
        var method = MakeMethod(rpc, cache);
        var cacheKey = new EthrEventHistoryCacheKey(ChainId, Registry, Identity);
        cache.SetIfNewer(cacheKey, PoisonedHistory(corruption), sizeBytes: 1);

        var result = await method.ResolveAsync($"did:ethr:sepolia:{Identity}");

        result.ResolutionMetadata.Error.Should().Be("internalError");
        GetLogsCallCount(rpc).Should().Be(0,
            "the corrupt block came from the cache and must not be silently replaced");
    }

    [Fact]
    public async Task Issue118_UnregisteredIdentities_DoNotCreatePermanentEmptyEntries()
    {
        var rpc = FinalityRpc(() => 0, _ => [], finalizedBlock: 100);
        using var cache = new BoundedEthrEventHistoryCache();
        var method = MakeMethod(rpc, cache);

        for (var i = 0; i < 50; i++)
        {
            var identity = "0x" + i.ToString("x40");
            var result = await method.ResolveAsync($"did:ethr:sepolia:{identity}");
            result.ResolutionMetadata.Error.Should().BeNull();
        }

        cache.Count.Should().Be(0);
    }

    [Fact]
    public void Issue118_BoundedCache_RejectsStaleWatermarkAndCapsAggregateSize()
    {
        using var cache = new BoundedEthrEventHistoryCache();
        var blocks = new[]
        {
            new CachedEthrEventBlock(
                1,
                [OwnerChangedLog(Identity, OwnerA, block: 1, previousChange: 0)])
        };
        var key = new EthrEventHistoryCacheKey(ChainId, Registry, Identity);

        cache.SetIfNewer(
            key,
            new CachedEthrEventHistory(200, blocks),
            BoundedEthrEventHistoryCache.DefaultSizeLimitBytes / 2);
        cache.SetIfNewer(
            key,
            new CachedEthrEventHistory(100, blocks),
            BoundedEthrEventHistoryCache.DefaultSizeLimitBytes / 2);

        cache.TryGet(key, out var retained).Should().BeTrue();
        retained!.FinalizedThroughBlock.Should().Be(200,
            "a stale concurrent writer must not regress the finalized watermark");

        for (var i = 1; i <= 3; i++)
        {
            var otherKey = new EthrEventHistoryCacheKey(
                ChainId,
                Registry,
                "0x" + i.ToString("x40"));
            cache.SetIfNewer(
                otherKey,
                new CachedEthrEventHistory((ulong)(200 + i), blocks),
                BoundedEthrEventHistoryCache.DefaultSizeLimitBytes / 2);
        }

        cache.Count.Should().BeLessThanOrEqualTo(2,
            "the dedicated cache has a hard 64 MiB aggregate size limit");
    }

    [Fact]
    public async Task Issue118_CacheReadAndWriteFailures_FallBackWithoutBreakingResolution()
    {
        var rpc = FinalityRpc(
            () => 20,
            block => block == 20
                ? [OwnerChangedLog(Identity, OwnerB, block: 20, previousChange: 0)]
                : [],
            finalizedBlock: 100);
        var method = MakeMethod(rpc, new ThrowingEventHistoryCache());

        var result = await method.ResolveAsync($"did:ethr:sepolia:{Identity}");

        result.ResolutionMetadata.Error.Should().BeNull();
        result.DocumentMetadata!.VersionId.Should().Be("20");
        GetLogsCallCount(rpc).Should().Be(1);
    }

    [Fact]
    public async Task Issue118_OversizedRawCachedLog_FailsBeforeAbiDecode()
    {
        var rpc = FinalityRpc(() => 20, _ => [], finalizedBlock: 100);
        using var cache = new BoundedEthrEventHistoryCache();
        var method = MakeMethod(rpc, cache);
        var hugeLog = OwnerChangedLog(Identity, OwnerA, block: 20, previousChange: 0) with
        {
            Data = "0x" + new string('0', 16_777_216),
        };
        cache.SetIfNewer(
            new EthrEventHistoryCacheKey(ChainId, Registry, Identity),
            new CachedEthrEventHistory(
                100,
                [new CachedEthrEventBlock(20, [hugeLog])]),
            sizeBytes: 1);

        var result = await method.ResolveAsync($"did:ethr:sepolia:{Identity}");

        result.ResolutionMetadata.Error.Should().Be("internalError");
        GetLogsCallCount(rpc).Should().Be(0);
    }

    private static DidEthrMethod MakeMethod(
        IEthereumRpcClient rpc,
        IEthrEventHistoryCache? eventHistoryCache)
    {
        var factory = Substitute.For<IEthereumRpcClientFactory>();
        factory.GetOrCreate(Arg.Any<EthereumNetworkConfig>()).Returns(rpc);
        return eventHistoryCache is null
            ? new DidEthrMethod(factory, [Sepolia], new DefaultKeyGenerator())
            : new DidEthrMethod(
                factory,
                [Sepolia],
                new DefaultKeyGenerator(),
                logger: null,
                eventHistoryCache: eventHistoryCache);
    }

    private static IEthereumRpcClient FinalityRpc(
        Func<ulong> latestChange,
        Func<ulong, IReadOnlyList<EthereumLogEntry>> logsByBlock,
        ulong? finalizedBlock)
    {
        var rpc = Substitute.For<IEthereumRpcClient, IEthereumFinalityRpcClient>();
        rpc.CallAsync(default!, default!, default)
            .ReturnsForAnyArgs(_ => "0x" + latestChange().ToString("x64"));
        rpc.GetLogsAsync(default!, default).ReturnsForAnyArgs(call =>
            Task.FromResult(logsByBlock(call.Arg<EthereumLogFilter>().FromBlock)));
        rpc.GetBlockTimestampAsync(default, default).ReturnsForAnyArgs(1_700_000_000UL);
        ((IEthereumFinalityRpcClient)rpc)
            .GetFinalizedBlockNumberAsync(default)
            .ReturnsForAnyArgs(finalizedBlock);
        return rpc;
    }

    private static int GetLogsCallCount(IEthereumRpcClient rpc) =>
        rpc.ReceivedCalls().Count(call =>
            call.GetMethodInfo().Name == nameof(IEthereumRpcClient.GetLogsAsync));

    private static CachedEthrEventHistory PoisonedHistory(string corruption)
    {
        var first = OwnerChangedLog(Identity, OwnerA, block: 20, previousChange: 0);
        IReadOnlyList<EthereumLogEntry> logs = corruption switch
        {
            "foreign-registry" => [first with { Address = OwnerB }],
            "foreign-identity" => [OwnerChangedLog(OwnerB, OwnerA, block: 20, previousChange: 0)],
            "duplicate-log-index" =>
            [
                first,
                OwnerChangedLog(Identity, OwnerB, block: 20, previousChange: 20),
            ],
            "invalid-previous-change" =>
                [OwnerChangedLog(Identity, OwnerA, block: 20, previousChange: 20)],
            _ => throw new ArgumentOutOfRangeException(nameof(corruption)),
        };

        return new CachedEthrEventHistory(
            FinalizedThroughBlock: 100,
            Blocks: [new CachedEthrEventBlock(BlockNumber: 20, Logs: logs)]);
    }

    private static EthereumLogEntry OwnerChangedLog(
        string identity,
        string newOwner,
        ulong block,
        ulong previousChange)
    {
        var ownerHex = newOwner.StartsWith("0x", StringComparison.Ordinal)
            ? newOwner[2..]
            : newOwner;
        return new EthereumLogEntry
        {
            Address = Registry,
            Topics = [Erc1056Topics.DIDOwnerChanged, PadAddress(identity)],
            Data = "0x" + "000000000000000000000000" + ownerHex
                + previousChange.ToString("x64"),
            BlockNumber = "0x" + block.ToString("x"),
            LogIndex = 0,
        };
    }

    private static string PadAddress(string address)
    {
        var hex = address.StartsWith("0x", StringComparison.Ordinal)
            ? address[2..]
            : address;
        return "0x" + hex.PadLeft(64, '0');
    }

    private static string Controller(NetDid.Core.Model.DidResolutionResult result) =>
        result.DidDocument!.VerificationMethod!
            .Single(vm => vm.Id.EndsWith("#controller", StringComparison.Ordinal))
            .BlockchainAccountId!
            .ToLowerInvariant();

    private sealed class ThrowingEventHistoryCache : IEthrEventHistoryCache
    {
        public bool TryGet(
            EthrEventHistoryCacheKey key,
            out CachedEthrEventHistory? history)
        {
            history = null;
            throw new ObjectDisposedException(nameof(ThrowingEventHistoryCache));
        }

        public void SetIfNewer(
            EthrEventHistoryCacheKey key,
            CachedEthrEventHistory history,
            long sizeBytes) =>
            throw new ObjectDisposedException(nameof(ThrowingEventHistoryCache));
    }

    private sealed class RecordingEventHistoryCache : IEthrEventHistoryCache
    {
        public CachedEthrEventHistory? WrittenHistory { get; private set; }

        public bool TryGet(
            EthrEventHistoryCacheKey key,
            out CachedEthrEventHistory? history)
        {
            history = null;
            return false;
        }

        public void SetIfNewer(
            EthrEventHistoryCacheKey key,
            CachedEthrEventHistory history,
            long sizeBytes) => WrittenHistory = history;
    }
}
