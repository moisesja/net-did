using FluentAssertions;
using NetCrypto;
using NetDid.Method.Ethr.Erc1056;
using NetDid.Method.Ethr.Rpc;
using NSubstitute;
using Xunit;

namespace NetDid.Method.Ethr.Tests;

/// <summary>
/// Issue #117: didDocumentMetadata must carry `updated` (block time of the last applied
/// change, whenever versionId is reported) and, on historical queries, `nextUpdate`
/// beside nextVersionId — matching the reference ethr-did-resolver. Timestamps the
/// resolution already fetched (VersionTime path, requested-version block) must be
/// reused, not re-queried. Genesis documents (no events) omit all four fields.
/// </summary>
public class Issue117MetadataTimestampTests
{
    private const string Identity = "0x001d3f1ef827552ae1114027bd3ecf1f086ba0f9";
    private const string Registry = "0xdCa7EF03e98e0DC2B855bE647C39ABe984fcF21B";
    private const string OwnerA = "0xdbf03b407c01e7cd3cbea99509d93f8dddc8c6fb";
    private const string OwnerB = "0x2036c6cd85692f0fb2c26e6c6b2eced9e4478dfd";
    private const string ZeroAddress = "0x0000000000000000000000000000000000000000";

    private static readonly EthereumNetworkConfig Sepolia = new()
    {
        Name = "sepolia", RpcUrl = "https://rpc.sepolia.example",
        ChainId = "0xaa36a7", RegistryAddress = Registry,
    };

    private static DidEthrMethod MakeMethod(IEthereumRpcClient rpc)
    {
        var factory = Substitute.For<IEthereumRpcClientFactory>();
        factory.GetOrCreate(Arg.Any<EthereumNetworkConfig>()).Returns(rpc);
        return new DidEthrMethod(factory, [Sepolia], new DefaultKeyGenerator());
    }

    /// <summary>
    /// Two owner changes at blocks 10 (ts 100) and 20 (ts 200), chained 20→10→genesis.
    /// </summary>
    private static IEthereumRpcClient TwoChangeHistory(
        string secondOwner = OwnerB, ulong tsBlock10 = 100, ulong tsBlock20 = 200)
    {
        var rpc = Substitute.For<IEthereumRpcClient>();
        rpc.CallAsync(default!, default!, default)
           .ReturnsForAnyArgs("0x" + 20UL.ToString("x64"));
        rpc.GetLogsAsync(default!, default).ReturnsForAnyArgs(call =>
        {
            var from = call.Arg<EthereumLogFilter>().FromBlock;
            IReadOnlyList<EthereumLogEntry> logs = from switch
            {
                10 => [OwnerChangedLog(Identity, OwnerA, 10, prev: 0)],
                20 => [OwnerChangedLog(Identity, secondOwner, 20, prev: 10)],
                _  => [],
            };
            return Task.FromResult(logs);
        });
        rpc.GetBlockTimestampAsync(10, Arg.Any<CancellationToken>()).Returns(tsBlock10);
        rpc.GetBlockTimestampAsync(15, Arg.Any<CancellationToken>()).Returns(150UL);
        rpc.GetBlockTimestampAsync(20, Arg.Any<CancellationToken>()).Returns(tsBlock20);
        return rpc;
    }

    // ── Current resolution ───────────────────────────────────────────────────────

    [Fact]
    public async Task Issue117_CurrentResolutionWithHistory_UpdatedIsLastChangeBlockTime()
    {
        var rpc = TwoChangeHistory();

        var result = await MakeMethod(rpc).ResolveAsync($"did:ethr:sepolia:{Identity}");

        result.ResolutionMetadata.Error.Should().BeNull();
        result.DocumentMetadata!.VersionId.Should().Be("20");
        result.DocumentMetadata.Updated.Should().Be(DateTimeOffset.FromUnixTimeSeconds(200));
        result.DocumentMetadata.NextVersionId.Should().BeNull(
            "current resolution has no adjacent next change");
        result.DocumentMetadata.NextUpdate.Should().BeNull();
        // Exactly one timestamp fetch — the last change block; nothing else is needed.
        await rpc.Received(1).GetBlockTimestampAsync(20, Arg.Any<CancellationToken>());
        await rpc.DidNotReceive().GetBlockTimestampAsync(10, Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Issue117_Genesis_NoEvents_OmitsUpdatedAndNextUpdate()
    {
        // changed() == 0: an unregistered identity resolves to the genesis document
        // with no version metadata at all, matching the reference resolver.
        var rpc = Substitute.For<IEthereumRpcClient>();
        rpc.CallAsync(default!, default!, default)
           .ReturnsForAnyArgs("0x" + new string('0', 64));

        var result = await MakeMethod(rpc).ResolveAsync($"did:ethr:sepolia:{Identity}");

        result.ResolutionMetadata.Error.Should().BeNull();
        result.DocumentMetadata!.VersionId.Should().BeNull();
        result.DocumentMetadata.Updated.Should().BeNull();
        result.DocumentMetadata.NextVersionId.Should().BeNull();
        result.DocumentMetadata.NextUpdate.Should().BeNull();
        await rpc.DidNotReceiveWithAnyArgs().GetBlockTimestampAsync(default, default);
    }

    [Fact]
    public async Task Issue117_DeactivatedWithHistory_UpdatedStillSet()
    {
        // The reference resolver merges { deactivated: true } with the version
        // metadata — deactivation must not suppress `updated`.
        var rpc = TwoChangeHistory(secondOwner: ZeroAddress);

        var result = await MakeMethod(rpc).ResolveAsync($"did:ethr:sepolia:{Identity}");

        result.ResolutionMetadata.Error.Should().BeNull();
        result.DocumentMetadata!.Deactivated.Should().BeTrue();
        result.DocumentMetadata.VersionId.Should().Be("20");
        result.DocumentMetadata.Updated.Should().Be(DateTimeOffset.FromUnixTimeSeconds(200));
    }

    // ── Historical resolution: versionId ─────────────────────────────────────────

    [Fact]
    public async Task Issue117_VersionIdBetweenChanges_UpdatedAndNextUpdatePopulated()
    {
        var rpc = TwoChangeHistory();
        var opts = new DidEthrResolveOptions { VersionId = "15" };

        var result = await MakeMethod(rpc)
            .ResolveAsync($"did:ethr:sepolia:{Identity}", opts);

        result.ResolutionMetadata.Error.Should().BeNull();
        result.DocumentMetadata!.VersionId.Should().Be("10");
        result.DocumentMetadata.Updated.Should().Be(DateTimeOffset.FromUnixTimeSeconds(100));
        result.DocumentMetadata.NextVersionId.Should().Be("20");
        // ts 200 → 1970-01-01T00:03:20Z, the reference resolver's ISO 8601 UTC
        // whole-second form.
        result.DocumentMetadata.NextUpdate.Should().Be("1970-01-01T00:03:20Z");
    }

    [Fact]
    public async Task Issue117_VersionIdEqualToLastChange_ReusesRequestedBlockTimestamp()
    {
        var rpc = TwoChangeHistory();
        var opts = new DidEthrResolveOptions { VersionId = "20" };

        var result = await MakeMethod(rpc)
            .ResolveAsync($"did:ethr:sepolia:{Identity}", opts);

        result.ResolutionMetadata.Error.Should().BeNull();
        result.DocumentMetadata!.VersionId.Should().Be("20");
        result.DocumentMetadata.Updated.Should().Be(DateTimeOffset.FromUnixTimeSeconds(200));
        result.DocumentMetadata.NextVersionId.Should().BeNull();
        result.DocumentMetadata.NextUpdate.Should().BeNull();
        // The requested block IS the last change: its timestamp was already fetched
        // for the reference clock and must be reused, not re-queried.
        await rpc.Received(1).GetBlockTimestampAsync(20, Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Issue117_VersionIdZeroWithHistory_OmitsUpdatedButReportsNextUpdate()
    {
        // Genesis VIEW of a registered DID (versionId=0 with later events) is not the
        // no-history genesis case: versionId/updated are omitted (no change applied yet)
        // while nextVersionId/nextUpdate point at the first change — matching the
        // reference resolver, which skips versionMeta only when versionId === 0 and
        // still emits versionMetaNext for a finite next change.
        var rpc = TwoChangeHistory();
        rpc.GetBlockTimestampAsync(0, Arg.Any<CancellationToken>()).Returns(50UL);
        var opts = new DidEthrResolveOptions { VersionId = "0" };

        var result = await MakeMethod(rpc)
            .ResolveAsync($"did:ethr:sepolia:{Identity}", opts);

        result.ResolutionMetadata.Error.Should().BeNull();
        result.DocumentMetadata!.VersionId.Should().BeNull();
        result.DocumentMetadata.Updated.Should().BeNull();
        result.DocumentMetadata.NextVersionId.Should().Be("10");
        // ts(10) = 100 → 1970-01-01T00:01:40Z
        result.DocumentMetadata.NextUpdate.Should().Be("1970-01-01T00:01:40Z");
    }

    [Fact]
    public async Task Issue117_SerializedMetadata_MatchesReferenceResolverShape()
    {
        // The externally consumed representation (PR #126 review): default
        // System.Text.Json serialization of the resolved metadata must render `updated`
        // in the same canonical Z form as `nextUpdate` and the reference resolver —
        // not the DateTimeOffset default "+00:00" form.
        var rpc = TwoChangeHistory();
        var opts = new DidEthrResolveOptions { VersionId = "15" };

        var result = await MakeMethod(rpc)
            .ResolveAsync($"did:ethr:sepolia:{Identity}", opts);

        var json = System.Text.Json.JsonSerializer.Serialize(result.DocumentMetadata,
            new System.Text.Json.JsonSerializerOptions
            {
                PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase,
            });

        json.Should().Contain("\"updated\":\"1970-01-01T00:01:40Z\"");
        json.Should().Contain("\"nextUpdate\":\"1970-01-01T00:03:20Z\"");
        json.Should().NotContain("+00:00");
    }

    [Fact]
    public async Task Issue117_NextUpdateFormat_IsIso8601UtcWholeSeconds()
    {
        var rpc = TwoChangeHistory(tsBlock20: 1_700_000_000);
        var opts = new DidEthrResolveOptions { VersionId = "15" };

        var result = await MakeMethod(rpc)
            .ResolveAsync($"did:ethr:sepolia:{Identity}", opts);

        result.DocumentMetadata!.NextUpdate.Should().Be("2023-11-14T22:13:20Z");
    }

    // ── Historical resolution: versionTime ───────────────────────────────────────

    [Fact]
    public async Task Issue117_VersionTime_ReusesWalkTimestamps_NoExtraFetches()
    {
        var rpc = TwoChangeHistory();
        // Between ts 100 (block 10) and ts 200 (block 20).
        var opts = new DidEthrResolveOptions { VersionTime = "1970-01-01T00:02:30Z" };

        var result = await MakeMethod(rpc)
            .ResolveAsync($"did:ethr:sepolia:{Identity}", opts);

        result.ResolutionMetadata.Error.Should().BeNull();
        result.DocumentMetadata!.VersionId.Should().Be("10");
        result.DocumentMetadata.Updated.Should().Be(DateTimeOffset.FromUnixTimeSeconds(100));
        result.DocumentMetadata.NextVersionId.Should().Be("20");
        result.DocumentMetadata.NextUpdate.Should().Be("1970-01-01T00:03:20Z");
        // The chronological walk already fetched every block's timestamp once;
        // updated/nextUpdate must come from that pass — zero additional calls.
        await rpc.Received(1).GetBlockTimestampAsync(10, Arg.Any<CancellationToken>());
        await rpc.Received(1).GetBlockTimestampAsync(20, Arg.Any<CancellationToken>());
    }

    // ── Hostile node: unrepresentable timestamp ──────────────────────────────────

    [Fact]
    public async Task Issue117_TimestampBeyondRepresentableRange_InternalErrorNotWrappedDate()
    {
        // ulong.MaxValue cast to long wraps to -1 (silent 1969-12-31T23:59:59Z);
        // long.MinValue-patterns throw ArgumentOutOfRangeException. Both must surface
        // as the fixed internalError mapping, never as a fabricated instant.
        var rpc = TwoChangeHistory(tsBlock20: ulong.MaxValue);

        var result = await MakeMethod(rpc).ResolveAsync($"did:ethr:sepolia:{Identity}");

        result.DidDocument.Should().BeNull();
        result.ResolutionMetadata.Error.Should().Be("internalError");
        result.DocumentMetadata?.Updated.Should().BeNull();
    }

    // ── Cancellation: the updated fetch is now the terminal dependency call ──────

    [Fact]
    public async Task Issue117_CallerCancelledDuringTerminalUpdatedFetch_Propagates()
    {
        // On default resolution the `updated` timestamp fetch is the LAST dependency
        // call before success — cancellation firing inside it has no next iteration
        // to observe it, so the post-await check must (completed-task mode).
        using var cts = new CancellationTokenSource();
        var rpc = TwoChangeHistory();
        rpc.GetBlockTimestampAsync(20, Arg.Any<CancellationToken>()).Returns(_ =>
        {
            cts.Cancel();
            return Task.FromResult(200UL);
        });

        var act = () => MakeMethod(rpc)
            .ResolveAsync($"did:ethr:sepolia:{Identity}", options: null, cts.Token);

        await act.Should().ThrowAsync<OperationCanceledException>(
            "a caller that cancelled during the final metadata fetch must never receive a stale success");
    }

    [Fact]
    public async Task Issue117_CallerCancelledWhileUpdatedFetchPending_Propagates()
    {
        // Pending-task mode: the fetch never completes and ignores its token; the
        // caller's cancellation must still unblock resolution via the bounded await.
        using var cts = new CancellationTokenSource();
        var pending = new TaskCompletionSource<ulong>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var rpc = TwoChangeHistory();
        rpc.GetBlockTimestampAsync(20, Arg.Any<CancellationToken>()).Returns(_ =>
        {
            cts.CancelAfter(TimeSpan.FromMilliseconds(50));
            return pending.Task;
        });

        var act = () => MakeMethod(rpc)
            .ResolveAsync($"did:ethr:sepolia:{Identity}", options: null, cts.Token);

        await act.Should().ThrowAsync<OperationCanceledException>();
    }

    // ── Fixtures ─────────────────────────────────────────────────────────────────

    private static EthereumLogEntry OwnerChangedLog(
        string identity, string newOwner, ulong block, ulong prev)
    {
        var ownerHex = newOwner.StartsWith("0x") ? newOwner[2..] : newOwner;
        var data = "0x" + "000000000000000000000000" + ownerHex + prev.ToString("x64");
        return new EthereumLogEntry
        {
            Address = Registry,
            Topics = [Erc1056Topics.DIDOwnerChanged, PadAddress(identity)],
            Data = data,
            BlockNumber = "0x" + block.ToString("x"),
            LogIndex = 0,
        };
    }

    private static string PadAddress(string addr)
    {
        var hex = addr.StartsWith("0x") ? addr[2..] : addr;
        return "0x" + hex.PadLeft(64, '0');
    }
}
