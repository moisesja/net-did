using FluentAssertions;
using Microsoft.Extensions.Logging;
using NetDid.Method.Ethr.Rpc;
using NSubstitute;
using Xunit;

namespace NetDid.Method.Ethr.Tests;

/// <summary>
/// Issue #119: opt-in RPC endpoint auto-configuration with historical-logs probing.
/// A candidate endpoint must pass an eth_chainId identity check AND return logs for
/// a hard-coded known-old registry event query; endpoints that answer the probe with
/// an empty log set (pruned/non-archive), report the wrong chain, fail transport, or
/// exceed the per-endpoint timeout are discarded with an actionable logged reason and
/// probing continues. Caller cancellation aborts the run; per-endpoint failures never do.
/// </summary>
public class Issue119AutoConfigTests
{
    private const string MainnetUrl  = "https://mainnet-a.example";
    private const string FallbackUrl = "https://mainnet-b.example";

    // ── Test doubles ─────────────────────────────────────────────────────────

    /// <summary>Records every log call; providers like this are how criterion 3
    /// ("actionable log message") is asserted — the repo has no FakeLogger package.</summary>
    private sealed class RecordingLogger : ILogger
    {
        public List<(LogLevel Level, string Message, Exception? Exception)> Entries { get; } = [];
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state,
            Exception? exception, Func<TState, Exception?, string> formatter)
            => Entries.Add((logLevel, formatter(state, exception), exception));
    }

    private sealed class AlwaysThrowingLogger : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state,
            Exception? exception, Func<TState, Exception?, string> formatter)
            => throw new InvalidOperationException("logger failed");
    }

    /// <summary>A log entry that genuinely satisfies the network's historical probe:
    /// registry address, padded identity topic, and the exact probed block.</summary>
    private static EthereumLogEntry MatchingProbeLog(EthereumNetworkConfig network)
    {
        var probe = EthrRpcAutoConfig.FindProbe(network.Name)!;
        return new EthereumLogEntry
        {
            Address = network.RegistryAddress,
            Topics =
            [
                NetDid.Method.Ethr.Erc1056.Erc1056Topics.DIDOwnerChanged,
                "0x000000000000000000000000" + probe.Identity[2..],
            ],
            Data = "0x",
            BlockNumber = "0x" + probe.Block.ToString("x"),
            LogIndex = 0,
        };
    }

    /// <summary>An rpc whose chainId matches and whose probe query returns one log
    /// genuinely matching the network's probe (address, identity topic, window).</summary>
    private static IEthereumRpcClient HealthyRpc(ulong chainId, EthereumNetworkConfig network)
    {
        var rpc = Substitute.For<IEthereumRpcClient>();
        rpc.GetChainIdAsync(Arg.Any<CancellationToken>()).Returns(chainId);
        rpc.GetLogsAsync(Arg.Any<EthereumLogFilter>(), Arg.Any<CancellationToken>())
           .Returns(Task.FromResult<IReadOnlyList<EthereumLogEntry>>([MatchingProbeLog(network)]));
        return rpc;
    }

    /// <summary>chainId matches but every probe query returns no logs — the pruned/
    /// non-archive endpoint shape this issue exists to detect.</summary>
    private static IEthereumRpcClient PrunedRpc(ulong chainId)
    {
        var rpc = Substitute.For<IEthereumRpcClient>();
        rpc.GetChainIdAsync(Arg.Any<CancellationToken>()).Returns(chainId);
        rpc.GetLogsAsync(Arg.Any<EthereumLogFilter>(), Arg.Any<CancellationToken>())
           .Returns(Task.FromResult<IReadOnlyList<EthereumLogEntry>>([]));
        return rpc;
    }

    private static Func<EthereumNetworkConfig, (IEthereumRpcClient, IDisposable?)> FactoryFor(
        Dictionary<string, IEthereumRpcClient> rpcByUrl)
        => candidate => (rpcByUrl[candidate.RpcUrl], null);

    private static Task<IReadOnlyList<EthereumNetworkConfig>> RunAsync(
        IReadOnlyDictionary<string, IReadOnlyList<string>>? candidates,
        Func<EthereumNetworkConfig, (IEthereumRpcClient, IDisposable?)> factory,
        ILogger? logger = null,
        TimeSpan? perEndpointTimeout = null,
        CancellationToken ct = default)
        => EthrRpcAutoConfig.ConfigureCoreAsync(candidates, logger, perEndpointTimeout, factory, ct);

    // ── Acceptance criterion 3: pruned endpoint rejected, actionable log ─────

    [Fact]
    public async Task Issue119_PrunedEndpoint_EmptyProbeLogs_DiscardedWithActionableLog()
    {
        var logger = new RecordingLogger();
        var result = await RunAsync(
            new Dictionary<string, IReadOnlyList<string>> { ["mainnet"] = [MainnetUrl] },
            FactoryFor(new() { [MainnetUrl] = PrunedRpc(1) }), logger);

        result.Should().BeEmpty();
        logger.Entries.Should().Contain(e =>
            e.Level == LogLevel.Warning
            && e.Message.Contains(MainnetUrl)
            && e.Message.Contains("archive"),
            "the discard reason must name the endpoint and the archive/historical cause");
        logger.Entries.Should().Contain(e => e.Message.Contains("omitted"),
            "a network with no passing candidate must be reported as omitted");
    }

    [Fact]
    public async Task Issue119_PrunedFirstCandidate_HealthySecond_SecondWins()
    {
        var logger = new RecordingLogger();
        var result = await RunAsync(
            new Dictionary<string, IReadOnlyList<string>> { ["mainnet"] = [MainnetUrl, FallbackUrl] },
            FactoryFor(new()
            {
                [MainnetUrl]  = PrunedRpc(1),
                [FallbackUrl] = HealthyRpc(1, KnownNetworks.Mainnet),
            }), logger);

        result.Should().ContainSingle().Which.RpcUrl.Should().Be(FallbackUrl);
        result[0].Name.Should().Be("mainnet");
        result[0].RegistryAddress.Should().Be(KnownNetworks.Mainnet.RegistryAddress);
    }

    // ── Chain-ID identity check ──────────────────────────────────────────────

    [Fact]
    public async Task Issue119_WrongChainId_Discarded()
    {
        var logger = new RecordingLogger();
        var result = await RunAsync(
            new Dictionary<string, IReadOnlyList<string>> { ["mainnet"] = [MainnetUrl] },
            FactoryFor(new() { [MainnetUrl] = HealthyRpc(chainId: 137, KnownNetworks.Mainnet) }),
            logger);

        result.Should().BeEmpty();
        logger.Entries.Should().Contain(e =>
            e.Message.Contains("eth_chainId") && e.Message.Contains("137"));
    }

    // ── Probe query shape ────────────────────────────────────────────────────

    [Fact]
    public async Task Issue119_ProbeFilter_UsesRegistryWindowAndPaddedIdentity()
    {
        EthereumLogFilter? seen = null;
        var rpc = Substitute.For<IEthereumRpcClient>();
        rpc.GetChainIdAsync(Arg.Any<CancellationToken>()).Returns(1UL);
        rpc.GetLogsAsync(Arg.Do<EthereumLogFilter>(f => seen = f), Arg.Any<CancellationToken>())
           .Returns(Task.FromResult<IReadOnlyList<EthereumLogEntry>>(
               [MatchingProbeLog(KnownNetworks.Mainnet)]));

        await RunAsync(
            new Dictionary<string, IReadOnlyList<string>> { ["mainnet"] = [MainnetUrl] },
            _ => (rpc, null));

        var probe = EthrRpcAutoConfig.FindProbe("mainnet")!;
        seen.Should().NotBeNull();
        seen!.Address.Should().Be(KnownNetworks.Mainnet.RegistryAddress);
        // Round 2: exact-block probing — the same query shape resolution issues,
        // so provider range caps below 41 blocks cannot cause a false reject.
        seen.FromBlock.Should().Be(probe.Block);
        seen.ToBlock.Should().Be(probe.Block);
        seen.Topics.Should().HaveCount(2);
        // Round 3, finding 4: topic0 must be the resolver's own signature OR-list —
        // a wildcard contract scan is a DIFFERENT request class that some providers
        // limit even when they serve the resolver's selective filter.
        seen.Topics![0].Should().Equal(
            NetDid.Method.Ethr.Erc1056.Erc1056Topics.DIDOwnerChanged,
            NetDid.Method.Ethr.Erc1056.Erc1056Topics.DIDDelegateChanged,
            NetDid.Method.Ethr.Erc1056.Erc1056Topics.DIDAttributeChanged);
        seen.Topics[1].Should().ContainSingle().Which.Should().Be(
            "0x000000000000000000000000" + probe.Identity[2..].ToLowerInvariant());
    }

    // ── Transport failures: discard the candidate, never the run ─────────────

    [Fact]
    public async Task Issue119_TransportFailure_DiscardedAndRunContinues()
    {
        var broken = Substitute.For<IEthereumRpcClient>();
        broken.GetChainIdAsync(Arg.Any<CancellationToken>())
              .Returns<ulong>(_ => throw new HttpRequestException("connection refused"));
        var logger = new RecordingLogger();

        var result = await RunAsync(
            new Dictionary<string, IReadOnlyList<string>> { ["mainnet"] = [MainnetUrl, FallbackUrl] },
            FactoryFor(new()
            {
                [MainnetUrl]  = broken,
                [FallbackUrl] = HealthyRpc(1, KnownNetworks.Mainnet),
            }), logger);

        result.Should().ContainSingle().Which.RpcUrl.Should().Be(FallbackUrl);
        // Adversarial round 1: the exception OBJECT must not reach the sink — a
        // remote endpoint controls inner-exception text (duplicate-JSON-key
        // ArgumentException quotes the attacker's key), so only bounded type names
        // are logged.
        logger.Entries.Should().Contain(e =>
            e.Message.Contains("failed") && e.Message.Contains("HttpRequestException"));
        logger.Entries.Should().OnlyContain(e => e.Exception == null,
            "endpoint-controlled exception text must never reach the log sink");
    }

    [Fact]
    public async Task Issue119_OneNetworkAllBroken_OtherNetworkStillConfigured()
    {
        var broken = Substitute.For<IEthereumRpcClient>();
        broken.GetChainIdAsync(Arg.Any<CancellationToken>())
              .Returns<ulong>(_ => throw new InvalidOperationException("hostile client"));

        var result = await RunAsync(
            new Dictionary<string, IReadOnlyList<string>>
            {
                ["mainnet"] = [MainnetUrl],
                ["sepolia"] = ["https://sepolia.example"],
            },
            FactoryFor(new()
            {
                [MainnetUrl] = broken,
                ["https://sepolia.example"] = HealthyRpc(11155111, KnownNetworks.Sepolia),
            }));

        result.Should().ContainSingle().Which.Name.Should().Be("sepolia");
    }

    // ── First healthy wins; later candidates are not contacted ───────────────

    [Fact]
    public async Task Issue119_FirstHealthyCandidate_WinsWithoutProbingLater()
    {
        var contacted = new List<string>();
        var result = await RunAsync(
            new Dictionary<string, IReadOnlyList<string>> { ["mainnet"] = [MainnetUrl, FallbackUrl] },
            candidate =>
            {
                contacted.Add(candidate.RpcUrl);
                return (HealthyRpc(1, candidate), null);
            });

        result.Should().ContainSingle().Which.RpcUrl.Should().Be(MainnetUrl);
        contacted.Should().Equal(MainnetUrl);
    }

    // ── Networks without probe data: chain-ID only, explicit UNVERIFIED ──────

    [Fact]
    public async Task Issue119_NetworkWithoutProbeData_ChainIdOnly_LoggedUnverified()
    {
        EthrRpcAutoConfig.FindProbe("holesky").Should().BeNull(
            "this test requires a catalogue network without probe data");

        var rpc = Substitute.For<IEthereumRpcClient>();
        rpc.GetChainIdAsync(Arg.Any<CancellationToken>()).Returns(17000UL);
        var logger = new RecordingLogger();

        var result = await RunAsync(
            new Dictionary<string, IReadOnlyList<string>> { ["holesky"] = ["https://holesky.example"] },
            _ => (rpc, null), logger);

        result.Should().ContainSingle().Which.Name.Should().Be("holesky");
        await rpc.DidNotReceive().GetLogsAsync(Arg.Any<EthereumLogFilter>(), Arg.Any<CancellationToken>());
        logger.Entries.Should().Contain(e =>
            e.Level == LogLevel.Warning && e.Message.Contains("UNVERIFIED"));
    }

    // ── Input hygiene: keys, aliases, URLs, snapshot ─────────────────────────

    [Fact]
    public async Task Issue119_UnknownNetworkKey_SkippedWithOrdinalLog()
    {
        // Round 3, finding 2: the key itself is caller-controlled text and must not
        // be logged raw — the skipped entry is identified by its map position.
        var logger = new RecordingLogger();
        var result = await RunAsync(
            new Dictionary<string, IReadOnlyList<string>> { ["not-a-network"] = [MainnetUrl] },
            _ => throw new InvalidOperationException("must not construct a client"), logger);

        result.Should().BeEmpty();
        logger.Entries.Should().Contain(e =>
            e.Message.Contains("entry #0") && !e.Message.Contains("not-a-network"));
    }

    [Fact]
    public async Task Issue119_DuplicateAliasKeys_ProbedOnce()
    {
        // "mainnet" and "0x1" resolve to the same catalogue entry; the second key
        // must be skipped, not probed into a duplicate config.
        var contacted = 0;
        var result = await RunAsync(
            new Dictionary<string, IReadOnlyList<string>>
            {
                ["mainnet"] = [MainnetUrl],
                ["0x1"]     = [FallbackUrl],
            },
            candidate =>
            {
                contacted++;
                return (HealthyRpc(1, candidate), null);
            });

        result.Should().ContainSingle();
        contacted.Should().Be(1);
    }

    [Fact]
    public async Task Issue119_NonHttpUrl_DiscardedWithoutClientConstruction()
    {
        var logger = new RecordingLogger();
        var result = await RunAsync(
            new Dictionary<string, IReadOnlyList<string>>
            {
                ["mainnet"] = ["not a url", "ftp://mainnet.example", "file:///etc/passwd"],
            },
            _ => throw new InvalidOperationException("must not construct a client"), logger);

        result.Should().BeEmpty();
        logger.Entries.Where(e => e.Message.Contains("absolute http(s)")).Should().HaveCount(3);
    }

    /// <summary>A hostile candidate list that yields different contents on every
    /// enumeration (TOCTOU): the snapshot taken at entry must be what is probed.</summary>
    private sealed class ShiftingList : IReadOnlyList<string>
    {
        private int _enumerations;
        private string[] Current => _enumerations <= 1
            ? [MainnetUrl]
            : ["https://swapped-in-later.example"];
        public string this[int index] => Current[index];
        public int Count => Current.Length;
        public IEnumerator<string> GetEnumerator()
        {
            _enumerations++;
            return ((IEnumerable<string>)Current).GetEnumerator();
        }
        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator()
            => GetEnumerator();
    }

    [Fact]
    public async Task Issue119_HostileCandidateList_SnapshotAtEntryIsProbed()
    {
        var contacted = new List<string>();
        var result = await RunAsync(
            new Dictionary<string, IReadOnlyList<string>> { ["mainnet"] = new ShiftingList() },
            candidate =>
            {
                contacted.Add(candidate.RpcUrl);
                return (HealthyRpc(1, candidate), null);
            });

        contacted.Should().Equal([MainnetUrl], "the entry-time snapshot is the probed set");
        result.Should().ContainSingle().Which.RpcUrl.Should().Be(MainnetUrl);
    }

    // ── Determinism: catalogue order regardless of dictionary order ──────────

    [Fact]
    public async Task Issue119_ResultOrder_FollowsCatalogueOrder()
    {
        var rpcs = new Dictionary<string, IEthereumRpcClient>
        {
            ["https://polygon.example"] = HealthyRpc(137, KnownNetworks.Polygon),
            ["https://mainnet.example"] = HealthyRpc(1, KnownNetworks.Mainnet),
        };
        var result = await RunAsync(
            new Dictionary<string, IReadOnlyList<string>>
            {
                // Dictionary lists polygon first; the catalogue orders mainnet first.
                ["polygon"] = ["https://polygon.example"],
                ["mainnet"] = ["https://mainnet.example"],
            },
            FactoryFor(rpcs));

        result.Select(n => n.Name).Should().Equal("mainnet", "polygon");
    }

    // ── Cancellation and timeouts ────────────────────────────────────────────

    [Fact]
    public async Task Issue119_CallerCancellation_Propagates()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        var act = () => RunAsync(
            new Dictionary<string, IReadOnlyList<string>> { ["mainnet"] = [MainnetUrl] },
            FactoryFor(new() { [MainnetUrl] = HealthyRpc(1, KnownNetworks.Mainnet) }),
            ct: cts.Token);

        await act.Should().ThrowAsync<OperationCanceledException>();
    }

    [Fact]
    public async Task Issue119_CancellationDuringLastCandidateProbe_Propagates()
    {
        // Terminal-element coverage: the dependency cancels the caller during the
        // FINAL candidate's probe and then returns a completed task. The post-await
        // caller-token check must propagate cancellation instead of reporting a
        // stale success or a discard.
        using var cts = new CancellationTokenSource();
        var rpc = Substitute.For<IEthereumRpcClient>();
        rpc.GetChainIdAsync(Arg.Any<CancellationToken>()).Returns(_ =>
        {
            cts.Cancel();
            return Task.FromResult(1UL);
        });

        var act = () => RunAsync(
            new Dictionary<string, IReadOnlyList<string>> { ["mainnet"] = [MainnetUrl] },
            _ => (rpc, null), ct: cts.Token);

        await act.Should().ThrowAsync<OperationCanceledException>();
    }

    [Fact]
    public async Task Issue119_TokenIgnoringHang_PerEndpointTimeout_DiscardsAndContinues()
    {
        // A hostile/hung endpoint whose task never completes and ignores the token:
        // the per-endpoint deadline must bound it (WaitAsyncObserved at the await
        // site) and move on to the next candidate — never hang the whole bootstrap.
        var hung = Substitute.For<IEthereumRpcClient>();
        hung.GetChainIdAsync(Arg.Any<CancellationToken>())
            .Returns(new TaskCompletionSource<ulong>().Task);
        var logger = new RecordingLogger();

        var result = await RunAsync(
            new Dictionary<string, IReadOnlyList<string>> { ["mainnet"] = [MainnetUrl, FallbackUrl] },
            FactoryFor(new()
            {
                [MainnetUrl]  = hung,
                [FallbackUrl] = HealthyRpc(1, KnownNetworks.Mainnet),
            }),
            logger, perEndpointTimeout: TimeSpan.FromMilliseconds(200));

        result.Should().ContainSingle().Which.RpcUrl.Should().Be(FallbackUrl);
        logger.Entries.Should().Contain(e => e.Message.Contains("deadline"));
    }

    [Fact]
    public async Task Issue119_NonPositiveTimeout_Throws()
    {
        var act = () => RunAsync(
            new Dictionary<string, IReadOnlyList<string>> { ["mainnet"] = [MainnetUrl] },
            _ => (Substitute.For<IEthereumRpcClient>(), null),
            perEndpointTimeout: TimeSpan.Zero);

        await act.Should().ThrowAsync<ArgumentOutOfRangeException>();
    }

    // ── Resource + logging resilience ────────────────────────────────────────

    private sealed class TrackingDisposable : IDisposable
    {
        public bool Disposed { get; private set; }
        public void Dispose() => Disposed = true;
    }

    [Fact]
    public async Task Issue119_OwnedClient_DisposedAfterProbe_EvenOnFailure()
    {
        var healthyOwned = new TrackingDisposable();
        var brokenOwned = new TrackingDisposable();
        var broken = Substitute.For<IEthereumRpcClient>();
        broken.GetChainIdAsync(Arg.Any<CancellationToken>())
              .Returns<ulong>(_ => throw new HttpRequestException("boom"));

        await RunAsync(
            new Dictionary<string, IReadOnlyList<string>> { ["mainnet"] = [MainnetUrl, FallbackUrl] },
            candidate => candidate.RpcUrl == MainnetUrl
                ? (broken, brokenOwned)
                : (HealthyRpc(1, candidate), healthyOwned));

        brokenOwned.Disposed.Should().BeTrue();
        healthyOwned.Disposed.Should().BeTrue();
    }

    [Fact]
    public async Task Issue119_ThrowingLogger_ConfigurationStillCompletes()
    {
        var result = await RunAsync(
            new Dictionary<string, IReadOnlyList<string>> { ["mainnet"] = [MainnetUrl] },
            FactoryFor(new() { [MainnetUrl] = HealthyRpc(1, KnownNetworks.Mainnet) }),
            new AlwaysThrowingLogger());

        result.Should().ContainSingle().Which.RpcUrl.Should().Be(MainnetUrl);
    }

    // ── Public API without network access ────────────────────────────────────

    [Fact]
    public async Task Issue119_PublicApi_InvalidUrlsOnly_ReturnsEmptyWithoutNetwork()
    {
        // URL validation runs before any client construction, so the public path is
        // exercisable offline with candidates that never reach the network.
        var result = await EthrRpcAutoConfig.ConfigureAsync(
            new Dictionary<string, IReadOnlyList<string>> { ["mainnet"] = ["not a url"] });

        result.Should().BeEmpty();
    }

    // ── Adversarial round 1: a probe pass requires filter-matching logs ──────

    [Fact]
    public async Task Issue119_FabricatedLogs_NotMatchingProbe_AreRejected()
    {
        // Both red-team agents demonstrated that Count > 0 alone let a provider that
        // clamps fromBlock (or any hostile endpoint) pass with a recent/foreign log.
        // A pass now requires ≥1 log matching registry address, identity topic, and
        // the probe window.
        var probe = EthrRpcAutoConfig.FindProbe("mainnet")!;
        var matching = MatchingProbeLog(KnownNetworks.Mainnet);
        var shapes = new Dictionary<string, EthereumLogEntry>
        {
            ["below probed block"] = matching with { BlockNumber = "0x" + (probe.Block - 1).ToString("x") },
            ["above probed block"] = matching with { BlockNumber = "0x" + (probe.Block + 1).ToString("x") },
            ["foreign address"] = matching with { Address = "0x" + new string('d', 40) },
            ["foreign identity topic"] = matching with
            {
                Topics = [matching.Topics[0], "0x" + new string('c', 64)],
            },
            ["missing identity topic"] = matching with { Topics = [matching.Topics[0]] },
            ["malformed block number"] = matching with { BlockNumber = "bogus" },
            // Round 3, finding 4: topic0 outside the resolver's signature OR-list is
            // not an ERC-1056 registry event and must not prove archive depth.
            ["foreign event signature"] = matching with
            {
                Topics = ["0x" + new string('e', 64), matching.Topics[1]],
            },
        };

        foreach (var (label, entry) in shapes)
        {
            var rpc = Substitute.For<IEthereumRpcClient>();
            rpc.GetChainIdAsync(Arg.Any<CancellationToken>()).Returns(1UL);
            rpc.GetLogsAsync(Arg.Any<EthereumLogFilter>(), Arg.Any<CancellationToken>())
               .Returns(Task.FromResult<IReadOnlyList<EthereumLogEntry>>([entry]));
            var logger = new RecordingLogger();

            var result = await RunAsync(
                new Dictionary<string, IReadOnlyList<string>> { ["mainnet"] = [MainnetUrl] },
                _ => (rpc, null), logger);

            result.Should().BeEmpty($"a fabricated log ({label}) must not prove archive depth");
            logger.Entries.Should().Contain(e => e.Message.Contains("archive"),
                $"the ({label}) discard must stay actionable");
        }
    }

    [Fact]
    public async Task Issue119_MixedLogs_OneGenuineMatch_StillPasses()
    {
        // Positive pairing so the hardening cannot become honest-endpoint denial:
        // decoys beside one genuine match — including uppercase hex from the node,
        // which must match case-insensitively — still pass.
        var matching = MatchingProbeLog(KnownNetworks.Mainnet);
        var decoy = matching with { BlockNumber = "0x1" };
        var genuineUppercase = matching with
        {
            Address = "0x" + matching.Address[2..].ToUpperInvariant(),
            Topics = [matching.Topics[0], "0x" + matching.Topics[1][2..].ToUpperInvariant()],
        };
        var rpc = Substitute.For<IEthereumRpcClient>();
        rpc.GetChainIdAsync(Arg.Any<CancellationToken>()).Returns(1UL);
        rpc.GetLogsAsync(Arg.Any<EthereumLogFilter>(), Arg.Any<CancellationToken>())
           .Returns(Task.FromResult<IReadOnlyList<EthereumLogEntry>>([decoy, genuineUppercase]));

        var result = await RunAsync(
            new Dictionary<string, IReadOnlyList<string>> { ["mainnet"] = [MainnetUrl] },
            _ => (rpc, null));

        result.Should().ContainSingle().Which.RpcUrl.Should().Be(MainnetUrl);
    }

    // ── Adversarial round 1: refusal-shape failures stay actionable ──────────

    [Fact]
    public async Task Issue119_HistoricalProbeRefused_LogsArchiveHintAndTypeName()
    {
        // The real-world publicnode shape: chainId answers fine, the historical
        // eth_getLogs is REFUSED (RPC error → client throws), not empty-answered.
        // The discard must still name the archive cause, via bounded type names
        // only — never the exception object.
        var rpc = Substitute.For<IEthereumRpcClient>();
        rpc.GetChainIdAsync(Arg.Any<CancellationToken>()).Returns(1UL);
        rpc.GetLogsAsync(Arg.Any<EthereumLogFilter>(), Arg.Any<CancellationToken>())
           .Returns<IReadOnlyList<EthereumLogEntry>>(_ => throw new NetDid.Core.Exceptions.EthereumInteractionException(
               "RPC error for 'eth_getLogs': code -32602"));
        var logger = new RecordingLogger();

        var result = await RunAsync(
            new Dictionary<string, IReadOnlyList<string>> { ["mainnet"] = [MainnetUrl] },
            _ => (rpc, null), logger);

        result.Should().BeEmpty();
        logger.Entries.Should().Contain(e =>
            e.Message.Contains("archive")
            && e.Message.Contains("EthereumInteractionException")
            && e.Exception == null);
    }

    // ── Adversarial round 1: seam robustness and parameter validation ────────

    [Fact]
    public async Task Issue119_TimeoutBeyondCancelAfterRange_ThrowsOwnParameterName()
    {
        // CancelAfter caps at ~49.7 days; beyond it the public API must fail with
        // ITS parameter name, not an internal 'delay'.
        var act = () => RunAsync(
            new Dictionary<string, IReadOnlyList<string>> { ["mainnet"] = [MainnetUrl] },
            _ => (Substitute.For<IEthereumRpcClient>(), null),
            perEndpointTimeout: TimeSpan.MaxValue);

        (await act.Should().ThrowAsync<ArgumentOutOfRangeException>())
            .Which.ParamName.Should().Be("perEndpointTimeout");
    }

    [Fact]
    public async Task Issue119_ThrowingClientFactory_DiscardsCandidate_RunContinues()
    {
        var logger = new RecordingLogger();
        var result = await RunAsync(
            new Dictionary<string, IReadOnlyList<string>> { ["mainnet"] = [MainnetUrl, FallbackUrl] },
            candidate => candidate.RpcUrl == MainnetUrl
                ? throw new InvalidOperationException("hostile factory")
                : (HealthyRpc(1, KnownNetworks.Mainnet), null),
            logger);

        result.Should().ContainSingle().Which.RpcUrl.Should().Be(FallbackUrl);
        logger.Entries.Should().Contain(e => e.Message.Contains("failed"));
    }

    private sealed class ThrowingDisposable : IDisposable
    {
        public void Dispose() => throw new InvalidOperationException("hostile dispose");
    }

    [Fact]
    public async Task Issue119_ThrowingOwnedDispose_DoesNotAbortOrMaskOutcome()
    {
        var result = await RunAsync(
            new Dictionary<string, IReadOnlyList<string>> { ["mainnet"] = [MainnetUrl] },
            _ => (HealthyRpc(1, KnownNetworks.Mainnet), new ThrowingDisposable()));

        result.Should().ContainSingle().Which.RpcUrl.Should().Be(MainnetUrl);
    }

    /// <summary>Implements ICollection so a Count/CopyTo-based snapshot would see
    /// attacker URLs and a lying Count, while the enumerator yields the honest list —
    /// the snapshot must be built from enumeration, not the ICollection fast path.</summary>
    private sealed class LyingCollectionList : IReadOnlyList<string>, ICollection<string>
    {
        public int Count => 3;
        public bool IsReadOnly => true;
        public string this[int index] => "https://attacker.example";
        public void CopyTo(string[] array, int arrayIndex)
        {
            for (var i = arrayIndex; i < array.Length; i++)
                array[i] = "https://attacker.example";
        }
        public IEnumerator<string> GetEnumerator()
            => ((IEnumerable<string>)new[] { MainnetUrl }).GetEnumerator();
        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator()
            => GetEnumerator();
        public void Add(string item) => throw new NotSupportedException();
        public void Clear() => throw new NotSupportedException();
        public bool Contains(string item) => false;
        public bool Remove(string item) => throw new NotSupportedException();
    }

    [Fact]
    public async Task Issue119_HostileICollectionCandidateList_EnumeratedSnapshotWins()
    {
        var contacted = new List<string>();
        var result = await RunAsync(
            new Dictionary<string, IReadOnlyList<string>> { ["mainnet"] = new LyingCollectionList() },
            candidate =>
            {
                contacted.Add(candidate.RpcUrl);
                return (HealthyRpc(1, KnownNetworks.Mainnet), null);
            });

        contacted.Should().Equal([MainnetUrl],
            "the snapshot must come from enumeration, not a lying ICollection Count/CopyTo");
        result.Should().ContainSingle().Which.RpcUrl.Should().Be(MainnetUrl);
    }

    [Fact]
    public void Issue119_DefaultCandidateEndpoints_NotDowncastMutable()
    {
        (EthrRpcAutoConfig.DefaultCandidateEndpoints as Dictionary<string, IReadOnlyList<string>>)
            .Should().BeNull("the shipped defaults must not be mutable via downcast");
    }

    // ── Review round 2 (PR #129): probe depth, credential-safe logs, boundary ─

    /// <summary>An endpoint that serves (and fabricates perfectly matching answers
    /// for) any eth_getLogs query at or above <c>minServedBlock</c>, and returns
    /// empty below it — the shape of a provider pruned before that block.</summary>
    private static IEthereumRpcClient PrunedBelowRpc(ulong chainId, ulong minServedBlock)
    {
        var rpc = Substitute.For<IEthereumRpcClient>();
        rpc.GetChainIdAsync(Arg.Any<CancellationToken>()).Returns(chainId);
        rpc.GetLogsAsync(Arg.Any<EthereumLogFilter>(), Arg.Any<CancellationToken>())
           .Returns(call =>
           {
               var filter = call.Arg<EthereumLogFilter>();
               if (filter.FromBlock < minServedBlock)
                   return Task.FromResult<IReadOnlyList<EthereumLogEntry>>([]);
               return Task.FromResult<IReadOnlyList<EthereumLogEntry>>(
               [
                   new EthereumLogEntry
                   {
                       Address = filter.Address,
                       Topics =
                       [
                           "0x" + new string('a', 64),
                           filter.Topics?[1]?[0] ?? "0x" + new string('b', 64),
                       ],
                       Data = "0x",
                       BlockNumber = "0x" + filter.FromBlock.ToString("x"),
                       LogIndex = 0,
                   },
               ]);
           });
        return rpc;
    }

    [Fact]
    public async Task Issue119_EndpointPrunedBefore10M_MainnetProbe_Rejected()
    {
        // Review round 2, finding 1 (HIGH): real mainnet registry events exist at
        // block 7,049,729 (2019-01-11; identity 0xee9b…cfa22, previousChange = 0,
        // verified live). An endpoint pruned before block 10M can resolve NO 2019
        // DID, yet the original 10,001,700-window probe approved it. The mainnet
        // probe must use the oldest verifiable event, so such an endpoint fails.
        var logger = new RecordingLogger();
        var result = await RunAsync(
            new Dictionary<string, IReadOnlyList<string>> { ["mainnet"] = [MainnetUrl] },
            _ => (PrunedBelowRpc(1, minServedBlock: 10_000_000), null), logger);

        result.Should().BeEmpty(
            "an endpoint that cannot serve the oldest real mainnet registry events must not pass");
        logger.Entries.Should().Contain(e => e.Message.Contains("archive"));
    }

    // ── Round 2, finding 3 (HIGH): no credential material may reach logs ─────

    private const string SecretUrl =
        "https://user:SECRETPASS@rpc.example/v3/SECRETKEY?token=SECRETQUERY";
    private static readonly string[] Sentinels = ["SECRETPASS", "SECRETKEY", "SECRETQUERY"];

    private static void AssertNoSentinel(RecordingLogger logger)
        => logger.Entries.Should().OnlyContain(
            e => !Sentinels.Any(s => e.Message.Contains(s)),
            "credentials embedded in RPC URLs (userinfo, path, query) must never reach logs");

    [Fact]
    public async Task Issue119_SecretUrl_SelectedEndpoint_LogsSanitizedHostOnly()
    {
        var logger = new RecordingLogger();
        var result = await RunAsync(
            new Dictionary<string, IReadOnlyList<string>> { ["mainnet"] = [SecretUrl] },
            _ => (HealthyRpc(1, KnownNetworks.Mainnet), null), logger);

        // The returned config must keep the full URL (it is the working endpoint) …
        result.Should().ContainSingle().Which.RpcUrl.Should().Be(SecretUrl);
        // … while every log line carries at most scheme + host.
        AssertNoSentinel(logger);
        logger.Entries.Should().Contain(e => e.Message.Contains("rpc.example"));
    }

    [Fact]
    public async Task Issue119_SecretUrl_EveryDiscardShape_NeverLogsSecrets()
    {
        var shapes = new Dictionary<string, IEthereumRpcClient>
        {
            ["pruned"] = PrunedRpc(1),
            ["wrong chain"] = HealthyRpc(chainId: 137, KnownNetworks.Mainnet),
            ["transport failure"] = MakeThrowingRpc(new HttpRequestException("refused")),
            ["hung"] = MakeHungRpc(),
        };
        foreach (var (label, rpc) in shapes)
        {
            var logger = new RecordingLogger();
            var result = await RunAsync(
                new Dictionary<string, IReadOnlyList<string>> { ["mainnet"] = [SecretUrl] },
                _ => (rpc, null), logger,
                perEndpointTimeout: TimeSpan.FromMilliseconds(200));

            result.Should().BeEmpty($"({label}) endpoint must be discarded");
            AssertNoSentinel(logger);
        }
    }

    private static IEthereumRpcClient MakeThrowingRpc(Exception ex)
    {
        var rpc = Substitute.For<IEthereumRpcClient>();
        rpc.GetChainIdAsync(Arg.Any<CancellationToken>()).Returns<ulong>(_ => throw ex);
        return rpc;
    }

    private static IEthereumRpcClient MakeHungRpc()
    {
        var rpc = Substitute.For<IEthereumRpcClient>();
        rpc.GetChainIdAsync(Arg.Any<CancellationToken>())
           .Returns(new TaskCompletionSource<ulong>().Task);
        return rpc;
    }

    [Fact]
    public async Task Issue119_SecretInUnparseableCandidate_NeverLogged()
    {
        // An unparseable candidate cannot be sanitized by Uri parsing, so nothing
        // of it may be logged — only its position.
        var logger = new RecordingLogger();
        var result = await RunAsync(
            new Dictionary<string, IReadOnlyList<string>>
            {
                ["mainnet"] = ["https://user:SECRETPASS@bad url with spaces"],
            },
            _ => throw new InvalidOperationException("must not construct a client"), logger);

        result.Should().BeEmpty();
        AssertNoSentinel(logger);
        logger.Entries.Should().Contain(e => e.Message.Contains("not an absolute http(s) URL"));
    }

    // ── Round 2, finding 5: snapshot boundary — cancellation and caps ────────
    // (Reworked in round 3, finding 5: the earlier NonTerminatingList versions did
    // not FAIL against pre-fix code, they wedged the test process — finite hostile
    // enumerables give clean, reproducible fail-first evidence.)

    /// <summary>Throws on the first enumeration step; proves enumeration never
    /// started without any risk of wedging the test process.</summary>
    private sealed class ThrowOnEnumerationList : IReadOnlyList<string>
    {
        public int MoveNextCalls;
        public string this[int index] => MainnetUrl;
        public int Count => 1;
        public IEnumerator<string> GetEnumerator()
        {
            MoveNextCalls++;
            throw new InvalidOperationException("caller input was enumerated");
        }
        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator()
            => GetEnumerator();
    }

    [Fact]
    public async Task Issue119_PreCancelledToken_DoesNotEnumerateCallerInput()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        var hostile = new ThrowOnEnumerationList();

        var act = () => RunAsync(
            new Dictionary<string, IReadOnlyList<string>> { ["mainnet"] = hostile },
            _ => (HealthyRpc(1, KnownNetworks.Mainnet), null), ct: cts.Token);

        // Pre-fix this fails FAST with the list's own InvalidOperationException
        // (enumeration happened); post-fix the token check precedes any enumeration.
        await act.Should().ThrowAsync<OperationCanceledException>();
        hostile.MoveNextCalls.Should().Be(0,
            "a pre-cancelled call must not enumerate hostile caller input at all");
    }

    [Fact]
    public async Task Issue119_CandidatesPerNetwork_CappedWithLoggedTruncation()
    {
        // Finite Max + 2 candidate list: only the first Max may be materialized and
        // probed, and the truncation must be logged, never silent.
        var urls = Enumerable.Range(0, EthrRpcAutoConfig.MaxCandidatesPerNetwork + 2)
            .Select(i => $"https://candidate-{i}.example").ToArray();
        var probed = 0;
        var logger = new RecordingLogger();

        var result = await RunAsync(
            new Dictionary<string, IReadOnlyList<string>> { ["mainnet"] = urls },
            candidate =>
            {
                probed++;
                return (PrunedRpc(1), null);
            }, logger);

        result.Should().BeEmpty();
        probed.Should().Be(EthrRpcAutoConfig.MaxCandidatesPerNetwork);
        logger.Entries.Should().Contain(e => e.Message.Contains("truncated"),
            "silent truncation would read as full coverage");
    }

    // ── Round 3, finding 1: cancel-then-throw during snapshot enumeration ────

    /// <summary>A candidate list whose enumeration cancels the caller's token and
    /// then throws a different exception — the cancel-then-throw shape from
    /// tasks/lessons.md. The public contract says caller cancellation propagates
    /// as OperationCanceledException, so OCE must win over the decoy.</summary>
    private sealed class CancelThenThrowList(CancellationTokenSource cts) : IReadOnlyList<string>
    {
        public string this[int index] => MainnetUrl;
        public int Count => 1;
        public IEnumerator<string> GetEnumerator()
        {
            cts.Cancel();
            throw new InvalidOperationException("decoy after cancelling the caller");
        }
        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator()
            => GetEnumerator();
    }

    [Fact]
    public async Task Issue119_InnerListCancelsThenThrows_PropagatesAsCancellation()
    {
        using var cts = new CancellationTokenSource();

        var act = () => RunAsync(
            new Dictionary<string, IReadOnlyList<string>>
            {
                ["mainnet"] = new CancelThenThrowList(cts),
            },
            _ => (HealthyRpc(1, KnownNetworks.Mainnet), null), ct: cts.Token);

        await act.Should().ThrowAsync<OperationCanceledException>();
    }

    private sealed class CancelThenThrowDictionary(CancellationTokenSource cts)
        : IReadOnlyDictionary<string, IReadOnlyList<string>>
    {
        public IReadOnlyList<string> this[string key] => [MainnetUrl];
        public IEnumerable<string> Keys => ["mainnet"];
        public IEnumerable<IReadOnlyList<string>> Values => [[MainnetUrl]];
        public int Count => 1;
        public bool ContainsKey(string key) => true;
        public bool TryGetValue(string key, out IReadOnlyList<string> value)
        {
            value = [MainnetUrl];
            return true;
        }
        public IEnumerator<KeyValuePair<string, IReadOnlyList<string>>> GetEnumerator()
        {
            cts.Cancel();
            throw new InvalidOperationException("decoy after cancelling the caller");
        }
        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator()
            => GetEnumerator();
    }

    [Fact]
    public async Task Issue119_OuterMapCancelsThenThrows_PropagatesAsCancellation()
    {
        using var cts = new CancellationTokenSource();

        var act = () => RunAsync(
            new CancelThenThrowDictionary(cts),
            _ => (HealthyRpc(1, KnownNetworks.Mainnet), null), ct: cts.Token);

        await act.Should().ThrowAsync<OperationCanceledException>();
    }

    // ── Round 3, finding 2: caller-controlled map keys never reach logs raw ──

    [Fact]
    public async Task Issue119_HostileMapKeys_NeverLoggedRaw()
    {
        // Keys are caller-controlled text: a CR/LF key forges log lines, a huge key
        // floods, and a mistakenly URL-shaped key carries credentials. Invalid
        // entries are identified by ordinal only; resolved networks by their
        // canonical catalogue name.
        var crlfKey = "evil\r\n[CRITICAL] forged-entry";
        var secretKey = "https://user:SECRETPASS@rpc.example/v3/SECRETKEY?token=SECRETQUERY";
        var hugeKey = new string('k', 1_000_000);
        var logger = new RecordingLogger();

        var result = await RunAsync(
            new Dictionary<string, IReadOnlyList<string>>
            {
                [crlfKey] = [MainnetUrl],
                [secretKey] = [MainnetUrl],
                [hugeKey] = [MainnetUrl],
            },
            _ => throw new InvalidOperationException("unknown keys are never probed"), logger);

        result.Should().BeEmpty();
        logger.Entries.Should().OnlyContain(e =>
            !e.Message.Contains("SECRETPASS") && !e.Message.Contains("SECRETKEY")
            && !e.Message.Contains("SECRETQUERY") && !e.Message.Contains("forged-entry")
            && !e.Message.Contains('\r') && !e.Message.Contains('\n')
            && e.Message.Length < 1_000);
        logger.Entries.Should().HaveCountGreaterThanOrEqualTo(3,
            "each skipped entry is still reported, by ordinal");
    }

    [Fact]
    public async Task Issue119_NetworkEntries_CappedWithLoggedTruncation()
    {
        var candidates = new Dictionary<string, IReadOnlyList<string>>();
        for (var i = 0; i < EthrRpcAutoConfig.MaxCandidateNetworks + 5; i++)
            candidates[$"bogus-network-{i}"] = [MainnetUrl];
        var logger = new RecordingLogger();

        var result = await RunAsync(candidates,
            _ => throw new InvalidOperationException("unknown keys are never probed"), logger);

        result.Should().BeEmpty();
        logger.Entries.Should().Contain(e => e.Message.Contains("truncated"));
    }

    // ── Shipped data invariants ──────────────────────────────────────────────

    [Fact]
    public void Issue119_DefaultCandidateEndpoints_ResolveToKnownNetworks()
    {
        EthrRpcAutoConfig.DefaultCandidateEndpoints.Should().NotBeEmpty();
        foreach (var (key, urls) in EthrRpcAutoConfig.DefaultCandidateEndpoints)
        {
            KnownNetworks.Find(key).Should().NotBeNull($"default key '{key}' must be a known deployment");
            urls.Should().NotBeEmpty();
            urls.Should().OnlyContain(u =>
                Uri.IsWellFormedUriString(u, UriKind.Absolute) && u.StartsWith("https://"));
        }
    }

    [Fact]
    public void Issue119_HistoricalProbes_AreWellFormedAndMatchCatalogue()
    {
        EthrRpcAutoConfig.HistoricalProbes.Should().NotBeEmpty();
        foreach (var probe in EthrRpcAutoConfig.HistoricalProbes)
        {
            KnownNetworks.Find(probe.Network).Should().NotBeNull(
                $"probe network '{probe.Network}' must be a known deployment");
            probe.Identity.Should().MatchRegex("^0x[0-9a-f]{40}$",
                "identity must be a canonical lowercase address");
            probe.Block.Should().BeGreaterThan(0);
        }

        // Round 2, finding 1: the mainnet probe is pinned to the EARLIEST known
        // registry event (block 7,049,729, 2019-01-11, previousChange = 0). A
        // younger probe approves endpoints that cannot resolve the oldest real
        // DIDs — exactly the false assurance this feature exists to prevent.
        var mainnet = EthrRpcAutoConfig.FindProbe("mainnet")!;
        mainnet.Block.Should().Be(7_049_729);
        mainnet.Identity.Should().Be("0xee9bddd4cdd24174f91949293f415bfad57cfa22");
    }

    [Fact]
    public void Issue119_EveryDefaultEndpointNetwork_HasProbeData()
    {
        // The batteries-included networks must all be depth-verifiable: shipping a
        // default candidate list for a network we cannot probe would silently grant
        // "configured" status on a liveness check alone.
        foreach (var key in EthrRpcAutoConfig.DefaultCandidateEndpoints.Keys)
        {
            EthrRpcAutoConfig.FindProbe(key).Should().NotBeNull(
                $"default-endpoint network '{key}' must have historical probe data");
        }
    }

    [Fact]
    public void Issue119_EveryCatalogueNetwork_IsCoveredOrExplicitlyExcluded()
    {
        // Round 3, finding 3: the acceptance gap must be structurally visible.
        // Every KnownNetworks.All entry either has batteries-included coverage
        // (defaults + probe) or a documented exclusion with a stated reason —
        // a catalogue entry silently in neither set is the gap the reviewer
        // flagged. Scope narrowing is recorded on issue #119 itself.
        foreach (var network in KnownNetworks.All)
        {
            var hasDefaults = EthrRpcAutoConfig.DefaultCandidateEndpoints.ContainsKey(network.Name);
            var isExcluded = EthrRpcAutoConfig.NetworksWithoutDefaults.ContainsKey(network.Name);

            (hasDefaults ^ isExcluded).Should().BeTrue(
                $"network '{network.Name}' must have shipped defaults or a documented exclusion, not neither/both");
            if (isExcluded)
                EthrRpcAutoConfig.NetworksWithoutDefaults[network.Name].Should().NotBeNullOrWhiteSpace(
                    "each exclusion must state its reason");
        }
    }
}
