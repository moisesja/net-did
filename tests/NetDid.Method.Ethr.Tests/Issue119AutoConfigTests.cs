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

    private static EthereumLogEntry SomeLog(string registry) => new()
    {
        Address = registry,
        Topics = ["0x" + new string('a', 64), "0x" + new string('b', 64)],
        Data = "0x",
        BlockNumber = "0x989680",
        LogIndex = 0,
    };

    /// <summary>An rpc whose chainId matches and whose probe query returns one log.</summary>
    private static IEthereumRpcClient HealthyRpc(ulong chainId, string registry)
    {
        var rpc = Substitute.For<IEthereumRpcClient>();
        rpc.GetChainIdAsync(Arg.Any<CancellationToken>()).Returns(chainId);
        rpc.GetLogsAsync(Arg.Any<EthereumLogFilter>(), Arg.Any<CancellationToken>())
           .Returns(Task.FromResult<IReadOnlyList<EthereumLogEntry>>([SomeLog(registry)]));
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
                [FallbackUrl] = HealthyRpc(1, KnownNetworks.Mainnet.RegistryAddress),
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
            FactoryFor(new() { [MainnetUrl] = HealthyRpc(chainId: 137, KnownNetworks.Mainnet.RegistryAddress) }),
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
               [SomeLog(KnownNetworks.Mainnet.RegistryAddress)]));

        await RunAsync(
            new Dictionary<string, IReadOnlyList<string>> { ["mainnet"] = [MainnetUrl] },
            _ => (rpc, null));

        var probe = EthrRpcAutoConfig.FindProbe("mainnet")!;
        seen.Should().NotBeNull();
        seen!.Address.Should().Be(KnownNetworks.Mainnet.RegistryAddress);
        seen.FromBlock.Should().Be(probe.FromBlock);
        seen.ToBlock.Should().Be(probe.ToBlock);
        seen.Topics.Should().HaveCount(2);
        seen.Topics![0].Should().BeNull("topic0 (event signature) must match any event kind");
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
                [FallbackUrl] = HealthyRpc(1, KnownNetworks.Mainnet.RegistryAddress),
            }), logger);

        result.Should().ContainSingle().Which.RpcUrl.Should().Be(FallbackUrl);
        logger.Entries.Should().Contain(e =>
            e.Message.Contains("failed") && e.Exception is HttpRequestException);
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
                ["https://sepolia.example"] = HealthyRpc(11155111, KnownNetworks.Sepolia.RegistryAddress),
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
                return (HealthyRpc(1, candidate.RegistryAddress), null);
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
    public async Task Issue119_UnknownNetworkKey_SkippedWithLog()
    {
        var logger = new RecordingLogger();
        var result = await RunAsync(
            new Dictionary<string, IReadOnlyList<string>> { ["not-a-network"] = [MainnetUrl] },
            _ => throw new InvalidOperationException("must not construct a client"), logger);

        result.Should().BeEmpty();
        logger.Entries.Should().Contain(e => e.Message.Contains("not-a-network"));
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
                return (HealthyRpc(1, candidate.RegistryAddress), null);
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
                return (HealthyRpc(1, candidate.RegistryAddress), null);
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
            ["https://polygon.example"] = HealthyRpc(137, KnownNetworks.Polygon.RegistryAddress),
            ["https://mainnet.example"] = HealthyRpc(1, KnownNetworks.Mainnet.RegistryAddress),
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
            FactoryFor(new() { [MainnetUrl] = HealthyRpc(1, KnownNetworks.Mainnet.RegistryAddress) }),
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
                [FallbackUrl] = HealthyRpc(1, KnownNetworks.Mainnet.RegistryAddress),
            }),
            logger, perEndpointTimeout: TimeSpan.FromMilliseconds(200));

        result.Should().ContainSingle().Which.RpcUrl.Should().Be(FallbackUrl);
        logger.Entries.Should().Contain(e => e.Message.Contains("did not complete"));
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
                : (HealthyRpc(1, candidate.RegistryAddress), healthyOwned));

        brokenOwned.Disposed.Should().BeTrue();
        healthyOwned.Disposed.Should().BeTrue();
    }

    [Fact]
    public async Task Issue119_ThrowingLogger_ConfigurationStillCompletes()
    {
        var result = await RunAsync(
            new Dictionary<string, IReadOnlyList<string>> { ["mainnet"] = [MainnetUrl] },
            FactoryFor(new() { [MainnetUrl] = HealthyRpc(1, KnownNetworks.Mainnet.RegistryAddress) }),
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
            probe.ToBlock.Should().BeGreaterThan(probe.FromBlock);
            (probe.ToBlock - probe.FromBlock).Should().BeLessOrEqualTo(40,
                "windows must stay under public providers' eth_getLogs range caps");
        }
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
}
