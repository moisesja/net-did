using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace NetDid.Method.Ethr.Rpc;

/// <summary>
/// Opt-in "batteries included" bootstrap for the official ERC-1056 deployments:
/// takes candidate public JSON-RPC endpoints per network, probes each one, and
/// returns ready-to-use <see cref="EthereumNetworkConfig"/>s for the endpoints
/// that actually work — without the caller hand-curating RPC URLs (issue #119).
///
/// <para><b>Why probing is necessary.</b> did:ethr resolution replays the full
/// ERC-1056 event history via <c>eth_getLogs</c>, including events that can be
/// years old. Many public endpoints pass a liveness check (<c>eth_chainId</c>)
/// yet do not serve historical logs — they answer old-range <c>eth_getLogs</c>
/// with an error or, worse, an empty array. Resolution against such an endpoint
/// fails closed at resolve time (see <c>IncompleteEventHistoryException</c>), but
/// only per DID and with an opaque error. Following the reference resolver
/// maintainer's approach, each candidate endpoint is therefore probed with a
/// hard-coded, on-chain-verified query for known-old registry events; an endpoint
/// that returns no logs for them is discarded up front with an actionable log
/// message.</para>
///
/// <para><b>Trust scope.</b> Probing verifies endpoint <i>availability and data
/// depth only</i>. A passing endpoint is still a single untrusted RPC node: it can
/// forge a self-consistent event history, and nothing in this helper (or in
/// resolution) detects that. Probe results are a quality filter, never an
/// integrity guarantee.</para>
///
/// <para>Typical usage — probe first, then register:</para>
/// <code>
/// var networks = await EthrRpcAutoConfig.ConfigureAsync(logger: logger);
/// var method = new DidEthrMethod(factory, networks, keyGenerator);
/// // or: builder.AddDidEthr(networks);
/// </code>
/// </summary>
public static class EthrRpcAutoConfig
{
    private static readonly TimeSpan DefaultPerEndpointTimeout = TimeSpan.FromSeconds(10);

    // CancellationTokenSource.CancelAfter rejects delays above ~49.7 days with its
    // own parameter name; validate here so the public API fails with OURS.
    internal static readonly TimeSpan MaxPerEndpointTimeout =
        TimeSpan.FromMilliseconds(uint.MaxValue - 2);

    /// <summary>
    /// Built-in candidate public endpoints for the major official deployments,
    /// keyed by <see cref="KnownNetworks"/> name. Each network's list is ordered:
    /// the first candidate that passes probing wins. Every first entry was verified
    /// to serve the network's historical probe at implementation time (2026-08),
    /// but public endpoints change policy without notice — that is exactly why
    /// <see cref="ConfigureAsync"/> probes at startup instead of trusting this
    /// list. Callers can pass their own dictionary (own keys, or extended lists)
    /// instead.
    /// </summary>
    public static IReadOnlyDictionary<string, IReadOnlyList<string>> DefaultCandidateEndpoints { get; } =
        // ReadOnlyDictionary: a bare Dictionary here is process-wide mutable via
        // downcast, silently redirecting every later ConfigureAsync(null).
        new System.Collections.ObjectModel.ReadOnlyDictionary<string, IReadOnlyList<string>>(
            new Dictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase)
            {
                ["mainnet"] = ["https://eth.drpc.org", "https://ethereum-rpc.publicnode.com"],
                ["sepolia"] = ["https://sepolia.drpc.org", "https://ethereum-sepolia-rpc.publicnode.com"],
                ["gno"]     = ["https://rpc.gnosischain.com", "https://gnosis.drpc.org"],
                ["polygon"] = ["https://polygon.drpc.org", "https://1rpc.io/matic"],
            });

    // ── Historical probes ─────────────────────────────────────────────────────
    // One entry per network, each an on-chain fact verified live via eth_getLogs
    // against archive-serving endpoints on 2026-08-02/03 (never fabricated — a
    // wrong probe would manufacture false verdicts in BOTH directions). Windows
    // span at most 41 blocks inclusive: several public providers cap eth_getLogs
    // ranges (1rpc.io: 50 blocks), and a probe must never be discarded for its
    // range when the endpoint would have served the data.
    //
    // Networks without an entry cannot have their historical depth verified;
    // ConfigureAsync then performs chain-ID validation only and logs a warning.
    // The reference resolver maintainer plans a companion auto-config library
    // with their own probe DID list; when it publishes, align these entries with
    // it so both ecosystems agree on what "serves historical data" means.
    internal static readonly IReadOnlyList<HistoricalLogProbe> HistoricalProbes =
    [
        // Mainnet, legacy registry: events for this identity at blocks 10,001,725
        // (DIDOwnerChanged) and 10,001,739 (DIDAttributeChanged), 2020-05-04.
        new HistoricalLogProbe
        {
            Network   = "mainnet",
            Identity  = "0xf87e64e1fd8098fde28fb0852459dc839f35de94",
            FromBlock = 10_001_700,
            ToBlock   = 10_001_740,
        },
        // Sepolia, current registry: earliest registry event on the network, a
        // DIDAttributeChanged for this identity at block 4,907,882 (2023-12-18).
        new HistoricalLogProbe
        {
            Network   = "sepolia",
            Identity  = "0x2ff0987ce5739e7ee45a9efd3b571c02c0a6db69",
            FromBlock = 4_907_860,
            ToBlock   = 4_907_900,
        },
        // Gnosis, current registry: earliest registry events on the network, for
        // this identity at block 45,566,242 (2026-04). The registry saw no earlier
        // use on Gnosis, so this probe can only prove ~months of historical depth.
        new HistoricalLogProbe
        {
            Network   = "gno",
            Identity  = "0xed4abf0bba69c63e2657cf94693cc4a9070896a2",
            FromBlock = 45_566_220,
            ToBlock   = 45_566_260,
        },
        // Polygon, legacy registry: earliest registry event on the network, a
        // DIDDelegateChanged for this identity at block 32,524,522 (2022-08-31).
        new HistoricalLogProbe
        {
            Network   = "polygon",
            Identity  = "0x6bad09aacca8ce0add18056b52a578cc9ad86979",
            FromBlock = 32_524_500,
            ToBlock   = 32_524_540,
        },
    ];

    /// <summary>
    /// Probes candidate JSON-RPC endpoints and returns a ready-to-use
    /// <see cref="EthereumNetworkConfig"/> per network for which a candidate passed,
    /// in <see cref="KnownNetworks.All"/> catalogue order.
    ///
    /// <para>Per network, candidates are tried sequentially and the first passing
    /// endpoint wins. A candidate passes when (a) its <c>eth_chainId</c> matches the
    /// catalogue entry and (b) an <c>eth_getLogs</c> query for that network's
    /// hard-coded known-old registry events returns at least one log that matches
    /// the probe itself — registry address, probed identity topic, and a block
    /// inside the probe window (a bare count would accept a provider that clamps
    /// <c>fromBlock</c> to its retained range). A candidate
    /// failing either check — or failing transport, timing out, or answering
    /// malformed data — is discarded with a logged reason and the next candidate is
    /// tried. Networks with no historical probe data are configured after the
    /// chain-ID check alone, with a logged warning that archive-grade serving is
    /// unverified. Networks with no passing candidate are omitted from the result
    /// (and logged), so the returned list is safe to hand directly to
    /// <c>DidEthrMethod</c> or <c>AddDidEthr</c>.</para>
    /// </summary>
    /// <param name="candidateEndpoints">
    /// Candidate endpoint URLs per network, keyed by <see cref="KnownNetworks"/>
    /// name or hex chain ID; <c>null</c> uses <see cref="DefaultCandidateEndpoints"/>.
    /// Keys that match no known deployment, and candidates that are not absolute
    /// http/https URLs, are skipped with a logged reason.
    /// </param>
    /// <param name="logger">
    /// Sink for per-endpoint decisions (each discarded endpoint is logged with its
    /// reason). Logging is best-effort: a throwing provider never breaks
    /// configuration.
    /// </param>
    /// <param name="perEndpointTimeout">
    /// Deadline for probing one candidate endpoint (both probe requests together);
    /// default 10 seconds. On expiry the candidate is discarded and the next one is
    /// tried. Each underlying request is additionally capped at 30 seconds by the
    /// hardened RPC client, so values above ~60 seconds cannot lengthen the probe
    /// further. The deadline bounds asynchronous waits: it is a hard bound against
    /// hostile/hung nodes via the default async client, but cannot preempt an
    /// injected client implementation that blocks synchronously before returning
    /// its task.
    /// </param>
    /// <param name="ct">
    /// Caller cancellation; propagates as <see cref="OperationCanceledException"/>
    /// and aborts the whole run (unlike a per-endpoint timeout).
    /// </param>
    public static Task<IReadOnlyList<EthereumNetworkConfig>> ConfigureAsync(
        IReadOnlyDictionary<string, IReadOnlyList<string>>? candidateEndpoints = null,
        ILogger? logger = null,
        TimeSpan? perEndpointTimeout = null,
        CancellationToken ct = default)
        => ConfigureCoreAsync(candidateEndpoints, logger, perEndpointTimeout, CreateOwnedClient, ct);

    // Testability seam: tests inject per-candidate IEthereumRpcClient fakes; the
    // public path builds one owned DefaultEthereumRpcClient per candidate URL.
    // The returned IDisposable (if any) is disposed after the candidate's probe.
    internal static async Task<IReadOnlyList<EthereumNetworkConfig>> ConfigureCoreAsync(
        IReadOnlyDictionary<string, IReadOnlyList<string>>? candidateEndpoints,
        ILogger? logger,
        TimeSpan? perEndpointTimeout,
        Func<EthereumNetworkConfig, (IEthereumRpcClient Client, IDisposable? Owned)> clientFactory,
        CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(clientFactory);
        var timeout = perEndpointTimeout ?? DefaultPerEndpointTimeout;
        if (timeout <= TimeSpan.Zero || timeout > MaxPerEndpointTimeout)
            throw new ArgumentOutOfRangeException(nameof(perEndpointTimeout),
                $"Per-endpoint timeout must be positive and at most {MaxPerEndpointTimeout}.");
        var log = logger ?? NullLogger.Instance;

        // Snapshot the caller-supplied interface-typed input ONCE at entry: a hostile
        // implementation can return different contents per enumeration, and every
        // later decision (and log line) must describe the same data that was probed.
        // Snapshot lists via their ENUMERATOR explicitly — a collection-expression
        // spread takes the ICollection Count/CopyTo fast path, which a hostile list
        // can answer differently from its enumerator (and a lying huge Count would
        // allocate unbounded).
        var snapshot = new List<(string Key, List<string?> Urls)>();
        foreach (var pair in candidateEndpoints ?? DefaultCandidateEndpoints)
        {
            var urls = new List<string?>();
            if (pair.Value is { } candidateList)
            {
                foreach (var url in candidateList)
                    urls.Add(url);
            }
            snapshot.Add((pair.Key, urls));
        }

        // Resolve keys against the deployment catalogue; dedupe aliases of the same
        // network ("mainnet" and "0x1"); order deterministically by catalogue order.
        var resolved = new List<(int Order, EthereumNetworkConfig Network, List<string?> Urls)>();
        var seenNetworks = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (key, urls) in snapshot)
        {
            if (key is null || KnownNetworks.Find(key) is not { } network)
            {
                LogSafe(log, LogLevel.Warning,
                    "did:ethr auto-config: candidate key '{Key}' matches no known " +
                    "ERC-1056 deployment; skipped.", key);
                continue;
            }
            if (!seenNetworks.Add(network.Name))
            {
                LogSafe(log, LogLevel.Warning,
                    "did:ethr auto-config: candidate key '{Key}' resolves to network " +
                    "'{Network}' which is already listed; skipped.", key, network.Name);
                continue;
            }
            var order = 0;
            for (; order < KnownNetworks.All.Count; order++)
            {
                if (ReferenceEquals(KnownNetworks.All[order], network))
                    break;
            }
            resolved.Add((order, network, urls));
        }
        resolved.Sort((a, b) => a.Order.CompareTo(b.Order));

        var configured = new List<EthereumNetworkConfig>();
        foreach (var (_, network, urls) in resolved)
        {
            ct.ThrowIfCancellationRequested();
            var probe = FindProbe(network.Name);
            string? healthyUrl = null;

            foreach (var url in urls)
            {
                ct.ThrowIfCancellationRequested();
                if (url is null
                    || !Uri.TryCreate(url, UriKind.Absolute, out var uri)
                    || (uri.Scheme != Uri.UriSchemeHttps && uri.Scheme != Uri.UriSchemeHttp))
                {
                    LogSafe(log, LogLevel.Warning,
                        "did:ethr auto-config: candidate '{Url}' for network '{Network}' " +
                        "discarded: not an absolute http(s) URL.", url, network.Name);
                    continue;
                }

                var candidate = network with { RpcUrl = url };
                var outcome = await ProbeCandidateAsync(clientFactory, candidate, probe, timeout, ct);
                ct.ThrowIfCancellationRequested();

                switch (outcome.Kind)
                {
                    case ProbeOutcomeKind.Passed:
                        LogSafe(log, LogLevel.Information,
                            "did:ethr auto-config: endpoint '{Url}' selected for network " +
                            "'{Network}': chain ID matches and the known-historical probe " +
                            "(blocks {FromBlock}-{ToBlock}) returned logs.",
                            url, network.Name, probe!.FromBlock, probe.ToBlock);
                        healthyUrl = url;
                        break;

                    case ProbeOutcomeKind.PassedUnverified:
                        LogSafe(log, LogLevel.Warning,
                            "did:ethr auto-config: endpoint '{Url}' selected for network " +
                            "'{Network}' after chain-ID validation only — no historical " +
                            "probe data exists for this network, so archive-grade " +
                            "eth_getLogs serving is UNVERIFIED; resolution of DIDs with " +
                            "old events may still fail against this endpoint.",
                            url, network.Name);
                        healthyUrl = url;
                        break;

                    case ProbeOutcomeKind.WrongChainId:
                        LogSafe(log, LogLevel.Warning,
                            "did:ethr auto-config: endpoint '{Url}' for network '{Network}' " +
                            "discarded: eth_chainId returned {ActualChainId}, expected " +
                            "{ExpectedChainId}.",
                            url, network.Name, outcome.ActualChainId, network.ChainId);
                        break;

                    case ProbeOutcomeKind.NoHistoricalLogs:
                        LogSafe(log, LogLevel.Warning,
                            "did:ethr auto-config: endpoint '{Url}' for network '{Network}' " +
                            "discarded: eth_getLogs returned no logs matching the known-old " +
                            "registry events (blocks {FromBlock}-{ToBlock}) — the endpoint " +
                            "does not serve archive/historical data. did:ethr resolution " +
                            "requires an archive-grade endpoint; supply one with historical " +
                            "eth_getLogs support.",
                            url, network.Name, probe!.FromBlock, probe.ToBlock);
                        break;

                    case ProbeOutcomeKind.TimedOut:
                        LogSafe(log, LogLevel.Warning,
                            "did:ethr auto-config: endpoint '{Url}' for network '{Network}' " +
                            "discarded: the probe was cancelled by the per-endpoint deadline " +
                            "({Timeout}) or the RPC client's per-request bound.",
                            url, network.Name, timeout);
                        break;

                    // Failure text is bounded TYPE NAMES only: the exception object is
                    // never handed to the sink because a remote endpoint controls
                    // inner-exception text (e.g. a duplicate-JSON-key ArgumentException
                    // quotes the attacker's key, CR/LF and multi-MiB included) and
                    // standard providers render the full chain.
                    case ProbeOutcomeKind.Failed when outcome.HistoricalStage:
                        LogSafe(log, LogLevel.Warning,
                            "did:ethr auto-config: endpoint '{Url}' for network '{Network}' " +
                            "discarded: the historical-logs probe for known-old registry " +
                            "events (blocks {FromBlock}-{ToBlock}) failed ({FailureType}; " +
                            "innermost {RootFailureType}) — the endpoint likely does not " +
                            "serve archive/historical eth_getLogs (some providers refuse " +
                            "archive queries outside a paid tier); supply an archive-grade " +
                            "endpoint.",
                            url, network.Name, probe!.FromBlock, probe.ToBlock,
                            FailureTypeName(outcome.Failure), RootFailureTypeName(outcome.Failure));
                        break;

                    default:
                        LogSafe(log, LogLevel.Warning,
                            "did:ethr auto-config: endpoint '{Url}' for network '{Network}' " +
                            "discarded: the probe request failed ({FailureType}; innermost " +
                            "{RootFailureType}).",
                            url, network.Name,
                            FailureTypeName(outcome.Failure), RootFailureTypeName(outcome.Failure));
                        break;
                }

                if (healthyUrl is not null)
                    break;
            }

            if (healthyUrl is not null)
            {
                configured.Add(network with { RpcUrl = healthyUrl });
            }
            else
            {
                LogSafe(log, LogLevel.Warning,
                    "did:ethr auto-config: no candidate endpoint for network '{Network}' " +
                    "passed probing; the network is omitted from the configuration.",
                    network.Name);
            }
        }

        ct.ThrowIfCancellationRequested();
        return configured;
    }

    internal static HistoricalLogProbe? FindProbe(string networkName)
        => HistoricalProbes.FirstOrDefault(p =>
            string.Equals(p.Network, networkName, StringComparison.OrdinalIgnoreCase));

    // ── Per-endpoint probe ────────────────────────────────────────────────────

    private enum ProbeOutcomeKind
    {
        Passed,
        PassedUnverified,
        WrongChainId,
        NoHistoricalLogs,
        TimedOut,
        Failed,
    }

    private readonly record struct ProbeOutcome(
        ProbeOutcomeKind Kind, ulong ActualChainId = 0, Exception? Failure = null,
        bool HistoricalStage = false);

    /// <summary>
    /// Full per-candidate containment: the client-factory call, the probe, and the
    /// owned-client disposal. A throwing factory or Dispose (injectable seam) is that
    /// candidate's failure, never a reason to abort the remaining networks or mask
    /// the probe outcome; only caller cancellation escapes.
    /// </summary>
    private static async Task<ProbeOutcome> ProbeCandidateAsync(
        Func<EthereumNetworkConfig, (IEthereumRpcClient Client, IDisposable? Owned)> clientFactory,
        EthereumNetworkConfig candidate,
        HistoricalLogProbe? probe,
        TimeSpan timeout,
        CancellationToken ct)
    {
        IEthereumRpcClient client;
        IDisposable? owned;
        try
        {
            (client, owned) = clientFactory(candidate);
        }
        catch (Exception ex) when (ex is not OperationCanceledException
            || !ct.IsCancellationRequested)
        {
            return new ProbeOutcome(ProbeOutcomeKind.Failed, Failure: ex);
        }

        try
        {
            return await ProbeEndpointAsync(client, candidate, probe, timeout, ct);
        }
        finally
        {
            try
            {
                owned?.Dispose();
            }
            catch
            {
                // A hostile Dispose must not mask the probe outcome.
            }
        }
    }

    private static async Task<ProbeOutcome> ProbeEndpointAsync(
        IEthereumRpcClient rpc,
        EthereumNetworkConfig candidate,
        HistoricalLogProbe? probe,
        TimeSpan timeout,
        CancellationToken ct)
    {
        // One deadline for the whole candidate, started before the first awaited
        // dependency; every dependency await is bounded at its own site AND the
        // token is re-checked after each await (a completed task deliberately
        // beats a fired token in WaitAsyncObserved).
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(timeout);
        var token = deadline.Token;
        var historicalStage = false;

        try
        {
            if (!TryParseChainId(candidate.ChainId, out var expectedChainId))
            {
                // Unreachable for catalogue entries (all carry a ChainId); fail closed
                // rather than skipping the identity check if that ever changes.
                return new ProbeOutcome(ProbeOutcomeKind.Failed, Failure: new InvalidOperationException(
                    "Network catalogue entry carries no parseable chain ID."));
            }

            token.ThrowIfCancellationRequested();
            var actualChainId = await rpc.GetChainIdAsync(token).WaitAsyncObserved(token);
            token.ThrowIfCancellationRequested();
            if (actualChainId != expectedChainId)
                return new ProbeOutcome(ProbeOutcomeKind.WrongChainId, actualChainId);

            if (probe is null)
                return new ProbeOutcome(ProbeOutcomeKind.PassedUnverified);

            var paddedIdentity = PadIdentityTopic(probe.Identity);
            var filter = new EthereumLogFilter
            {
                Address   = candidate.RegistryAddress,
                FromBlock = probe.FromBlock,
                ToBlock   = probe.ToBlock,
                Topics    = [null, [paddedIdentity]],
            };
            historicalStage = true;
            token.ThrowIfCancellationRequested();
            var logs = await rpc.GetLogsAsync(filter, token).WaitAsyncObserved(token);
            token.ThrowIfCancellationRequested();

            return AnyLogMatchesProbe(logs, candidate, probe, paddedIdentity)
                ? new ProbeOutcome(ProbeOutcomeKind.Passed)
                : new ProbeOutcome(ProbeOutcomeKind.NoHistoricalLogs);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // Caller cancellation aborts the whole run; only the per-endpoint
            // deadline is a discard-and-continue condition.
            throw;
        }
        catch (OperationCanceledException)
        {
            return new ProbeOutcome(ProbeOutcomeKind.TimedOut, HistoricalStage: historicalStage);
        }
        catch (Exception ex)
        {
            // Probing is a quality filter over unreliable public endpoints: ANY
            // failure (transport, malformed response, hostile shape) means "this
            // candidate is unusable", never "abort configuring the other networks".
            return new ProbeOutcome(ProbeOutcomeKind.Failed, Failure: ex,
                HistoricalStage: historicalStage);
        }
    }

    /// <summary>
    /// A probe pass requires at least one returned log that actually matches what
    /// was asked for: the registry address, the probed identity topic, and a block
    /// inside the probe window. Counting alone is not evidence — a provider that
    /// silently clamps <c>fromBlock</c> to its earliest retained block (observed
    /// real-world behavior), or a hostile endpoint fabricating an arbitrary log,
    /// would otherwise pass while serving no historical data at all. Matching is
    /// case-insensitive (nodes may emit checksummed/uppercase hex).
    /// </summary>
    private static bool AnyLogMatchesProbe(
        IReadOnlyList<EthereumLogEntry> logs,
        EthereumNetworkConfig candidate,
        HistoricalLogProbe probe,
        string paddedIdentity)
    {
        for (var i = 0; i < logs.Count; i++)
        {
            var entry = logs[i];
            if (entry is null)
                continue;
            if (!string.Equals(entry.Address, candidate.RegistryAddress,
                    StringComparison.OrdinalIgnoreCase))
                continue;
            if (entry.Topics is not { Count: >= 2 } topics
                || !string.Equals(topics[1], paddedIdentity, StringComparison.OrdinalIgnoreCase))
                continue;
            if (!TryParseHexQuantity(entry.BlockNumber, out var block)
                || block < probe.FromBlock || block > probe.ToBlock)
                continue;
            return true;
        }
        return false;
    }

    private static bool TryParseChainId(string? chainId, out ulong value)
        => TryParseHexQuantity(chainId, out value);

    private static bool TryParseHexQuantity(string? quantity, out ulong value)
    {
        value = 0;
        if (quantity is null
            || !quantity.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
            || quantity.Length <= 2)
            return false;
        return ulong.TryParse(quantity.AsSpan(2),
            System.Globalization.NumberStyles.HexNumber,
            System.Globalization.CultureInfo.InvariantCulture, out value);
    }

    private static string PadIdentityTopic(string identity)
        => "0x" + identity[2..].ToLowerInvariant().PadLeft(64, '0');

    private static (IEthereumRpcClient Client, IDisposable? Owned) CreateOwnedClient(
        EthereumNetworkConfig candidate)
    {
        // The probe owns this client. HttpClient's hidden 100-second default is
        // neutralized so the timeout authorities are exactly two: the hardened RPC
        // client's per-request 30-second cap and this helper's per-endpoint deadline.
        var http = new HttpClient
        {
            BaseAddress = new Uri(candidate.RpcUrl, UriKind.Absolute),
            Timeout     = System.Threading.Timeout.InfiniteTimeSpan,
        };
        return (new DefaultEthereumRpcClient(http), http);
    }

    /// <summary>
    /// Best-effort logging: a hostile or broken provider that throws from
    /// <c>Log</c> must never break auto-configuration (same never-throw stance as
    /// resolution's failure logging). Deliberately takes no <see cref="Exception"/>:
    /// endpoint-controlled exception text must never reach the sink — failures are
    /// described by bounded type names in the template arguments instead.
    /// </summary>
    private static void LogSafe(
        ILogger logger, LogLevel level, string messageTemplate, params object?[] args)
    {
        try
        {
            logger.Log(level, messageTemplate, args);
        }
        catch
        {
            // Swallow: logging is diagnostics, not behavior.
        }
    }

    private static string FailureTypeName(Exception? failure)
        => failure?.GetType().Name ?? "unknown";

    /// <summary>Innermost exception type name (bounded walk — a hostile exception
    /// graph must not turn diagnostics into an unbounded traversal).</summary>
    private static string RootFailureTypeName(Exception? failure)
    {
        if (failure is null)
            return "unknown";
        var current = failure;
        for (var depth = 0; depth < 8 && current.InnerException is { } inner; depth++)
            current = inner;
        return current.GetType().Name;
    }
}

/// <summary>
/// A known-old, on-chain-verified ERC-1056 event query used to test whether an
/// endpoint serves historical <c>eth_getLogs</c>: at least one event for
/// <see cref="Identity"/> is known to exist on <see cref="Network"/>'s registry
/// within [<see cref="FromBlock"/>, <see cref="ToBlock"/>], so an empty answer
/// means the endpoint does not serve data that old.
/// </summary>
internal sealed record HistoricalLogProbe
{
    /// <summary>The <see cref="KnownNetworks"/> name this probe belongs to.</summary>
    public required string Network { get; init; }

    /// <summary>Identity address (0x-prefixed) with known events in the window.</summary>
    public required string Identity { get; init; }

    /// <summary>Inclusive start of the probe block window.</summary>
    public required ulong FromBlock { get; init; }

    /// <summary>Inclusive end of the probe block window (kept ≤ 40 blocks after
    /// <see cref="FromBlock"/> to stay under public providers' range caps).</summary>
    public required ulong ToBlock { get; init; }
}
