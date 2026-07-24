using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using NetDid.Core;
using NetCrypto;
using NetDid.Core.Exceptions;
using NetDid.Core.Model;
using NetDid.Method.Ethr.Crypto;
using NetDid.Method.Ethr.Erc1056;
using NetDid.Method.Ethr.Resolution;
using NetDid.Method.Ethr.Rpc;

namespace NetDid.Method.Ethr;

/// <summary>
/// Implementation of the did:ethr DID method (Phase 1: Create + Resolve).
/// Update and Deactivate are stubbed and will be filled in Phase 2.
/// </summary>
public sealed class DidEthrMethod : DidMethodBase
{
    private readonly IEthereumRpcClientFactory _rpcFactory;
    private readonly IReadOnlyList<EthereumNetworkConfig> _networks;
    private readonly IKeyGenerator _keyGenerator;
    private readonly ILogger<DidEthrMethod> _logger;

    public DidEthrMethod(
        IEthereumRpcClientFactory rpcFactory,
        IEnumerable<EthereumNetworkConfig> networks,
        IKeyGenerator keyGenerator,
        ILogger<DidEthrMethod>? logger = null)
    {
        _rpcFactory   = rpcFactory ?? throw new ArgumentNullException(nameof(rpcFactory));
        _networks     = networks?.ToList() ?? throw new ArgumentNullException(nameof(networks));
        _keyGenerator = keyGenerator ?? throw new ArgumentNullException(nameof(keyGenerator));
        _logger       = logger ?? NullLogger<DidEthrMethod>.Instance;
    }

    public override string MethodName => "ethr";
    public override DidMethodCapabilities Capabilities =>
        DidMethodCapabilities.Create |
        DidMethodCapabilities.Resolve |
        DidMethodCapabilities.ServiceEndpoints;

    /// <summary>did:ethr only accepts secp256k1 keys for DID creation.</summary>
    public override IReadOnlyList<KeyType> SupportedKeyTypes { get; } = [KeyType.Secp256k1];

    // Defensive bounds against a hostile RPC node. The endpoint is untrusted, so
    // resolution must be bounded on every axis a node controls — not just count:
    //   • hops / events  — a fabricated previousChange chain (one eth_getLogs per
    //                       hop) or an event flood. Far above any realistic history.
    //   • aggregate bytes — the event count cap is byte-blind: one large-value
    //                       attribute per hop stays under it yet retains ~response-cap
    //                       bytes per hop → multi-GB heap. Bound total retained bytes.
    //   • aggregate time  — hops × the per-request timeout is hours; an overall
    //                       resolution deadline (see ResolveCoreAsync) bounds wall-clock,
    //                       covering the post-walk per-event block-timestamp fan-out too.
    // Exceeding any bound aborts resolution, mapped to a resolution error.
    private const int  MaxEventChainHops   = 1_000;
    private const int  MaxCollectedEvents  = 5_000;
    private const long MaxCollectedBytes   = 32L * 1024 * 1024; // 32 MiB retained
    private static readonly TimeSpan ResolutionDeadline = TimeSpan.FromSeconds(120);

    // ── Create ────────────────────────────────────────────────────────────────

    protected override async Task<DidCreateResult> CreateCoreAsync(
        DidCreateOptions options, CancellationToken ct)
    {
        if (options is not DidEthrCreateOptions ethrOptions)
            throw new ArgumentException(
                $"Options must be {nameof(DidEthrCreateOptions)}.", nameof(options));

        byte[] publicKey;
        if (ethrOptions.ExistingKey is not null)
        {
            if (ethrOptions.ExistingKey.KeyType != KeyType.Secp256k1)
                throw new ArgumentException(
                    "ExistingKey must be a Secp256k1 key for did:ethr.", nameof(options));
            publicKey = KeyTypeExtensions.NormalizeToCompressed(
                ethrOptions.ExistingKey.KeyType, ethrOptions.ExistingKey.PublicKey.ToArray());
        }
        else
        {
            var keyPair = _keyGenerator.Generate(KeyType.Secp256k1);
            publicKey = keyPair.PublicKey;
        }

        var address = EthereumAddress.FromCompressedPublicKey(publicKey).ToLowerInvariant();
        var network = FindNetwork(ethrOptions.Network);
        var rpc     = _rpcFactory.GetOrCreate(network);
        var chainId = await ResolveChainId(network, rpc, ct);
        var did     = $"did:ethr:{ethrOptions.Network.ToLowerInvariant()}:{address}";
        var identifier = new EthrIdentifier(ethrOptions.Network.ToLowerInvariant(), address, false, null);

        var doc = EthrDocumentBuilder.Build(did, identifier, chainId, [], DateTimeOffset.UtcNow, false);

        return new DidCreateResult
        {
            Did         = new Did(did),
            DidDocument = doc,
        };
    }

    // ── Resolve ───────────────────────────────────────────────────────────────

    protected override async Task<DidResolutionResult> ResolveCoreAsync(
        string did, DidResolutionOptions? options, CancellationToken ct)
    {
        EthrIdentifier identifier;
        try { identifier = EthrIdentifier.Parse(did); }
        catch (ArgumentException ex)
        {
            _logger.LogWarning(ex, "Failed to parse did:ethr identifier: {Did}", did);
            return DidResolutionResult.InvalidDid(did);
        }

        EthereumNetworkConfig network;
        try { network = FindNetwork(identifier.Network); }
        catch (InvalidOperationException ex)
        {
            _logger.LogWarning(ex, "Network not configured for did:ethr: {Did}", did);
            return DidResolutionResult.NotFound(did);
        }
        var rpc     = _rpcFactory.GetOrCreate(network);

        // Everything past this point consumes UNTRUSTED data from the RPC node
        // (event bytes, hex fields, JSON shape). A resolver must never throw out
        // of ResolveAsync — it must return resolutionMetadata.error. Map any such
        // failure to notFound, but let genuine caller cancellation propagate.
        //
        // An overall deadline bounds total wall-clock across the walk and the
        // post-walk block-timestamp fan-out, so a slow-drip node cannot tie up
        // resolution for hours within the per-request timeouts. When THIS token
        // fires (not the caller's), ct.IsCancellationRequested is false, so it
        // falls through to notFound rather than propagating as cancellation.
        using var deadlineCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadlineCts.CancelAfter(ResolutionDeadline);
        try
        {
            return await ResolveFromChainAsync(did, identifier, network, rpc, options, deadlineCts.Token);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "did:ethr resolution failed against RPC data for {Did}", did);
            return DidResolutionResult.NotFound(did);
        }
    }

    private async Task<DidResolutionResult> ResolveFromChainAsync(
        string did, EthrIdentifier identifier, EthereumNetworkConfig network,
        IEthereumRpcClient rpc, DidResolutionOptions? options, CancellationToken ct)
    {
        var chainId = await ResolveChainId(network, rpc, ct);

        // Determine version / block ceiling
        ulong? versionBlockNumber = null;
        if (options?.VersionId is string vid && ulong.TryParse(vid, out var vb))
            versionBlockNumber = vb;

        // changed(identity) → first block that has a relevant event
        var changedHex    = Erc1056Calls.Changed(identifier.IdentityAddress);
        var changedResult = await rpc.CallAsync(network.RegistryAddress, changedHex, ct);
        var latestChange  = ParseHexUlong(changedResult);

        // Collect events walking backwards from min(latestChange, versionBlock)
        var ceiling = versionBlockNumber.HasValue
            ? Math.Min(latestChange, versionBlockNumber.Value)
            : latestChange;

        var collectedEvents = new List<Erc1056Event>();
        if (ceiling > 0)
            await WalkEventChainAsync(
                rpc, network.RegistryAddress, identifier.IdentityAddress,
                ceiling, collectedEvents, ct);

        // Oldest-first
        collectedEvents.Reverse();

        // Reference time & optional block-timestamp fetching for VersionTime
        DateTimeOffset referenceTime;
        ulong?         nextVersionId = null;

        if (versionBlockNumber.HasValue)
        {
            var ts = await rpc.GetBlockTimestampAsync(versionBlockNumber.Value, ct);
            referenceTime = DateTimeOffset.FromUnixTimeSeconds((long)ts);

            // Peek at the next change block after versionBlockNumber for metadata
            if (latestChange > versionBlockNumber.Value)
                nextVersionId = latestChange; // simplified — Phase 2 can refine
        }
        else if (options?.VersionTime is string vtStr
            && DateTimeOffset.TryParse(vtStr, out var vt))
        {
            referenceTime = vt;
            // Fetch block timestamps and trim events
            var blockTsCache = new Dictionary<ulong, ulong>();
            var trimmed = new List<Erc1056Event>();
            foreach (var ev in collectedEvents)
            {
                if (!blockTsCache.TryGetValue(ev.BlockNumber, out var bts))
                {
                    bts = await rpc.GetBlockTimestampAsync(ev.BlockNumber, ct);
                    blockTsCache[ev.BlockNumber] = bts;
                }
                if (DateTimeOffset.FromUnixTimeSeconds((long)bts) <= referenceTime)
                    trimmed.Add(ev);
                else if (nextVersionId is null)
                    nextVersionId = ev.BlockNumber;
            }
            collectedEvents = trimmed;
        }
        else
        {
            referenceTime = DateTimeOffset.UtcNow;
        }

        // Detect deactivation
        bool isDeactivated = collectedEvents
            .OfType<OwnerChangedEvent>()
            .LastOrDefault()?.NewOwner == "0x0000000000000000000000000000000000000000";

        var doc = EthrDocumentBuilder.Build(did, identifier, chainId,
            collectedEvents, referenceTime, isDeactivated);

        // Build metadata
        var lastChangeBlock = collectedEvents.Count > 0
            ? collectedEvents[^1].BlockNumber : 0UL;

        var meta = new DidDocumentMetadata
        {
            VersionId   = versionBlockNumber?.ToString() ?? (lastChangeBlock > 0 ? lastChangeBlock.ToString() : null),
            Deactivated = isDeactivated ? true : null,
            NextVersionId = nextVersionId?.ToString(),
        };

        return new DidResolutionResult
        {
            DidDocument        = doc,
            ResolutionMetadata = new DidResolutionMetadata { ContentType = DidContentTypes.JsonLd },
            DocumentMetadata   = meta,
        };
    }

    // ── Event chain walker ────────────────────────────────────────────────────

    private async Task WalkEventChainAsync(
        IEthereumRpcClient rpc,
        string registryAddress, string identityAddress,
        ulong fromBlock, List<Erc1056Event> accumulator, CancellationToken ct)
    {
        var currentBlock = fromBlock;
        var hops = 0;
        long collectedBytes = 0;
        while (currentBlock > 0)
        {
            // Bound the number of block hops: a hostile node can point every
            // previousChange one block lower, turning the walk into an arbitrarily
            // long chain of sequential eth_getLogs calls (DoS). The "strictly less
            // than currentBlock" advance below prevents same-block cycles but not
            // length, so cap the traversal explicitly.
            if (++hops > MaxEventChainHops)
                throw new EthereumInteractionException(
                    $"did:ethr event chain for identity {identityAddress} exceeded " +
                    $"{MaxEventChainHops} block hops; aborting to avoid unbounded RPC traversal.");

            var paddedIdentity = "0x" + identityAddress[2..].PadLeft(64, '0').ToLowerInvariant();
            var filter = new EthereumLogFilter
            {
                Address   = registryAddress,
                FromBlock = currentBlock,
                ToBlock   = currentBlock,
                // topics[0]: event signature OR-list
                // topics[1]: indexed identity address — server-side filter eliminates
                //            events for other identities, cutting RPC payload on busy networks.
                Topics    =
                [
                    [
                        Erc1056Topics.DIDOwnerChanged,
                        Erc1056Topics.DIDDelegateChanged,
                        Erc1056Topics.DIDAttributeChanged,
                    ],
                    [paddedIdentity],
                ],
            };

            var logs = await rpc.GetLogsAsync(filter, ct);

            // nextBlock = the highest previousChange value that is STRICTLY less than
            // currentBlock.  Later transactions in the same block emit
            // previousChange == currentBlock (because changed[identity] was already
            // updated by an earlier tx in the block); following those values would
            // revisit the same block and loop forever.  Only values < currentBlock
            // represent a genuinely earlier block in the chain.
            ulong nextBlock = 0;

            foreach (var log in logs)
            {
                try
                {
                    var ev = Erc1056EventParser.Parse(log);
                    if (!string.Equals(ev.Identity, identityAddress,
                            StringComparison.OrdinalIgnoreCase))
                        continue;
                    accumulator.Add(ev);
                    // Bound total events: a hostile node can pack a single block with
                    // unbounded matching logs (memory DoS) even within the hop cap.
                    if (accumulator.Count > MaxCollectedEvents)
                        throw new EthereumInteractionException(
                            $"did:ethr event chain for identity {identityAddress} exceeded " +
                            $"{MaxCollectedEvents} events; aborting to bound memory use.");
                    // Bound total RETAINED bytes: the event count cap is byte-blind, so
                    // a few large-value attribute events per hop could still exhaust the
                    // heap. Attribute values are the only wire-sized retained field.
                    collectedBytes += (ev as AttributeChangedEvent)?.Value.Length ?? 0;
                    if (collectedBytes > MaxCollectedBytes)
                        throw new EthereumInteractionException(
                            $"did:ethr event chain for identity {identityAddress} exceeded " +
                            $"{MaxCollectedBytes} retained bytes; aborting to bound memory use.");
                    // Advance only when previousChange points to a strictly earlier block.
                    if (ev.PreviousChange < currentBlock && ev.PreviousChange > nextBlock)
                        nextBlock = ev.PreviousChange;
                }
                catch (ArgumentException ex)
                {
                    _logger.LogWarning(ex, "Skipping unparseable ERC-1056 log at block {Block}", currentBlock);
                }
            }

            currentBlock = nextBlock;
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private EthereumNetworkConfig FindNetwork(string network)
    {
        var match = _networks.FirstOrDefault(n =>
            string.Equals(n.Name, network, StringComparison.OrdinalIgnoreCase)
            || string.Equals(n.ChainId, network, StringComparison.OrdinalIgnoreCase));

        if (match is null)
            throw new InvalidOperationException(
                $"No network configuration found for '{network}'. " +
                $"Registered networks: {string.Join(", ", _networks.Select(n => n.Name))}");
        return match;
    }

    private async Task<string> ResolveChainId(EthereumNetworkConfig network, IEthereumRpcClient rpc, CancellationToken ct)
    {
        if (network.ChainId is not null)
        {
            var hex = network.ChainId.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
                ? network.ChainId[2..] : network.ChainId;
            return Convert.ToUInt64(hex, 16).ToString();
        }
        var chainId = await rpc.GetChainIdAsync(ct);
        return chainId.ToString();
    }

    private static ulong ParseHexUlong(string hex)
    {
        var clean = hex.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? hex[2..] : hex;
        if (clean.Length == 0) return 0;
        return Convert.ToUInt64(clean.TrimStart('0').Length == 0 ? "0" : clean.TrimStart('0'), 16);
    }
}
