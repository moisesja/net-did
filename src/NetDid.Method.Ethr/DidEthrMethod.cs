using System.Globalization;
using System.Numerics;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using NetDid.Core;
using NetCrypto;
using NetDid.Core.Exceptions;
using NetDid.Core.Model;
using NetDid.Method.Ethr.Abi;
using NetDid.Method.Ethr.Crypto;
using NetDid.Method.Ethr.Erc1056;
using NetDid.Method.Ethr.Resolution;
using NetDid.Method.Ethr.Rpc;
using NetDid.Method.Ethr.Transactions;

namespace NetDid.Method.Ethr;

/// <summary>
/// Implementation of the did:ethr DID method — full CRUD against the ERC-1056
/// EthereumDIDRegistry. Create derives a DID from a secp256k1 key with no transaction;
/// Resolve replays the on-chain event history; Update and Deactivate submit registry
/// transactions (directly, or as relayed meta-transactions) signed through NetCrypto's
/// <see cref="IRecoverableDigestSigner"/> seam.
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
        DidMethodCapabilities.Update |
        DidMethodCapabilities.Deactivate |
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

    /// <summary>
    /// Overall wall-clock bound for one resolution. Internal so tests can shorten it.
    /// Enforced with <see cref="AbandonableTaskExtensions.WaitAsyncObserved{T}"/> on
    /// every dependency await in the resolve path, so even an injected RPC client that
    /// ignores cancellation cannot hang resolution past it, retain per-resolution
    /// continuations on a shared hung task, or resume abandoned work later.
    /// </summary>
    internal TimeSpan ResolutionDeadline { get; set; } = TimeSpan.FromSeconds(120);

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
            using var keyPair = _keyGenerator.Generate(KeyType.Secp256k1);
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
            try { _logger.LogWarning(ex, "Failed to parse did:ethr identifier: {Did}", did); }
            catch { /* logging is best-effort; the resolver never throws */ }
            return DidResolutionResult.InvalidDid(did);
        }

        if (!TryParseResolutionOptions(
                options, out var versionBlockNumber, out var versionTime))
            return DidResolutionResult.InvalidOptions(did);

        EthereumNetworkConfig network;
        try { network = FindNetwork(identifier.Network); }
        catch (InvalidOperationException ex)
        {
            try { _logger.LogWarning(ex, "Network not configured for did:ethr: {Did}", did); }
            catch { /* logging is best-effort; the resolver never throws */ }
            return DidResolutionResult.NotFound(did);
        }
        // Everything past this point consumes UNTRUSTED data from the RPC node
        // (event bytes, hex fields, JSON shape). A resolver must never throw out
        // of ResolveAsync — it must return resolutionMetadata.error. Every failure
        // in here is resolver INFRASTRUCTURE (pruned/hostile node, transport,
        // timeout), never a statement about the DID's existence — a genuinely
        // unregistered identity resolves to the ERC-1056 genesis document instead
        // of erroring. Map failures to internalError (issue #116); genuine caller
        // cancellation propagates.
        //
        // An overall deadline bounds total wall-clock across the walk and the
        // post-walk block-timestamp fan-out, so a slow-drip node cannot tie up
        // resolution for hours within the per-request timeouts. When THIS token
        // fires (not the caller's), ct.IsCancellationRequested is false, so it
        // falls through to internalError rather than propagating as cancellation.
        using var deadlineCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadlineCts.CancelAfter(ResolutionDeadline);
        try
        {
            // The client factory is an injected dependency: a throw from it is
            // infrastructure too, and must not defeat the never-throw contract.
            //
            // Deadline mechanics: every dependency await INSIDE the resolve path
            // (CallAsync / GetLogsAsync / GetBlockTimestampAsync / GetChainIdAsync) is
            // individually bounded with WaitAsyncObserved, so when the deadline fires
            // the inner state machine unwinds immediately — BCL WaitAsync removes its
            // continuation from the dependency task, and a client that ignores
            // cancellation and returns one shared forever-pending task retains at most
            // ONE deduped fault observer, not one continuation per resolution, and can
            // never resume abandoned work (no post-deadline RPC fan-out on late
            // completion). The outer wrap below is defense in depth for any future
            // non-dependency await added to ResolveFromChainAsync.
            var rpc = _rpcFactory.GetOrCreate(network);
            return await ResolveFromChainAsync(
                    did, identifier, network, rpc, versionBlockNumber, versionTime,
                    deadlineCts.Token)
                .WaitAsyncObserved(deadlineCts.Token);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (OperationCanceledException ex)
        {
            // The caller's token did NOT fire: this is the overall resolution deadline
            // or the RPC client's per-request timeout — resolver infrastructure.
            LogResolveFailure(ex, did);
            return DidResolutionResult.InternalError(did,
                "did:ethr resolution timed out against the RPC endpoint before the " +
                "event history could be retrieved; the DID's existence was not determined.");
        }
        catch (EthereumInteractionException ex)
        {
            LogResolveFailure(ex, did);
            // Fixed, library-owned reason text ONLY: Exception.Message arriving through
            // an injectable seam is untrusted regardless of exception type — anyone can
            // construct the public EthereumInteractionException with arbitrary text, and
            // our own messages interpolate node-supplied fragments. The one category
            // callers need to distinguish (pruned/incomplete history, issue #116) is
            // identified by an internal sealed marker type that code outside this
            // assembly cannot instantiate — the TYPE is the trusted provenance, and the
            // caller-facing text is a constant.
            var reason = ex is IncompleteEventHistoryException
                ? "did:ethr event history is incomplete: a block asserted by the " +
                  "registry's changed() pointer returned no matching ERC-1056 events " +
                  "(pruned/non-archive or hostile RPC endpoint); retry against an " +
                  "archive node."
                : "Ethereum RPC interaction failed.";
            return DidResolutionResult.InternalError(did, reason);
        }
        catch (Exception ex)
        {
            LogResolveFailure(ex, did);
            return DidResolutionResult.InternalError(did,
                "did:ethr resolution failed against RPC data.");
        }
    }

    /// <summary>
    /// Logs a resolution failure without letting logging defeat the resolver's
    /// never-throw contract: providers may format the exception eagerly
    /// (ToString → Message) and a hostile injected dependency can throw from those
    /// virtual members — and the provider itself may throw on ANY call. First
    /// attempt carries the exception; the retry carries type-name-only diagnostics;
    /// after that the failure is swallowed — logging is best-effort.
    /// </summary>
    private void LogResolveFailure(Exception ex, string did)
    {
        try
        {
            _logger.LogWarning(ex,
                "did:ethr resolution failed against RPC infrastructure for {Did}", did);
        }
        catch
        {
            try
            {
                _logger.LogWarning(
                    "did:ethr resolution failed against RPC infrastructure for {Did}; " +
                    "diagnostics unavailable — {ExceptionType} or the logging provider " +
                    "threw while formatting", did, ex.GetType().FullName);
            }
            catch
            {
                // An always-throwing provider must not break resolution.
            }
        }
    }

    private async Task<DidResolutionResult> ResolveFromChainAsync(
        string did, EthrIdentifier identifier, EthereumNetworkConfig network,
        IEthereumRpcClient rpc, ulong? versionBlockNumber,
        DateTimeOffset? versionTime, CancellationToken ct)
    {
        var chainId = await ResolveChainId(network, rpc, ct);

        // changed(identity) → first block that has a relevant event
        var changedHex    = Erc1056Calls.Changed(identifier.IdentityAddress);
        var changedResult = await rpc.CallAsync(network.RegistryAddress, changedHex, ct)
            .WaitAsyncObserved(ct);
        var latestChange  = ParseChangedResult(changedResult);

        // Collect the FULL event history (walk from the latest change to genesis).
        // Historical resolution partitions this list by block number below — we must NOT
        // start the walk at a requested version, or a version between two changes would
        // miss the earlier change and collapse to a genesis document.
        var collectedEvents = new List<Erc1056Event>();
        if (latestChange > 0)
            await WalkEventChainAsync(
                rpc, network.RegistryAddress, identifier.IdentityAddress,
                latestChange, collectedEvents, ct);

        // Order oldest-first BY BLOCK. OrderBy is stable and each block's events were
        // appended in ascending log order during the walk, so this reorders blocks
        // oldest-first WITHOUT reversing events within a block — a flat List.Reverse()
        // would invert a same-block add→revoke into revoke→add and leave a revoked key live.
        collectedEvents = collectedEvents.OrderBy(e => e.BlockNumber).ToList();

        // Reference time & optional block-timestamp fetching for VersionTime
        DateTimeOffset referenceTime;
        ulong?         nextVersionId = null;

        if (versionBlockNumber.HasValue)
        {
            // Resolve as of a specific block: the adjacent next change is the first event
            // STRICTLY after the requested block (collectedEvents is ascending); then keep
            // only changes at or before the requested block.
            var version = versionBlockNumber.Value;
            nextVersionId = collectedEvents
                .FirstOrDefault(e => e.BlockNumber > version)?.BlockNumber;
            collectedEvents = collectedEvents
                .Where(e => e.BlockNumber <= version).ToList();

            // Expire delegates/attributes/services against the requested block's timestamp.
            // Historical resolution necessarily trusts the node's block timestamp as the
            // reference clock (there is no other clock for a past block); this grants a
            // hostile node no power it lacks over validTo itself. Default (non-historical)
            // resolution uses the trusted local UtcNow below.
            var ts = await rpc.GetBlockTimestampAsync(version, ct).WaitAsyncObserved(ct);
            referenceTime = DateTimeOffset.FromUnixTimeSeconds((long)ts);
        }
        else if (versionTime is { } vt)
        {
            referenceTime = vt;
            // Validate timestamps as a non-decreasing chain, then retain only
            // the valid chronological prefix at or before the requested time.
            var trimmed = new List<Erc1056Event>();
            ulong? previousTimestamp = null;
            foreach (var blockEvents in collectedEvents.GroupBy(ev => ev.BlockNumber))
            {
                var bts = await rpc.GetBlockTimestampAsync(blockEvents.Key, ct)
                    .WaitAsyncObserved(ct);
                if (previousTimestamp is { } prior && bts < prior)
                    throw new EthereumInteractionException(
                        $"did:ethr block timestamps decrease: block " +
                        $"{blockEvents.Key} has {bts} after {prior}.");
                previousTimestamp = bts;

                if (DateTimeOffset.FromUnixTimeSeconds((long)bts) <= referenceTime)
                    trimmed.AddRange(blockEvents);
                else if (nextVersionId is null)
                    nextVersionId = blockEvents.Key;
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
            // The version is the block of the last APPLIED change (post-partition), not the
            // requested block — metadata must report the state actually returned.
            VersionId   = lastChangeBlock > 0 ? lastChangeBlock.ToString() : null,
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

            var logs = (await rpc.GetLogsAsync(filter, ct).WaitAsyncObserved(ct))?.ToList()
                ?? throw new EthereumInteractionException(
                    $"did:ethr history for identity {identityAddress} returned a null log collection.");

            // nextBlock = the highest previousChange value that is STRICTLY less than
            // currentBlock.  Later transactions in the same block emit
            // previousChange == currentBlock (because changed[identity] was already
            // updated by an earlier tx in the block); following those values would
            // revisit the same block and loop forever.  Only values < currentBlock
            // represent a genuinely earlier block in the chain.
            ulong nextBlock = 0;
            var blockEvents = new List<Erc1056Event>(logs.Count);
            var seenLogIndices = new HashSet<ulong>();

            // Canonical intra-block order: sort by logIndex rather than trusting the node's
            // response array order, so a same-block add→revoke of one key always applies in
            // chain order (the block-level OrderBy in ResolveFromChainAsync is stable and
            // preserves this).
            foreach (var log in logs.OrderBy(l => l.LogIndex))
            {
                if (log is null)
                    throw new EthereumInteractionException(
                        $"did:ethr history for identity {identityAddress} contains a null log " +
                        $"at block {currentBlock}.");
                if (!string.Equals(log.Address, registryAddress,
                        StringComparison.OrdinalIgnoreCase))
                    throw new EthereumInteractionException(
                        $"did:ethr history for identity {identityAddress} contains a log from " +
                        $"registry '{log.Address}' instead of '{registryAddress}'.");
                if (!seenLogIndices.Add(log.LogIndex))
                    throw new EthereumInteractionException(
                        $"did:ethr history for identity {identityAddress} contains duplicate " +
                        $"logIndex {log.LogIndex} at block {currentBlock}.");

                var ev = Erc1056EventParser.Parse(log);
                if (!string.Equals(ev.Identity, identityAddress,
                        StringComparison.OrdinalIgnoreCase))
                    throw new EthereumInteractionException(
                        $"did:ethr history block {currentBlock} contains an event for foreign " +
                        $"identity {ev.Identity}; expected {identityAddress}.");
                if (ev.BlockNumber != currentBlock)
                    throw new EthereumInteractionException(
                        $"did:ethr history event reports block {ev.BlockNumber}; expected " +
                        $"{currentBlock}.");
                if (ev.PreviousChange > currentBlock)
                    throw new EthereumInteractionException(
                        $"did:ethr history event at block {currentBlock} points forward to " +
                        $"previousChange {ev.PreviousChange}.");

                blockEvents.Add(ev);
            }

            // changed()/previousChange asserts a real event exists at this block. If the
            // node returned no matching event, the authorization history is incomplete or corrupt —
            // fail CLOSED to a resolution error rather than silently returning a partial
            // document that could re-authorize a revoked key or hide a deactivation.
            if (blockEvents.Count == 0)
                throw new IncompleteEventHistoryException(
                    $"did:ethr history for identity {identityAddress} is incomplete: block " +
                    $"{currentBlock} has no valid matching ERC-1056 event (pruned/non-archive " +
                    "or hostile RPC node).");

            // ERC-1056 updates changed[identity] to block.number after every mutation.
            // Therefore the earliest event for this identity in a block must point to
            // a genuinely earlier block (or zero), and every later same-block event
            // must point back to this block. Any other sequence proves the filtered
            // history is truncated or internally inconsistent.
            if (blockEvents[0].PreviousChange >= currentBlock)
                throw new EthereumInteractionException(
                    $"did:ethr history block {currentBlock} starts with previousChange " +
                    $"{blockEvents[0].PreviousChange}; the first event must point to an earlier block.");
            for (var eventIndex = 1; eventIndex < blockEvents.Count; eventIndex++)
            {
                if (blockEvents[eventIndex].PreviousChange != currentBlock)
                    throw new EthereumInteractionException(
                        $"did:ethr history block {currentBlock} event {eventIndex} has " +
                        $"previousChange {blockEvents[eventIndex].PreviousChange}; every event " +
                        "after the first must point to the current block.");
            }

            nextBlock = blockEvents[0].PreviousChange;

            // Commit a block only after every log in it has passed validation. This avoids
            // retaining a valid authorization while silently dropping a malformed revoke.
            if (accumulator.Count + blockEvents.Count > MaxCollectedEvents)
                throw new EthereumInteractionException(
                    $"did:ethr event chain for identity {identityAddress} exceeded " +
                    $"{MaxCollectedEvents} events; aborting to bound memory use.");

            foreach (var ev in blockEvents)
            {
                collectedBytes += (ev as AttributeChangedEvent)?.Value.Length ?? 0;
                if (collectedBytes > MaxCollectedBytes)
                    throw new EthereumInteractionException(
                        $"did:ethr event chain for identity {identityAddress} exceeded " +
                        $"{MaxCollectedBytes} retained bytes; aborting to bound memory use.");
            }

            accumulator.AddRange(blockEvents);
            currentBlock = nextBlock;
        }
    }

    // ── Update / Deactivate ───────────────────────────────────────────────────

    private const string ZeroAddress = "0x0000000000000000000000000000000000000000";

    /// <summary>
    /// Overall wall-clock bound for one Update/Deactivate call (all of its transactions).
    /// Internal so tests can shorten it; when it fires, the failure reports receipt-confirmed
    /// transactions separately from locally known hashes that may still confirm.
    /// </summary>
    internal TimeSpan WriteDeadline { get; set; } = TimeSpan.FromMinutes(3);

    protected override async Task<DidUpdateResult> UpdateCoreAsync(
        string did, DidUpdateOptions options, CancellationToken ct)
    {
        if (options is not DidEthrUpdateOptions ethrOptions)
            throw new ArgumentException(
                $"Options must be {nameof(DidEthrUpdateOptions)}.", nameof(options));

        // Snapshot caller-supplied interface-typed collections ONCE at the trust
        // boundary; every later read uses these private copies. (Attribute Value
        // arrays are snapshotted by the operation builder itself.)
        var removeServices   = ethrOptions.RemoveServices?.ToList() ?? [];
        var revokeDelegates  = ethrOptions.RevokeDelegates?.ToList() ?? [];
        var removeAttributes = ethrOptions.RemoveAttributes?.ToList() ?? [];
        var addServices      = ethrOptions.AddServices?.ToList() ?? [];
        var addDelegates     = ethrOptions.AddDelegates?.ToList() ?? [];
        var addAttributes    = ethrOptions.AddAttributes?.ToList() ?? [];
        var newOwner         = ethrOptions.NewOwnerAddress;

        if (removeServices.Count + revokeDelegates.Count + removeAttributes.Count
            + addServices.Count + addDelegates.Count + addAttributes.Count == 0
            && newOwner is null)
            throw new ArgumentException(
                "The update must contain at least one operation.", nameof(options));

        var identifier = EthrIdentifier.Parse(did);
        var identity = identifier.IdentityAddress;

        // Build (and thereby validate) every operation BEFORE any RPC traffic.
        // Order: revocations, then additions, then — always last — the owner change,
        // because changeOwner strips the current key's authority over later operations.
        var operations = new List<Erc1056Operation>();
        foreach (var service in removeServices)
            operations.Add(Erc1056TransactionBuilder.RevokeAttribute(
                identity, "did/svc/" + Required(service, nameof(DidEthrUpdateOptions.RemoveServices)).ServiceType,
                Encoding.UTF8.GetBytes(service.ServiceEndpoint)));
        foreach (var del in revokeDelegates)
            operations.Add(Erc1056TransactionBuilder.RevokeDelegate(
                identity, Required(del, nameof(DidEthrUpdateOptions.RevokeDelegates)).DelegateType,
                del.DelegateAddress));
        foreach (var attribute in removeAttributes)
            operations.Add(Erc1056TransactionBuilder.RevokeAttribute(
                identity, Required(attribute, nameof(DidEthrUpdateOptions.RemoveAttributes)).Name,
                attribute.Value));
        foreach (var service in addServices)
            operations.Add(Erc1056TransactionBuilder.SetAttribute(
                identity, "did/svc/" + Required(service, nameof(DidEthrUpdateOptions.AddServices)).ServiceType,
                Encoding.UTF8.GetBytes(service.ServiceEndpoint),
                ValiditySeconds(service.Validity)));
        foreach (var del in addDelegates)
            operations.Add(Erc1056TransactionBuilder.AddDelegate(
                identity, Required(del, nameof(DidEthrUpdateOptions.AddDelegates)).DelegateType,
                del.DelegateAddress, ValiditySeconds(del.Validity)));
        foreach (var attribute in addAttributes)
            operations.Add(Erc1056TransactionBuilder.SetAttribute(
                identity, Required(attribute, nameof(DidEthrUpdateOptions.AddAttributes)).Name,
                attribute.Value, ValiditySeconds(attribute.Validity)));
        if (newOwner is not null)
            operations.Add(Erc1056TransactionBuilder.ChangeOwner(identity, newOwner));

        using var deadlineCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadlineCts.CancelAfter(WriteDeadline);
        var token = deadlineCts.Token;

        var (transactionHashes, controllerAddress) = await ExecuteOperationsAsync(
            identifier, ethrOptions.ControllerKey, ethrOptions.UseMetaTransaction,
            ethrOptions.Relayer, operations, ct, token);

        // EVERYTHING past this point runs with operations already on-chain, so every failure
        // here must still carry the landed set — a post-loop throw that reported nothing was
        // how the first evidence fix stayed reachable (it only guarded the submission loop).
        try
        {
            token.ThrowIfCancellationRequested();
            var result = await BuildUpdateResultAsync(
                did, identifier, transactionHashes, controllerAddress, newOwner, token)
                .WaitAsyncObserved(token);
            token.ThrowIfCancellationRequested();
            return result;
        }
        catch (OperationCanceledException ex) when (ct.IsCancellationRequested)
        {
            throw AttachTransactionEvidence(ex, transactionHashes);
        }
        catch (OperationCanceledException ex) when (deadlineCts.IsCancellationRequested)
        {
            throw AttachTransactionEvidence(CreateDeadlineException(
                ex, transactionHashes, [], operations.Count), transactionHashes);
        }
        catch (Exception ex)
        {
            throw AttachTransactionEvidence(ex, transactionHashes);
        }
    }

    private async Task<DidUpdateResult> BuildUpdateResultAsync(
        string did, EthrIdentifier identifier, List<string> transactionHashes,
        string controllerAddress, string? newOwner, CancellationToken ct)
    {
        var identity = identifier.IdentityAddress;
        var resolved = await ResolveAsync(did, null, ct).WaitAsyncObserved(ct);
        ct.ThrowIfCancellationRequested();
        if (resolved.DidDocument is null)
            throw new EthereumInteractionException(
                $"did:ethr update transactions landed [{string.Join(", ", transactionHashes)}] " +
                $"but post-update resolution failed: {resolved.ResolutionMetadata.Error}.");

        // did:ethr's update authority is exactly the identity owner; delegates and attributes
        // never gain update rights. Read that authority back FROM THE CHAIN rather than
        // inferring it from what we submitted: a racing third party (or the very owner change
        // we just made) decides who can sign the next update, and evidence derived from intent
        // would report a key that no longer holds authority. Reading also normalizes the
        // address to the method's canonical form (lowercase, 0x-prefixed).
        var network = FindNetwork(identifier.Network);
        var effectiveOwner = ParseAddressWordResult(
            await _rpcFactory.GetOrCreate(network).CallAsync(
                network.RegistryAddress, Erc1056Calls.IdentityOwner(identity), ct)
                .WaitAsyncObserved(ct));
        ct.ThrowIfCancellationRequested();

        // That eth_call and the event log both come from the same untrusted node, so trusting
        // it alone just swaps one unauthenticated oracle for another. The document the
        // resolver just replayed already knows the controller; require the two to agree, so a
        // node must forge BOTH consistently rather than one cheap call.
        var documentController = resolved.DidDocument.VerificationMethod?
            .FirstOrDefault(vm => vm.Id.EndsWith("#controller", StringComparison.Ordinal))?
            .BlockchainAccountId;

        // A deactivated document carries NO verification methods, so there is no controller
        // to compare against — the naive "skip when null" left the read-back unchecked in
        // exactly that case. The event history still pins the answer: it says the owner slot
        // was zeroed, and the contract's identityOwner() returns the identity when the slot
        // is zero, so the registry must report the identity itself.
        var expectedOwner = resolved.DocumentMetadata?.Deactivated == true
            ? identity
            : ExtractAddress(documentController);

        if (expectedOwner is not null
            && !string.Equals(expectedOwner, effectiveOwner, StringComparison.OrdinalIgnoreCase))
            throw new EthereumInteractionException(
                $"did:ethr update transactions landed [{string.Join(", ", transactionHashes)}] " +
                $"but the registry reports owner {effectiveOwner} while the replayed event " +
                $"history implies {expectedOwner}. Refusing to report contradictory " +
                "update-authority evidence.");

        // The null address is unownable: nobody can authorize a further update. The empty list
        // is DidUpdateResult's documented "no keys are authorized" signal — reporting
        // 0x000…000 as an effective key would claim a key nobody holds retains authority.
        var deactivated = string.Equals(effectiveOwner, ZeroAddress, StringComparison.OrdinalIgnoreCase);
        var authorityChanged = !string.Equals(effectiveOwner, controllerAddress, StringComparison.OrdinalIgnoreCase);

        return new DidUpdateResult
        {
            DidDocument = resolved.DidDocument,
            Artifacts = new Dictionary<string, object>
            {
                ["transactions"] = (IReadOnlyList<string>)transactionHashes,
                ["registry"] = network.RegistryAddress,
            },
            AuthorizationChange = authorityChanged
                ? AuthorizationChangeStatus.Changed : AuthorizationChangeStatus.Unchanged,
            UpdateKeyChange = authorityChanged
                ? AuthorizationChangeStatus.Changed : AuthorizationChangeStatus.Unchanged,
            RevealedUpdateKeys  = [controllerAddress],
            EffectiveUpdateKeys = deactivated ? [] : [effectiveOwner],
        };
    }

    protected override async Task<DidDeactivateResult> DeactivateCoreAsync(
        string did, DidDeactivateOptions options, CancellationToken ct)
    {
        if (options is not DidEthrDeactivateOptions ethrOptions)
            throw new ArgumentException(
                $"Options must be {nameof(DidEthrDeactivateOptions)}.", nameof(options));

        var identifier = EthrIdentifier.Parse(did);
        var operations = new List<Erc1056Operation>
        {
            Erc1056TransactionBuilder.ChangeOwner(identifier.IdentityAddress, ZeroAddress),
        };

        using var deadlineCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadlineCts.CancelAfter(WriteDeadline);
        var token = deadlineCts.Token;

        var (transactionHashes, _) = await ExecuteOperationsAsync(
            identifier, ethrOptions.ControllerKey, ethrOptions.UseMetaTransaction,
            ethrOptions.Relayer, operations, ct, token);

        // Success is what the chain now says, not what we submitted. As in Update, a failure
        // in this post-batch read must still carry the transactions that already landed.
        DidResolutionResult resolved;
        try
        {
            token.ThrowIfCancellationRequested();
            resolved = await ResolveAsync(did, null, token).WaitAsyncObserved(token);
            token.ThrowIfCancellationRequested();
        }
        catch (OperationCanceledException ex) when (ct.IsCancellationRequested)
        {
            throw AttachTransactionEvidence(ex, transactionHashes);
        }
        catch (OperationCanceledException ex) when (deadlineCts.IsCancellationRequested)
        {
            throw AttachTransactionEvidence(CreateDeadlineException(
                ex, transactionHashes, [], operations.Count), transactionHashes);
        }
        catch (Exception ex)
        {
            throw AttachTransactionEvidence(ex, transactionHashes);
        }

        // ResolveAsync maps RPC/history failures to an internalError RESULT rather than throwing
        // (its documented never-throw contract), so the catch above does not see them.
        // Reporting Success = false for a confirmed on-chain write whose effect we simply
        // could not read is a false negative that invites an unnecessary — possibly unsafe —
        // retry. Only report false when the state was read and is known not deactivated.
        if (resolved.DidDocument is null || resolved.ResolutionMetadata.Error is not null)
            throw AttachTransactionEvidence(new EthereumInteractionException(
                $"did:ethr deactivation transactions landed " +
                $"[{string.Join(", ", transactionHashes)}] but the resulting state could not be " +
                $"read back: {resolved.ResolutionMetadata.Error ?? "no document"}. The " +
                "deactivation may well have taken effect — do not retry blindly."),
                transactionHashes);

        return new DidDeactivateResult
        {
            Success = resolved.DocumentMetadata?.Deactivated == true,
            Artifacts = new Dictionary<string, object>
            {
                ["transactions"] = (IReadOnlyList<string>)transactionHashes,
                ["registry"] = FindNetwork(identifier.Network).RegistryAddress,
            },
        };
    }

    /// <summary>
    /// Submits the prepared operations sequentially — directly, or as relayed ERC-1056
    /// meta-transactions — under one overall write deadline. Returns the landed
    /// transaction hashes and the controller's address.
    /// </summary>
    private async Task<(List<string> Hashes, string ControllerAddress)> ExecuteOperationsAsync(
        EthrIdentifier identifier,
        IRecoverableDigestSigner controllerKey,
        bool useMetaTransaction,
        IRecoverableDigestSigner? relayer,
        IReadOnlyList<Erc1056Operation> operations,
        CancellationToken callerCt,
        CancellationToken token)
    {
        var controllerAddress = TransactionPipeline.AddressOf(controllerKey, "ControllerKey");
        IRecoverableDigestSigner submitter;
        if (useMetaTransaction)
        {
            if (relayer is null)
                throw new ArgumentException(
                    "UseMetaTransaction requires a Relayer signer to pay for the wrapping transactions.",
                    "options");
            _ = TransactionPipeline.AddressOf(relayer, "Relayer");
            submitter = relayer;
        }
        else
        {
            submitter = controllerKey;
        }

        var network = FindNetwork(identifier.Network);
        var registry = network.RegistryAddress;
        var identity = identifier.IdentityAddress;
        var rpc = _rpcFactory.GetOrCreate(network);

        var hashes = new List<string>();
        var inFlightHashes = new List<string>();
        try
        {
            // For WRITES the chain id is a security parameter: it is the EIP-155 replay binding
            // baked into the signature. Letting an unconfigured network fall back to the node's
            // eth_chainId lets the endpoint choose what chain the caller's key authorizes — it
            // can answer "1" for a devnet and forward the resulting valid mainnet transaction.
            // Resolution may auto-detect (it only reads); writing must be told explicitly.
            if (network.ChainId is null)
                throw new ArgumentException(
                    $"Network '{network.Name}' has no configured ChainId. did:ethr writes require " +
                    "an explicit chain id: it is the EIP-155 replay binding in the signature, and " +
                    "auto-detecting it would let the RPC endpoint decide which chain your key " +
                    "signs for. Set EthereumNetworkConfig.ChainId (KnownNetworks entries already " +
                    "carry it).", nameof(EthereumNetworkConfig.ChainId));
            var chainId = await ResolveChainIdNumericAsync(network, rpc, token).WaitAsyncObserved(token);

            // Pre-flight (advisory; the contract's onlyOwner/checkSignature is the
            // enforcement point): fail before broadcasting anything if the controller key
            // is not the current identity owner.
            var currentOwner = ParseAddressWordResult(await rpc.CallAsync(
                registry, Erc1056Calls.IdentityOwner(identity), token).WaitAsyncObserved(token));
            if (!string.Equals(currentOwner, controllerAddress, StringComparison.OrdinalIgnoreCase))
                throw new EthereumInteractionException(
                    $"ControllerKey address {controllerAddress} is not the current owner " +
                    $"({currentOwner}) of identity {identity}; the registry would reject every operation.");

            // ERC-1056 v0.0.3 (the LegacyNonce generation — mainnet 0xdCa7EF03… and friends)
            // increments nonce[identity] in checkSignature, but the changeOwner / addDelegate /
            // revokeDelegate preimages READ nonce[identityOwner(identity)]. While owner ==
            // identity those are the same slot and replay protection works. Once ownership has
            // been transferred they diverge and the preimage nonce is a counter nothing ever
            // increments — the same signed calldata replays forever, letting anyone who observed
            // it resurrect a revoked delegate at will. Demonstrated against real v0.0.3 bytecode.
            //
            // Attribute operations are NOT affected: their preimages read nonce[identity], which
            // is the slot checkSignature increments, so they stay single-use. Refuse precisely the
            // vulnerable operations rather than all meta-transactions on these networks.
            if (useMetaTransaction && network.LegacyNonce
                && !string.Equals(currentOwner, identity, StringComparison.OrdinalIgnoreCase)
                && operations.FirstOrDefault(op => !op.UsesIdentityNonceOnLegacy) is { } vulnerable)
                throw new EthereumInteractionException(
                    $"Refusing to sign a '{vulnerable.MethodName}' meta-transaction for identity " +
                    $"{identity} on '{network.Name}': this network runs the legacy ERC-1056 " +
                    "registry, whose owner/delegate meta-transaction nonce is never incremented " +
                    $"once ownership has been transferred (current owner {currentOwner}). Any " +
                    "signature produced here would be replayable indefinitely by anyone who " +
                    "observes it. Submit this operation directly (UseMetaTransaction = false).");

            foreach (var operation in operations)
            {
                // Task.WaitAsync does not throw for an already-completed dependency Task when
                // cancellation raced with its completion. Never begin the next operation after
                // the caller or overall deadline has canceled the write.
                token.ThrowIfCancellationRequested();

                string calldata;
                if (useMetaTransaction)
                {
                    // Nonce key per contract generation: modern reads nonce[identityOwner]
                    // for every method; legacy reads nonce[identity] for attribute methods.
                    // The owner is stable throughout the batch (owner change is last).
                    var nonceKey = network.LegacyNonce && operation.UsesIdentityNonceOnLegacy
                        ? identity : currentOwner;
                    var metaNonce = ParseChangedResult(await rpc.CallAsync(
                        registry, Erc1056TransactionBuilder.NonceCalldata(nonceKey), token)
                        .WaitAsyncObserved(token));

                    var digest = Erc1056TransactionBuilder.MetaTransactionDigest(
                        registry, metaNonce, identity, operation);
                    var signature = await controllerKey.SignDigestAsync(digest, token)
                        .WaitAsyncObserved(token);

                    // The relayer is about to pay for this. TransactionPipeline verifies the
                    // OUTER relayer signature, but nothing verified this inner one: a signer
                    // that advertises the owner's public key while signing with another key
                    // passes the owner pre-flight and produces a guaranteed registry revert
                    // after the gas is spent. Recover it and require the controller.
                    var recoveredController = TransactionPipeline.RecoverSigner(
                        digest, signature.Signature64, signature.RecoveryId,
                        "The controller signature");
                    if (!string.Equals(recoveredController, controllerAddress, StringComparison.Ordinal))
                        throw new EthereumInteractionException(
                            $"The controller signature recovers to {recoveredController}, not to " +
                            $"the address its public key advertises ({controllerAddress}). " +
                            "Nothing was broadcast; the registry would have rejected it after " +
                            "the relayer paid gas.");
                    if (signature.RecoveryId is not (0 or 1))
                        throw new EthereumInteractionException(
                            "The controller signature's recovery id cannot be encoded as an " +
                            "ERC-1056 sigV value.");
                    calldata = operation.SignedCalldata(
                        (byte)(27 + signature.RecoveryId),
                        signature.Signature64[..32], signature.Signature64[32..]);
                }
                else
                {
                    calldata = operation.DirectCalldata;
                }

                EthereumTransactionReceipt receipt;
                var attemptEvidence = new TransactionAttemptEvidence();
                try
                {
                    receipt = await TransactionPipeline.SubmitAndConfirmAsync(
                        rpc, submitter, registry, Convert.FromHexString(calldata[2..]),
                        chainId, attemptEvidence,
                        maxGasPriceWei: network.MaxGasPriceWei,
                        maxTransactionFeeWei: network.MaxTransactionFeeWei,
                        ct: token);
                }
                catch
                {
                    // TransactionPipeline classifies the current transaction at the lifecycle
                    // boundary. A receipt-confirmed transaction belongs in the landed set even
                    // when it reverted; a hash with no observed receipt stays explicitly
                    // in-flight. Fold both BEFORE the outer catch filters run so operation 1
                    // cannot escape without the only hash a caller can query before retrying.
                    if (attemptEvidence.ConfirmedHash is { } confirmed)
                        RecordConfirmed(hashes, inFlightHashes, confirmed);
                    if (attemptEvidence.InFlightHash is { } inFlight)
                        RecordInFlight(hashes, inFlightHashes, inFlight);
                    throw;
                }
                RecordConfirmed(hashes, inFlightHashes, receipt.TransactionHash);
            }
        }
        catch (OperationCanceledException ex) when (callerCt.IsCancellationRequested)
        {
            // Caller cancellation keeps its type, but must still carry what landed:
            // silently discarding that evidence invites a double-applying retry.
            throw AttachTransactionEvidence(ex, hashes, inFlightHashes);
        }
        catch (OperationCanceledException ex) when (token.IsCancellationRequested)
        {
            throw AttachTransactionEvidence(
                CreateDeadlineException(ex, hashes, inFlightHashes, operations.Count),
                hashes, inFlightHashes);
        }
        catch (OperationCanceledException ex) when (hashes.Count > 0 || inFlightHashes.Count > 0)
        {
            // A dependency can abort with OperationCanceledException even when neither the
            // caller token nor our deadline fired. Preserve the real type/cause and evidence;
            // do not falsely report an internal timeout.
            throw AttachTransactionEvidence(ex, hashes, inFlightHashes);
        }
        catch (Exception ex) when (hashes.Count > 0)
        {
            // ANY mid-batch failure — a malformed RPC word (ArgumentException), a dropped
            // connection (HttpRequestException), anything — must report what already landed.
            // Catching only EthereumInteractionException here let those paths tell the caller
            // "nothing happened" while operations sat on-chain.
            throw AttachTransactionEvidence(new EthereumInteractionException(
                $"did:ethr update failed after confirming {hashes.Count} of {operations.Count} " +
                $"transactions [{string.Join(", ", hashes)}]. Transactions without an observed " +
                $"receipt may still confirm [{string.Join(", ", inFlightHashes)}]. " +
                $"Failure: {TrustedExceptionDetail(ex)}",
                ex), hashes, inFlightHashes);
        }
        catch (Exception ex) when (inFlightHashes.Count > 0)
        {
            // No receipt-confirmed transaction precedes the failure, so preserve the original
            // exception type. Still attach the candidate hash: a first-operation transport
            // failure is exactly where silently returning an empty landed set makes retries
            // unsafe.
            throw AttachTransactionEvidence(ex, hashes, inFlightHashes);
        }
        catch (Exception ex)
        {
            // These public keys are also guessable. A pre-flight dependency exception must not
            // be able to arrive at the API boundary carrying forged evidence merely because no
            // locally owned transaction state existed yet.
            throw SanitizeUntrustedTransactionEvidence(ex);
        }

        return (hashes, controllerAddress);
    }

    private static void RecordConfirmed(
        List<string> confirmedHashes, List<string> inFlightHashes, string hash)
    {
        inFlightHashes.RemoveAll(
            candidate => string.Equals(candidate, hash, StringComparison.Ordinal));
        if (!confirmedHashes.Contains(hash, StringComparer.Ordinal))
            confirmedHashes.Add(hash);
    }

    private static void RecordInFlight(
        IReadOnlyList<string> confirmedHashes, List<string> inFlightHashes, string hash)
    {
        if (!confirmedHashes.Contains(hash, StringComparer.Ordinal)
            && !inFlightHashes.Contains(hash, StringComparer.Ordinal))
            inFlightHashes.Add(hash);
    }

    private EthereumInteractionException CreateDeadlineException(
        Exception cause,
        IReadOnlyList<string> confirmedHashes,
        IReadOnlyList<string> inFlightHashes,
        int operationCount)
        => new(
            $"did:ethr write deadline ({WriteDeadline}) exceeded after confirming " +
            $"{confirmedHashes.Count} of {operationCount} transactions " +
            $"[{string.Join(", ", confirmedHashes)}]. Transactions without an observed receipt " +
            $"may still confirm [{string.Join(", ", inFlightHashes)}]; query those hashes " +
            "before retrying.",
            cause);

    /// <summary>
    /// Records receipt-confirmed and possibly-broadcast transactions separately, so callers
    /// can inspect chain state before retrying instead of parsing a message or treating mempool
    /// acceptance as confirmation.
    /// </summary>
    internal static Exception AttachTransactionEvidence(
        Exception exception,
        IReadOnlyList<string> confirmedHashes,
        IReadOnlyList<string>? inFlightHashes = null)
    {
        // Never write to dependency-owned Exception.Data. Exception.Data is virtual; an
        // injected client can return a throwing or read-only dictionary and otherwise destroy
        // the pipeline-owned evidence while we try to attach it. A fresh carrier has trusted,
        // writable Data and retains the original failure as InnerException.
        var carrier = CreateTrustedExceptionCarrier(exception);
        carrier.Data[LandedTransactionsKey] = confirmedHashes.ToArray();
        carrier.Data[InFlightTransactionsKey] = inFlightHashes?.ToArray() ?? [];
        return carrier;
    }

    internal static Exception SanitizeUntrustedTransactionEvidence(Exception exception)
        // A successful Remove is not proof: a virtual Data getter can return a different
        // dictionary on its next access. Cross the dependency boundary with a fresh carrier
        // whose metadata is known to be empty.
        => CreateTrustedExceptionCarrier(exception);

    private static Exception CreateTrustedExceptionCarrier(Exception cause)
        => cause switch
        {
            // TaskCanceledException is how HttpClient reports a TIMEOUT, so it is the most
            // common real failure on this path. Preserve the exact type: re-typing it to the
            // base class silently breaks `catch (TaskCanceledException)` for callers.
            TaskCanceledException canceled
                when canceled.GetType() == typeof(TaskCanceledException)
                => new TaskCanceledException(
                    SafeExceptionDetail(canceled), canceled, canceled.CancellationToken),
            OperationCanceledException canceled
                when canceled.GetType() == typeof(OperationCanceledException)
                => new OperationCanceledException(
                    canceled.Message, canceled, canceled.CancellationToken),
            OperationCanceledException canceled => new OperationCanceledException(
                SafeExceptionDetail(canceled), canceled),
            HttpRequestException http
                when http.GetType() == typeof(HttpRequestException)
                => new HttpRequestException(http.Message, http, http.StatusCode),
            HttpRequestException http => new HttpRequestException(
                SafeExceptionDetail(http), http),
            ArgumentException argument
                when argument.GetType() == typeof(ArgumentException)
                => new ArgumentException(argument.Message, argument.ParamName, argument),
            ArgumentException argument => new ArgumentException(
                SafeExceptionDetail(argument), argument),
            EthereumInteractionException interaction
                when interaction.GetType() == typeof(EthereumInteractionException)
                => new EthereumInteractionException(interaction.Message, interaction),
            EthereumInteractionException interaction => new EthereumInteractionException(
                SafeExceptionDetail(interaction), interaction),
            _ => new EthereumInteractionException(SafeExceptionDetail(cause), cause),
        };

    private static string TrustedExceptionDetail(Exception cause)
        // Exact library-owned interaction exceptions use Exception's normal Message
        // implementation; anything else goes through the sanitizer rather than being dropped.
        => cause.GetType() == typeof(EthereumInteractionException)
            ? cause.Message
            : SafeExceptionDetail(cause);

    /// <summary>Longest dependency-supplied detail we will embed in a message we produce.</summary>
    private const int MaxDependencyDetailLength = 400;

    /// <summary>
    /// Renders a dependency exception as diagnostic text that is safe to embed in a message we
    /// own. Discarding the detail outright made the common case — an <c>HttpClient</c> timeout,
    /// which arrives as a <see cref="TaskCanceledException"/> subclass — unreadable at the top
    /// level. The detail is still untrusted, so it is:
    /// <list type="bullet">
    ///   <item><description>read inside a guard, because <see cref="Exception.Message"/> is
    ///   virtual and a hostile override may throw;</description></item>
    ///   <item><description>stripped of control characters, so it cannot forge log lines
    ///   (CR/LF injection) in whatever consumes the message;</description></item>
    ///   <item><description>length-bounded, so an oversized message cannot bloat logs.</description></item>
    /// </list>
    /// It is diagnostic text only and is never treated as transaction evidence.
    /// </summary>
    private static string SafeExceptionDetail(Exception cause)
    {
        // Type identity cannot be overridden, so it is always safe and is the single most
        // useful thing to surface.
        var typeName = cause.GetType().Name;

        string? message;
        try
        {
            message = cause.Message;
        }
        catch
        {
            return $"{typeName} (message unavailable: the dependency's Message accessor threw).";
        }

        if (string.IsNullOrWhiteSpace(message))
            return $"{typeName} (no message supplied).";

        var sanitized = new string(
            message.Select(c => char.IsControl(c) ? ' ' : c).ToArray()).Trim();
        if (sanitized.Length > MaxDependencyDetailLength)
            sanitized = sanitized[..MaxDependencyDetailLength] + "…";

        return $"{typeName}: {sanitized}";
    }

    /// <summary>
    /// Key used once did:ethr transaction submission begins to record the <c>string[]</c> of
    /// hashes for which a matching receipt was observed on a failed Update, Deactivate, or
    /// <see cref="Deployment.Erc1056Registry.DeployAsync"/> call
    /// (<see cref="Exception.Data"/>). This includes reverted receipts: the operation did not
    /// apply, but the transaction is confirmed and consumed gas/account nonce. Validation and
    /// pre-flight failures before a transaction hash exists need not contain this key.
    /// </summary>
    public const string LandedTransactionsKey = "netdid.ethr.landedTransactions";

    /// <summary>
    /// Key used once did:ethr transaction submission begins to record the <c>string[]</c> of
    /// locally computed hashes that may have been broadcast but were not receipt-confirmed on
    /// a failed Update, Deactivate, or
    /// <see cref="Deployment.Erc1056Registry.DeployAsync"/> call. Callers must query these
    /// hashes before retrying; an immediate retry can double-apply an operation whose response
    /// or receipt was lost. Validation and pre-flight failures before a transaction hash exists
    /// need not contain this key.
    /// </summary>
    public const string InFlightTransactionsKey = "netdid.ethr.inFlightTransactions";

    /// <summary>
    /// A null ELEMENT inside an option collection is caller error, not a crash: without this
    /// it surfaced as a bare NullReferenceException (NFR-3 violation).
    /// </summary>
    private static T Required<T>(T? element, string collectionName) where T : class
        => element ?? throw new ArgumentException(
            $"{collectionName} contains a null entry.", "options");

    private static ulong ValiditySeconds(TimeSpan validity)
    {
        if (validity <= TimeSpan.Zero)
            throw new ArgumentException(
                "Validity must be positive — the registry would record an already-expired entry.",
                nameof(validity));
        return (ulong)validity.TotalSeconds;
    }

    /// <summary>
    /// Extracts the lowercase 0x address from a CAIP-10 <c>blockchainAccountId</c>
    /// (<c>eip155:&lt;chain&gt;:&lt;address&gt;</c>). Compared as a whole address rather than with a
    /// suffix match, which could report a false match on an unrelated trailing substring.
    /// </summary>
    private static string? ExtractAddress(string? blockchainAccountId)
    {
        if (blockchainAccountId is null)
            return null;
        var lastSeparator = blockchainAccountId.LastIndexOf(':');
        var address = lastSeparator >= 0
            ? blockchainAccountId[(lastSeparator + 1)..]
            : blockchainAccountId;
        return address.Length == 42 && address.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
            ? address.ToLowerInvariant()
            : null;
    }

    /// <summary>Parses an eth_call result carrying one ABI address word.</summary>
    private static string ParseAddressWordResult(string result)
    {
        var word = ParseChangedResultBytes(result);
        for (var i = 0; i < 12; i++)
        {
            if (word[i] != 0)
                throw new EthereumInteractionException(
                    "eth_call returned a word that is not a zero-padded address.");
        }
        return "0x" + Convert.ToHexString(word[12..]).ToLowerInvariant();
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

    private static async Task<ulong> ResolveChainIdNumericAsync(
        EthereumNetworkConfig network, IEthereumRpcClient rpc, CancellationToken ct)
    {
        if (network.ChainId is not null)
        {
            var hex = network.ChainId.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
                ? network.ChainId[2..] : network.ChainId;
            return Convert.ToUInt64(hex, 16);
        }
        return await rpc.GetChainIdAsync(ct).WaitAsyncObserved(ct);
    }

    private static async Task<string> ResolveChainId(
        EthereumNetworkConfig network, IEthereumRpcClient rpc, CancellationToken ct)
        => (await ResolveChainIdNumericAsync(network, rpc, ct))
            .ToString(CultureInfo.InvariantCulture);

    private static bool TryParseResolutionOptions(
        DidResolutionOptions? options,
        out ulong? versionBlockNumber,
        out DateTimeOffset? versionTime)
    {
        versionBlockNumber = null;
        versionTime = null;

        if (options is null)
            return true;

        if (options.VersionId is not null && options.VersionTime is not null)
            return false;

        if (options.VersionId is { } versionId)
        {
            if (!ulong.TryParse(
                    versionId, NumberStyles.None, CultureInfo.InvariantCulture,
                    out var parsedBlock)
                || !string.Equals(
                    versionId, parsedBlock.ToString(CultureInfo.InvariantCulture),
                    StringComparison.Ordinal))
                return false;

            versionBlockNumber = parsedBlock;
        }

        if (options.VersionTime is { } versionTimeText)
        {
            if (!DateTimeOffset.TryParseExact(
                    versionTimeText,
                    "yyyy-MM-dd'T'HH:mm:ss'Z'",
                    CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                    out var parsedTime))
                return false;

            versionTime = parsedTime;
        }

        return true;
    }

    private static ulong ParseChangedResult(string result)
        => AbiDecoder.DecodeUint256(ParseChangedResultBytes(result));

    /// <summary>Validates an eth_call result as exactly one canonical ABI word and returns its bytes.</summary>
    private static byte[] ParseChangedResultBytes(string result)
    {
        if (!result.StartsWith("0x", StringComparison.Ordinal)
            || result.Length != 66)
            throw new ArgumentException(
                "ERC-1056 read calls must return exactly one 0x-prefixed ABI word.",
                nameof(result));
        foreach (var c in result.AsSpan(2))
        {
            if (!char.IsAsciiDigit(c) && c is not (>= 'a' and <= 'f'))
                throw new ArgumentException(
                    "ERC-1056 read calls must return canonical lowercase hex data.",
                    nameof(result));
        }

        try
        {
            return Convert.FromHexString(result[2..]);
        }
        catch (FormatException ex)
        {
            throw new ArgumentException(
                "ERC-1056 read call returned malformed hex data.",
                nameof(result), ex);
        }
    }
}
