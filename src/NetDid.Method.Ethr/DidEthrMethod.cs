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
            _logger.LogWarning(ex, "Failed to parse did:ethr identifier: {Did}", did);
            return DidResolutionResult.InvalidDid(did);
        }

        if (!TryParseResolutionOptions(
                options, out var versionBlockNumber, out var versionTime))
            return DidResolutionResult.InvalidOptions(did);

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
            return await ResolveFromChainAsync(
                did, identifier, network, rpc, versionBlockNumber, versionTime,
                deadlineCts.Token);
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
        IEthereumRpcClient rpc, ulong? versionBlockNumber,
        DateTimeOffset? versionTime, CancellationToken ct)
    {
        var chainId = await ResolveChainId(network, rpc, ct);

        // changed(identity) → first block that has a relevant event
        var changedHex    = Erc1056Calls.Changed(identifier.IdentityAddress);
        var changedResult = await rpc.CallAsync(network.RegistryAddress, changedHex, ct);
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
            var ts = await rpc.GetBlockTimestampAsync(version, ct);
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
                var bts = await rpc.GetBlockTimestampAsync(blockEvents.Key, ct);
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

            var logs = (await rpc.GetLogsAsync(filter, ct))?.ToList()
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
                throw new EthereumInteractionException(
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
    /// Internal so tests can shorten it; when it fires, the failure reports which
    /// operations landed — a broadcast transaction may still confirm afterwards.
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

        var (transactionHashes, controllerAddress) = await ExecuteOperationsAsync(
            identifier, ethrOptions.ControllerKey, ethrOptions.UseMetaTransaction,
            ethrOptions.Relayer, operations, ct);

        // EVERYTHING past this point runs with operations already on-chain, so every failure
        // here must still carry the landed set — a post-loop throw that reported nothing was
        // how the first evidence fix stayed reachable (it only guarded the submission loop).
        try
        {
            return await BuildUpdateResultAsync(
                did, identifier, transactionHashes, controllerAddress, newOwner, ct);
        }
        catch (Exception ex)
        {
            throw AttachLandedTransactions(ex, transactionHashes);
        }
    }

    private async Task<DidUpdateResult> BuildUpdateResultAsync(
        string did, EthrIdentifier identifier, List<string> transactionHashes,
        string controllerAddress, string? newOwner, CancellationToken ct)
    {
        var identity = identifier.IdentityAddress;
        var resolved = await ResolveAsync(did, null, ct);
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
                network.RegistryAddress, Erc1056Calls.IdentityOwner(identity), ct));

        // That eth_call and the event log both come from the same untrusted node, so trusting
        // it alone just swaps one unauthenticated oracle for another. The document the
        // resolver just replayed already knows the controller; require the two to agree, so a
        // node must forge BOTH consistently rather than one cheap call.
        var documentController = resolved.DidDocument.VerificationMethod?
            .FirstOrDefault(vm => vm.Id.EndsWith("#controller", StringComparison.Ordinal))?
            .BlockchainAccountId;
        if (documentController is not null
            && !documentController.EndsWith(effectiveOwner[2..], StringComparison.OrdinalIgnoreCase))
            throw new EthereumInteractionException(
                $"did:ethr update transactions landed [{string.Join(", ", transactionHashes)}] " +
                $"but the registry reports owner {effectiveOwner} while the replayed event " +
                $"history yields controller '{documentController}'. Refusing to report " +
                "contradictory update-authority evidence.");

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

        var (transactionHashes, _) = await ExecuteOperationsAsync(
            identifier, ethrOptions.ControllerKey, ethrOptions.UseMetaTransaction,
            ethrOptions.Relayer, operations, ct);

        // Success is what the chain now says, not what we submitted. As in Update, a failure
        // in this post-batch read must still carry the transactions that already landed.
        DidResolutionResult resolved;
        try
        {
            resolved = await ResolveAsync(did, null, ct);
        }
        catch (Exception ex)
        {
            throw AttachLandedTransactions(ex, transactionHashes);
        }
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
        CancellationToken callerCt)
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
        var chainId = await ResolveChainIdNumericAsync(network, rpc, callerCt);

        // Pre-flight (advisory; the contract's onlyOwner/checkSignature is the
        // enforcement point): fail before broadcasting anything if the controller key
        // is not the current identity owner.
        var currentOwner = ParseAddressWordResult(await rpc.CallAsync(
            registry, Erc1056Calls.IdentityOwner(identity), callerCt));
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

        using var deadlineCts = CancellationTokenSource.CreateLinkedTokenSource(callerCt);
        deadlineCts.CancelAfter(WriteDeadline);
        var token = deadlineCts.Token;

        var hashes = new List<string>();
        try
        {
            foreach (var operation in operations)
            {
                string calldata;
                if (useMetaTransaction)
                {
                    // Nonce key per contract generation: modern reads nonce[identityOwner]
                    // for every method; legacy reads nonce[identity] for attribute methods.
                    // The owner is stable throughout the batch (owner change is last).
                    var nonceKey = network.LegacyNonce && operation.UsesIdentityNonceOnLegacy
                        ? identity : currentOwner;
                    var metaNonce = ParseChangedResult(await rpc.CallAsync(
                        registry, Erc1056TransactionBuilder.NonceCalldata(nonceKey), token));

                    var digest = Erc1056TransactionBuilder.MetaTransactionDigest(
                        registry, metaNonce, identity, operation);
                    var signature = await controllerKey.SignDigestAsync(digest, token);
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

                var receipt = await TransactionPipeline.SubmitAndConfirmAsync(
                    rpc, submitter, registry, Convert.FromHexString(calldata[2..]),
                    chainId, maxGasPriceWei: network.MaxGasPriceWei, ct: token);
                hashes.Add(receipt.TransactionHash);
            }
        }
        catch (OperationCanceledException ex) when (callerCt.IsCancellationRequested)
        {
            // Caller cancellation keeps its type, but must still carry what landed:
            // silently discarding that evidence invites a double-applying retry.
            throw AttachLandedTransactions(ex, hashes);
        }
        catch (OperationCanceledException ex)
        {
            throw AttachLandedTransactions(new EthereumInteractionException(
                $"did:ethr write deadline ({WriteDeadline}) exceeded after landing " +
                $"{hashes.Count} of {operations.Count} operations " +
                $"[{string.Join(", ", hashes)}]; a broadcast transaction may still confirm later.",
                ex), hashes);
        }
        catch (Exception ex) when (hashes.Count > 0)
        {
            // ANY mid-batch failure — a malformed RPC word (ArgumentException), a dropped
            // connection (HttpRequestException), anything — must report what already landed.
            // Catching only EthereumInteractionException here let those paths tell the caller
            // "nothing happened" while operations sat on-chain.
            throw AttachLandedTransactions(new EthereumInteractionException(
                $"did:ethr update failed after landing {hashes.Count} of {operations.Count} " +
                $"operations [{string.Join(", ", hashes)}]: {ex.Message}", ex), hashes);
        }

        return (hashes, controllerAddress);
    }

    /// <summary>
    /// Records the transactions that already landed on the exception, so a caller can read
    /// them structurally instead of parsing the message.
    /// </summary>
    private static T AttachLandedTransactions<T>(T exception, IReadOnlyList<string> hashes)
        where T : Exception
    {
        exception.Data[LandedTransactionsKey] = hashes.ToArray();
        return exception;
    }

    /// <summary>
    /// Key under which a failed Update/Deactivate records the <c>string[]</c> of transaction
    /// hashes that were already confirmed on-chain (<see cref="Exception.Data"/>).
    /// </summary>
    public const string LandedTransactionsKey = "netdid.ethr.landedTransactions";

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
        return await rpc.GetChainIdAsync(ct);
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
