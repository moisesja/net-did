using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using NetDid.Core;
using NetDid.Core.Crypto;
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

        var network = FindNetwork(identifier.Network);
        var rpc     = _rpcFactory.GetOrCreate(network);
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
            DidDocument      = doc,
            ResolutionMetadata = new DidResolutionMetadata(),
            DocumentMetadata = meta,
        };
    }

    // ── Event chain walker ────────────────────────────────────────────────────

    private async Task WalkEventChainAsync(
        IEthereumRpcClient rpc,
        string registryAddress, string identityAddress,
        ulong fromBlock, List<Erc1056Event> accumulator, CancellationToken ct)
    {
        var currentBlock = fromBlock;
        while (currentBlock > 0)
        {
            var filter = new EthereumLogFilter
            {
                Address   = registryAddress,
                FromBlock = currentBlock,
                ToBlock   = currentBlock,
                Topics    = [[
                    Erc1056Topics.DIDOwnerChanged,
                    Erc1056Topics.DIDDelegateChanged,
                    Erc1056Topics.DIDAttributeChanged,
                ]],
            };

            var logs = await rpc.GetLogsAsync(filter, ct);
            ulong previousChange = 0;

            foreach (var log in logs)
            {
                try
                {
                    var ev = Erc1056EventParser.Parse(log);
                    if (!string.Equals(ev.Identity, identityAddress,
                            StringComparison.OrdinalIgnoreCase))
                        continue;
                    accumulator.Add(ev);
                    if (ev.PreviousChange > previousChange)
                        previousChange = ev.PreviousChange;
                }
                catch (ArgumentException ex)
                {
                    _logger.LogWarning(ex, "Skipping unparseable ERC-1056 log at block {Block}", currentBlock);
                }
            }

            currentBlock = previousChange;
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
