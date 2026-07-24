using FluentAssertions;
using NetCrypto;
using NetDid.Method.Ethr.Erc1056;
using NetDid.Method.Ethr.Rpc;
using NSubstitute;
using Xunit;

namespace NetDid.Method.Ethr.Tests;

/// <summary>
/// Adversarial regression tests: the RPC node is UNTRUSTED. Resolution must never
/// throw out of ResolveAsync (contract: return resolutionMetadata.error) and must
/// not let a hostile node drive unbounded work. Findings from the PR #70 adoption
/// adversarial review (2026-07-24).
/// </summary>
public class DidEthrResolverHardeningTests
{
    private const string Identity = "0x001d3f1ef827552ae1114027bd3ecf1f086ba0f9";
    private const string Registry = "0xdCa7EF03e98e0DC2B855bE647C39ABe984fcF21B";

    private static readonly EthereumNetworkConfig SepoliaConfig = new()
    {
        Name            = "sepolia",
        RpcUrl          = "https://rpc.sepolia.example",
        ChainId         = "0xaa36a7",
        RegistryAddress = Registry,
    };

    private static DidEthrMethod MakeMethod(IEthereumRpcClient rpc)
    {
        var factory = Substitute.For<IEthereumRpcClientFactory>();
        factory.GetOrCreate(Arg.Any<EthereumNetworkConfig>()).Returns(rpc);
        return new DidEthrMethod(factory, [SepoliaConfig], new DefaultKeyGenerator());
    }

    // ── Finding 1 (CRITICAL): unbounded event-chain walk ────────────────────────

    [Fact]
    public async Task ResolveAsync_HostileDescendingChain_AbortsBounded_ReturnsNotFound()
    {
        // A hostile node points every block's previousChange one block lower, so the
        // walker would issue one eth_getLogs per block down to 0. Starting height is
        // set far above the internal hop cap; resolution must abort (notFound) after a
        // BOUNDED number of round-trips, not walk all 200_000 blocks.
        const ulong startBlock = 200_000;
        var getLogsCalls = 0;

        var rpc = Substitute.For<IEthereumRpcClient>();
        rpc.CallAsync(default!, default!, default)
           .ReturnsForAnyArgs("0x" + startBlock.ToString("x64"));
        rpc.GetLogsAsync(Arg.Any<EthereumLogFilter>(), Arg.Any<CancellationToken>())
           .Returns(call =>
           {
               getLogsCalls++;
               var block = call.Arg<EthereumLogFilter>().FromBlock;
               // previousChange = block - 1  → an ever-descending chain
               return Task.FromResult(OwnerChangedLog(Identity, Identity, block, prev: block - 1));
           });

        var result = await MakeMethod(rpc).ResolveAsync($"did:ethr:sepolia:{Identity}");

        result.ResolutionMetadata.Error.Should().Be("notFound");
        getLogsCalls.Should().BeLessThanOrEqualTo(10_001,
            "the walker must stop at the hop cap, not traverse all 200_000 blocks");
    }

    [Fact]
    public async Task ResolveAsync_SingleBlockEventFlood_AbortsReturnsNotFound()
    {
        // A single block packed with more matching logs than the event cap → the
        // accumulator would grow without bound. Resolution must abort to notFound.
        const ulong block = 1;
        var flood = new List<EthereumLogEntry>(50_001);
        for (var i = 0; i < 50_001; i++)
            flood.Add(OwnerChangedLog(Identity, Identity, block, prev: 0)[0]);

        var rpc = Substitute.For<IEthereumRpcClient>();
        rpc.CallAsync(default!, default!, default)
           .ReturnsForAnyArgs("0x" + block.ToString("x64"));
        rpc.GetLogsAsync(default!, default)
           .ReturnsForAnyArgs(Task.FromResult<IReadOnlyList<EthereumLogEntry>>(flood));

        var result = await MakeMethod(rpc).ResolveAsync($"did:ethr:sepolia:{Identity}");

        result.ResolutionMetadata.Error.Should().Be("notFound");
    }

    // ── Finding 2: non-hex / overflowing wire fields escape as exceptions ────────

    [Theory]
    [InlineData("0xZZZZ")]                                   // FormatException
    [InlineData("0xfffffffffffffffffff")]                    // 19 f's → OverflowException (> ulong)
    [InlineData("not-even-hex")]
    [InlineData("")]                                          // ParseHexUlong tolerates "", but exercise it
    public async Task ResolveAsync_MalformedChangedResult_ReturnsNotFound(string changedResult)
    {
        var rpc = Substitute.For<IEthereumRpcClient>();
        rpc.CallAsync(default!, default!, default).ReturnsForAnyArgs(changedResult);

        var result = await MakeMethod(rpc).ResolveAsync($"did:ethr:sepolia:{Identity}");

        // Either notFound (threw and was mapped) or a clean empty resolution ("" → 0
        // blocks). Never an escaped exception, and never a null-error-with-throw.
        result.ResolutionMetadata.Error.Should().BeOneOf("notFound", null);
    }

    // ── Finding 3 (simulated): RPC client shape-exception escapes the walker ─────

    [Fact]
    public async Task ResolveAsync_RpcClientThrowsInvalidOperation_ReturnsNotFound()
    {
        // Simulates DefaultEthereumRpcClient hitting a malformed eth_getLogs JSON
        // shape (InvalidOperationException / NullReferenceException) — the type the
        // walker's per-log `catch (ArgumentException)` does NOT catch. Must map to notFound.
        var rpc = Substitute.For<IEthereumRpcClient>();
        rpc.CallAsync(default!, default!, default)
           .ReturnsForAnyArgs("0x" + (5UL).ToString("x64"));
        rpc.GetLogsAsync(default!, default)
           .ReturnsForAnyArgs<Task<IReadOnlyList<EthereumLogEntry>>>(
               _ => throw new InvalidOperationException("malformed JSON shape"));

        var result = await MakeMethod(rpc).ResolveAsync($"did:ethr:sepolia:{Identity}");

        result.ResolutionMetadata.Error.Should().Be("notFound");
    }

    // ── Finding 5: builder throws on decodable-but-hostile event ─────────────────

    [Fact]
    public async Task ResolveAsync_ServiceEventWithEmptyEndpoint_ReturnsNotFound()
    {
        // A did/svc attribute that ABI-decodes cleanly but carries an EMPTY endpoint
        // makes EthrDocumentBuilder → ServiceEndpointValue.FromUri throw ArgumentException.
        // That escaped ResolveCoreAsync before the fix.
        const ulong block = 5;
        var log = ServiceAttributeLog(Identity, "did/svc/AgentService", value: [], validTo: 0xffffffff, block);

        var rpc = Substitute.For<IEthereumRpcClient>();
        rpc.CallAsync(default!, default!, default)
           .ReturnsForAnyArgs("0x" + block.ToString("x64"));
        rpc.GetLogsAsync(default!, default).ReturnsForAnyArgs(call =>
        {
            var f = call.Arg<EthereumLogFilter>();
            return Task.FromResult<IReadOnlyList<EthereumLogEntry>>(
                f.FromBlock == block ? [log] : []);
        });

        var result = await MakeMethod(rpc).ResolveAsync($"did:ethr:sepolia:{Identity}");

        result.ResolutionMetadata.Error.Should().Be("notFound");
    }

    // ── Sanity: a well-formed hostile-shaped-but-valid resolve still succeeds ─────

    [Fact]
    public async Task ResolveAsync_ShortValidChain_StillSucceeds()
    {
        // Guard against the caps/try-catch over-rejecting: a normal 2-hop chain resolves.
        const ulong head = 10, prevBlock = 4;

        var rpc = Substitute.For<IEthereumRpcClient>();
        rpc.CallAsync(default!, default!, default).ReturnsForAnyArgs("0x" + head.ToString("x64"));
        rpc.GetLogsAsync(default!, default).ReturnsForAnyArgs(call =>
        {
            var b = call.Arg<EthereumLogFilter>().FromBlock;
            if (b == head)      return Task.FromResult(OwnerChangedLog(Identity, Identity, head, prev: prevBlock));
            if (b == prevBlock) return Task.FromResult(OwnerChangedLog(Identity, Identity, prevBlock, prev: 0));
            return Task.FromResult<IReadOnlyList<EthereumLogEntry>>([]);
        });

        var result = await MakeMethod(rpc).ResolveAsync($"did:ethr:sepolia:{Identity}");

        result.ResolutionMetadata.Error.Should().BeNull();
        result.DidDocument.Should().NotBeNull();
    }

    // ── Fixtures ─────────────────────────────────────────────────────────────────

    private static IReadOnlyList<EthereumLogEntry> OwnerChangedLog(
        string identity, string newOwner, ulong block, ulong prev)
    {
        var ownerHex = newOwner.StartsWith("0x") ? newOwner[2..] : newOwner;
        var data = "0x"
            + "000000000000000000000000" + ownerHex   // owner (address, 32-byte word)
            + prev.ToString("x64");                    // previousChange (uint256)
        return [new EthereumLogEntry
        {
            Address     = Registry,
            Topics      = [Erc1056Topics.DIDOwnerChanged, PadAddress(identity)],
            Data        = data,
            BlockNumber = "0x" + block.ToString("x"),
        }];
    }

    private static EthereumLogEntry ServiceAttributeLog(
        string identity, string name, byte[] value, ulong validTo, ulong block)
    {
        // DIDAttributeChanged data layout:
        //   name(32) | valueOffset(32) | validTo(32) | previousChange(32)
        //   | valueLength(32) | valueBytes(padded to 32)
        var nameWord = new byte[32];
        System.Text.Encoding.ASCII.GetBytes(name).CopyTo(nameWord, 0);

        var data = "0x"
            + Convert.ToHexString(nameWord).ToLowerInvariant()
            + (128UL).ToString("x64")     // valueOffset → byte 128 (the length word)
            + validTo.ToString("x64")
            + (0UL).ToString("x64")       // previousChange
            + ((ulong)value.Length).ToString("x64");
        if (value.Length > 0)
        {
            var padded = new byte[(value.Length + 31) / 32 * 32];
            value.CopyTo(padded, 0);
            data += Convert.ToHexString(padded).ToLowerInvariant();
        }

        return new EthereumLogEntry
        {
            Address     = Registry,
            Topics      = [Erc1056Topics.DIDAttributeChanged, PadAddress(identity)],
            Data        = data,
            BlockNumber = "0x" + block.ToString("x"),
        };
    }

    private static string PadAddress(string addr)
    {
        var hex = addr.StartsWith("0x") ? addr[2..] : addr;
        return "0x" + hex.PadLeft(64, '0');
    }
}
