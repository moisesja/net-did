using FluentAssertions;
using NetCrypto;
using NetDid.Method.Ethr.Erc1056;
using NetDid.Method.Ethr.Rpc;
using NSubstitute;
using Xunit;

namespace NetDid.Method.Ethr.Tests;

/// <summary>
/// End-to-end (through ResolveAsync + the walker + replay) regression tests for the
/// authorization/history correctness defects found in PR #104 review:
/// same-block ordering, fail-closed on incomplete history, and historical resolution.
/// </summary>
public class DidEthrResolveCorrectnessTests
{
    private const string Identity = "0x001d3f1ef827552ae1114027bd3ecf1f086ba0f9";
    private const string Registry = "0xdCa7EF03e98e0DC2B855bE647C39ABe984fcF21B";
    private const string DelegateAddr = "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed";
    private const string OwnerA = "0xdbf03b407c01e7cd3cbea99509d93f8dddc8c6fb";
    private const string OwnerB = "0x2036c6cd85692f0fb2c26e6c6b2eced9e4478dfd";
    private const string OwnerC = "0x1234567890abcdef1234567890abcdef12345678";

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

    private static IEthereumRpcClient RpcWith(ulong changedBlock,
        Func<ulong, IReadOnlyList<EthereumLogEntry>> logsByBlock)
    {
        var rpc = Substitute.For<IEthereumRpcClient>();
        rpc.CallAsync(default!, default!, default)
           .ReturnsForAnyArgs("0x" + changedBlock.ToString("x64"));
        rpc.GetLogsAsync(default!, default).ReturnsForAnyArgs(call =>
            Task.FromResult(logsByBlock(call.Arg<EthereumLogFilter>().FromBlock)));
        rpc.GetBlockTimestampAsync(default, default).ReturnsForAnyArgs(1_700_000_000UL);
        return rpc;
    }

    // ── #1 Same-block add→revoke must NOT leave the key live ─────────────────────

    [Fact]
    public async Task ResolveAsync_SameBlockAddThenRevokeSameDelegate_KeyIsAbsent()
    {
        // Block 50 carries, in canonical (ascending) log order: add X, then revoke X.
        // A flat List.Reverse() would replay them as revoke→add and leave X live.
        const ulong block = 50;
        var future = (ulong)(DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 3600);
        var rpc = RpcWith(block, b => b == block
            ? new[]
              {
                  DelegateLog(Identity, DelegateAddr, "veriKey", validTo: future, prev: 0,     block),  // add
                  DelegateLog(Identity, DelegateAddr, "veriKey", validTo: 1,      prev: block, block),  // revoke
              }
            : []);

        var result = await MakeMethod(rpc).ResolveAsync($"did:ethr:sepolia:{Identity}");

        result.ResolutionMetadata.Error.Should().BeNull();
        // Only #controller survives — the same-block-revoked delegate must be gone.
        result.DidDocument!.VerificationMethod.Should().ContainSingle()
            .Which.Id.Should().EndWith("#controller");
        result.DidDocument.AssertionMethod
            .Should().NotContain(e => e.Reference != null && e.Reference.Contains("#delegate"));
    }

    [Fact]
    public async Task ResolveAsync_SameBlockRevokeThenReAdd_KeyIsPresent()
    {
        // Ordering guard the other way: revoke (of nothing) then add → key present.
        const ulong block = 60;
        var future = (ulong)(DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 3600);
        var rpc = RpcWith(block, b => b == block
            ? new[]
              {
                  DelegateLog(Identity, DelegateAddr, "veriKey", validTo: 1,      prev: 0,     block),  // revoke (no-op)
                  DelegateLog(Identity, DelegateAddr, "veriKey", validTo: future, prev: block, block),  // add
              }
            : []);

        var result = await MakeMethod(rpc).ResolveAsync($"did:ethr:sepolia:{Identity}");

        result.ResolutionMetadata.Error.Should().BeNull();
        result.DidDocument!.AssertionMethod
            .Should().Contain(e => e.Reference != null && e.Reference.Contains("#delegate-2"));
    }

    [Fact]
    public async Task ResolveAsync_SameBlockResponseOutOfOrder_LogIndexRestoresChainOrder()
    {
        // The node returns the two same-block events in REVERSE array order (revoke first),
        // but with correct logIndex. Sorting by logIndex must still apply add→revoke, so the
        // key is absent — proving we don't trust the response array order.
        const ulong block = 70;
        var future = (ulong)(DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 3600);
        var rpc = RpcWith(block, b => b == block
            ? new[]
              {
                  DelegateLog(Identity, DelegateAddr, "veriKey", validTo: 1,      prev: block, block, logIndex: 1), // revoke (idx 1)
                  DelegateLog(Identity, DelegateAddr, "veriKey", validTo: future, prev: 0,     block, logIndex: 0), // add (idx 0)
              }
            : []);

        var result = await MakeMethod(rpc).ResolveAsync($"did:ethr:sepolia:{Identity}");

        result.ResolutionMetadata.Error.Should().BeNull();
        result.DidDocument!.VerificationMethod.Should().ContainSingle()
            .Which.Id.Should().EndWith("#controller");
    }

    // ── #2 Incomplete history must fail CLOSED (notFound) ────────────────────────

    [Fact]
    public async Task ResolveAsync_PointerBlockEmpty_ReturnsNotFound()
    {
        // changed()=N>0 asserts an event at N; an empty result (pruned/non-archive node)
        // must not silently produce a genesis document.
        var rpc = RpcWith(77, _ => []);

        var result = await MakeMethod(rpc).ResolveAsync($"did:ethr:sepolia:{Identity}");

        result.ResolutionMetadata.Error.Should().Be("notFound");
    }

    [Fact]
    public async Task ResolveAsync_PointerBlockOnlyMalformedLog_ReturnsNotFound()
    {
        // A hostile node returns a garbage-topic log at the pointer block to erase the
        // real (e.g. revoke/owner-change) event. Skipped-as-unparseable → zero valid
        // events at an asserted block → fail closed.
        const ulong block = 88;
        var rpc = RpcWith(block, b => b == block ? new[] { GarbageTopicLog(Identity, block) } : []);

        var result = await MakeMethod(rpc).ResolveAsync($"did:ethr:sepolia:{Identity}");

        result.ResolutionMetadata.Error.Should().Be("notFound");
    }

    // ── #3 Historical resolution: partition at the requested block ───────────────

    [Fact]
    public async Task ResolveAsync_VersionIdBetweenChanges_ReturnsEarlierState()
    {
        // Owner changes at blocks 10 (→A) and 20 (→B). versionId=15 must return the
        // block-10 state (owner A), with versionId=10 and nextVersionId=20.
        var rpc = OwnerHistory((10, OwnerA, 0), (20, OwnerB, 10));
        var opts = new DidEthrResolveOptions { VersionId = "15" };

        var result = await MakeMethod(rpc).ResolveAsync($"did:ethr:sepolia:{Identity}", opts);

        result.ResolutionMetadata.Error.Should().BeNull();
        Controller(result).Should().Contain(OwnerA[2..], "the block-10 owner applies at version 15")
            .And.NotContainEquivalentOf(OwnerB[2..]);
        result.DocumentMetadata!.VersionId.Should().Be("10");        // last APPLIED change, not requested 15
        result.DocumentMetadata.NextVersionId.Should().Be("20");     // adjacent next change
    }

    [Fact]
    public async Task ResolveAsync_VersionIdBetweenThreeChanges_NextVersionIdIsAdjacentNotLatest()
    {
        // Changes at 10/20/30. versionId=15 → nextVersionId must be 20 (adjacent), not 30 (latest).
        var rpc = OwnerHistory((10, OwnerA, 0), (20, OwnerB, 10), (30, OwnerC, 20));
        var opts = new DidEthrResolveOptions { VersionId = "15" };

        var result = await MakeMethod(rpc).ResolveAsync($"did:ethr:sepolia:{Identity}", opts);

        result.ResolutionMetadata.Error.Should().BeNull();
        result.DocumentMetadata!.NextVersionId.Should().Be("20");
        result.DocumentMetadata.VersionId.Should().Be("10");
    }

    [Fact]
    public async Task ResolveAsync_VersionIdZero_ReturnsGenesis_NextVersionIdIsFirstBlock()
    {
        // versionId=0 → genesis (state before any event): only #controller with the
        // original identity as owner, nextVersionId = the FIRST event block.
        var rpc = OwnerHistory((10, OwnerA, 0), (20, OwnerB, 10));
        var opts = new DidEthrResolveOptions { VersionId = "0" };

        var result = await MakeMethod(rpc).ResolveAsync($"did:ethr:sepolia:{Identity}", opts);

        result.ResolutionMetadata.Error.Should().BeNull();
        result.DidDocument!.VerificationMethod.Should().ContainSingle()
            .Which.Id.Should().EndWith("#controller");
        Controller(result).Should().Contain(Identity[2..], "genesis owner is the identity itself");
        result.DocumentMetadata!.NextVersionId.Should().Be("10");
        result.DocumentMetadata.VersionId.Should().BeNull();         // no change applied at genesis
    }

    [Fact]
    public async Task ResolveAsync_NoVersion_ReturnsLatestState()
    {
        // Sanity: without a version, the latest owner (B) applies. Guards against the
        // full-history-walk change over-trimming.
        var rpc = OwnerHistory((10, OwnerA, 0), (20, OwnerB, 10));

        var result = await MakeMethod(rpc).ResolveAsync($"did:ethr:sepolia:{Identity}");

        result.ResolutionMetadata.Error.Should().BeNull();
        Controller(result).Should().Contain(OwnerB[2..]);
        result.DocumentMetadata!.VersionId.Should().Be("20");
    }

    // ── Fixtures ─────────────────────────────────────────────────────────────────

    private static string Controller(NetDid.Core.Model.DidResolutionResult r)
        => r.DidDocument!.VerificationMethod!
            .Single(v => v.Id.EndsWith("#controller")).BlockchainAccountId!.ToLowerInvariant();

    private IEthereumRpcClient OwnerHistory(params (ulong Block, string Owner, ulong Prev)[] changes)
    {
        var latest = changes.Max(c => c.Block);
        return RpcWith(latest, b =>
        {
            var match = changes.FirstOrDefault(c => c.Block == b);
            return match.Block == b && match.Owner != null
                ? new[] { OwnerChangedLog(Identity, match.Owner, b, match.Prev) }
                : [];
        });
    }

    private static EthereumLogEntry OwnerChangedLog(string identity, string newOwner, ulong block, ulong prev)
    {
        var ownerHex = newOwner.StartsWith("0x") ? newOwner[2..] : newOwner;
        var data = "0x" + "000000000000000000000000" + ownerHex + prev.ToString("x64");
        return new EthereumLogEntry
        {
            Address = Registry,
            Topics = [Erc1056Topics.DIDOwnerChanged, PadAddress(identity)],
            Data = data,
            BlockNumber = "0x" + block.ToString("x"),
        };
    }

    private static EthereumLogEntry DelegateLog(
        string identity, string delegate20, string delegateType,
        ulong validTo, ulong prev, ulong block, ulong logIndex = 0)
    {
        var delHex = delegate20.StartsWith("0x") ? delegate20[2..] : delegate20;
        var typeWord = new byte[32];
        System.Text.Encoding.ASCII.GetBytes(delegateType).CopyTo(typeWord, 0);
        var data = "0x"
            + Convert.ToHexString(typeWord).ToLowerInvariant()
            + "000000000000000000000000" + delHex
            + validTo.ToString("x64")
            + prev.ToString("x64");
        return new EthereumLogEntry
        {
            Address = Registry,
            Topics = [Erc1056Topics.DIDDelegateChanged, PadAddress(identity)],
            Data = data,
            BlockNumber = "0x" + block.ToString("x"),
            LogIndex = logIndex,
        };
    }

    private static EthereumLogEntry GarbageTopicLog(string identity, ulong block) => new()
    {
        Address = Registry,
        // Not one of the three ERC-1056 topics → Erc1056EventParser throws ArgumentException.
        Topics = ["0x" + new string('e', 64), PadAddress(identity)],
        Data = "0x" + new string('0', 128),
        BlockNumber = "0x" + block.ToString("x"),
    };

    private static string PadAddress(string addr)
    {
        var hex = addr.StartsWith("0x") ? addr[2..] : addr;
        return "0x" + hex.PadLeft(64, '0');
    }
}
