using FluentAssertions;
using NetDid.Core;
using NetDid.Core.Crypto;
using NetDid.Core.Model;
using NetDid.Method.Ethr.Erc1056;
using NetDid.Method.Ethr.Rpc;
using NSubstitute;
using Xunit;

namespace NetDid.Method.Ethr.Tests;

/// <summary>
/// Integration-style tests for DidEthrMethod.CreateAsync and ResolveAsync.
/// The IEthereumRpcClient is mocked — no live network calls.
/// </summary>
public class DidEthrMethodTests
{
    private static readonly EthereumNetworkConfig SepoliaConfig = new()
    {
        Name           = "sepolia",
        RpcUrl         = "https://rpc.sepolia.example",
        ChainId        = "0xaa36a7",
        RegistryAddress = "0xdCa7EF03e98e0DC2B855bE647C39ABe984fcF21B",
    };

    private static DidEthrMethod MakeMethod(IEthereumRpcClient rpc)
    {
        // Wrap the single mock in a factory so all network lookups return it.
        // Tests that care about per-network routing construct the factory themselves.
        var factory = Substitute.For<IEthereumRpcClientFactory>();
        factory.GetOrCreate(Arg.Any<EthereumNetworkConfig>()).Returns(rpc);
        return new DidEthrMethod(factory, [SepoliaConfig], new DefaultKeyGenerator());
    }

    private static ISigner MakeSigner(KeyPair keyPair)
        => new KeyPairSigner(keyPair, new DefaultCryptoProvider());

    // ── Create ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task CreateAsync_GeneratesNewKey_ProducesValidEthrDid()
    {
        var rpc = Substitute.For<IEthereumRpcClient>();
        rpc.GetChainIdAsync(default).ReturnsForAnyArgs(Task.FromResult(11155111UL));

        var method = MakeMethod(rpc);
        var result = await method.CreateAsync(new DidEthrCreateOptions { Network = "sepolia" });

        result.Did.Value.Should().StartWith("did:ethr:sepolia:0x");
        result.DidDocument.Should().NotBeNull();
        result.DidDocument!.VerificationMethod.Should().HaveCount(1);
        result.DidDocument.VerificationMethod![0].Type
            .Should().Be("EcdsaSecp256k1RecoveryMethod2020");
    }

    [Fact]
    public async Task CreateAsync_ExistingSecp256k1Key_UsesThatAddress()
    {
        var rpc = Substitute.For<IEthereumRpcClient>();
        rpc.GetChainIdAsync(default).ReturnsForAnyArgs(Task.FromResult(11155111UL));

        var keyGen = new DefaultKeyGenerator();
        var keyPair = keyGen.Generate(KeyType.Secp256k1);
        var signer = MakeSigner(keyPair);

        var method = MakeMethod(rpc);
        var result = await method.CreateAsync(new DidEthrCreateOptions
        {
            Network     = "sepolia",
            ExistingKey = signer,
        });

        // DID should encode the same address regardless of repeated calls
        var result2 = await method.CreateAsync(new DidEthrCreateOptions
        {
            Network     = "sepolia",
            ExistingKey = signer,
        });
        result.Did.Value.Should().Be(result2.Did.Value);
    }

    [Fact]
    public async Task CreateAsync_WrongKeyType_ThrowsArgumentException()
    {
        var rpc    = Substitute.For<IEthereumRpcClient>();
        var keyGen = new DefaultKeyGenerator();
        var ed25519Signer = MakeSigner(keyGen.Generate(KeyType.Ed25519));

        var method = MakeMethod(rpc);
        var act = () => method.CreateAsync(new DidEthrCreateOptions
        {
            Network     = "sepolia",
            ExistingKey = ed25519Signer,
        });

        await act.Should().ThrowAsync<ArgumentException>();
    }

    // ── Resolve — no-op (changed = 0) ─────────────────────────────────────────

    [Fact]
    public async Task ResolveAsync_NoEvents_ReturnsDefaultDocument()
    {
        var rpc = Substitute.For<IEthereumRpcClient>();
        // changed(address) returns 0x0 → no event history
        rpc.CallAsync(default!, default!, default)
           .ReturnsForAnyArgs("0x0000000000000000000000000000000000000000000000000000000000000000");

        var method = MakeMethod(rpc);
        var did    = "did:ethr:sepolia:0x001d3f1ef827552ae1114027bd3ecf1f086ba0f9";
        var result = await method.ResolveAsync(did);

        result.ResolutionMetadata.Error.Should().BeNull();
        result.DidDocument.Should().NotBeNull();
        result.DidDocument!.VerificationMethod.Should().HaveCount(1);
        result.DidDocument.VerificationMethod![0].Id.Should().EndWith("#controller");
    }

    // ── Resolve — with owner-change event ─────────────────────────────────────

    [Fact]
    public async Task ResolveAsync_WithOwnerChangedEvent_ReflectsNewOwner()
    {
        const string identity  = "0x001d3f1ef827552ae1114027bd3ecf1f086ba0f9";
        const string newOwner         = "0xdbf03b407c01e7cd3cbea99509d93f8dddc8c6fb";
        const string newOwnerChecksum  = "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB";
        const ulong  eventBlock = 42;

        var rpc = Substitute.For<IEthereumRpcClient>();

        // First call to changed() returns block 42
        rpc.CallAsync(default!, default!, default)
           .ReturnsForAnyArgs(
               "0x000000000000000000000000000000000000000000000000000000000000002a");

        rpc.GetLogsAsync(default!, default).ReturnsForAnyArgs(call =>
        {
            var filter = call.Arg<EthereumLogFilter>();
            if (filter.FromBlock == eventBlock && filter.ToBlock == eventBlock)
                return Task.FromResult(BuildOwnerChangedLog(identity, newOwner, eventBlock));
            return Task.FromResult<IReadOnlyList<EthereumLogEntry>>([]);
        });

        var method = MakeMethod(rpc);
        var result = await method.ResolveAsync($"did:ethr:sepolia:{identity}");

        result.ResolutionMetadata.Error.Should().BeNull();
        var controller = result.DidDocument!.VerificationMethod!
            .Single(v => v.Id.EndsWith("#controller"));
        controller.BlockchainAccountId.Should().Contain(newOwnerChecksum);
    }

    // ── Resolve — deactivated ─────────────────────────────────────────────────

    [Fact]
    public async Task ResolveAsync_ZeroAddressOwner_MarksDeactivated()
    {
        const string identity   = "0x001d3f1ef827552ae1114027bd3ecf1f086ba0f9";
        const string zeroAddr   = "0x0000000000000000000000000000000000000000";
        const ulong  eventBlock  = 99;

        var rpc = Substitute.For<IEthereumRpcClient>();
        rpc.CallAsync(default!, default!, default)
           .ReturnsForAnyArgs(
               "0x0000000000000000000000000000000000000000000000000000000000000063");

        rpc.GetLogsAsync(default!, default).ReturnsForAnyArgs(call =>
        {
            var filter = call.Arg<EthereumLogFilter>();
            if (filter.FromBlock == eventBlock)
                return Task.FromResult(BuildOwnerChangedLog(identity, zeroAddr, eventBlock));
            return Task.FromResult<IReadOnlyList<EthereumLogEntry>>([]);
        });

        var method = MakeMethod(rpc);
        var result = await method.ResolveAsync($"did:ethr:sepolia:{identity}");

        result.DocumentMetadata?.Deactivated.Should().BeTrue();
        result.DidDocument!.VerificationMethod.Should().BeNullOrEmpty();
    }

    // ── Resolve — VersionId ────────────────────────────────────────────────────

    [Fact]
    public async Task ResolveAsync_WithVersionId_UsesBlockTimestampAsReferenceTime()
    {
        const string identity   = "0x001d3f1ef827552ae1114027bd3ecf1f086ba0f9";
        const string delegate20 = "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed";
        const ulong  eventBlock  = 50;
        const ulong  versionBlock = 50;
        // validTo is far in the future from the block timestamp
        const ulong  blockTimestamp = 1_700_000_000; // Nov 2023
        const ulong  validTo = blockTimestamp + 3600;

        var rpc = Substitute.For<IEthereumRpcClient>();
        rpc.CallAsync(default!, default!, default)
           .ReturnsForAnyArgs("0x" + eventBlock.ToString("x64"));

        rpc.GetLogsAsync(default!, default).ReturnsForAnyArgs(call =>
        {
            var filter = call.Arg<EthereumLogFilter>();
            if (filter.FromBlock == eventBlock)
                return Task.FromResult(BuildDelegateLog(identity, delegate20, "veriKey",
                    validTo, 0, eventBlock));
            return Task.FromResult<IReadOnlyList<EthereumLogEntry>>([]);
        });
        rpc.GetBlockTimestampAsync(versionBlock, default).ReturnsForAnyArgs(blockTimestamp);

        var method = MakeMethod(rpc);
        var options = new DidEthrResolveOptions { VersionId = versionBlock.ToString() };
        var result  = await method.ResolveAsync($"did:ethr:sepolia:{identity}", options);

        result.ResolutionMetadata.Error.Should().BeNull();
        result.DocumentMetadata!.VersionId.Should().Be(versionBlock.ToString());
        // The delegate is valid at that block timestamp → should be in document
        result.DidDocument!.VerificationMethod.Should().HaveCount(2); // #controller + #delegate-1
    }

    // ── Unsupported operations ────────────────────────────────────────────────

    [Fact]
    public async Task UpdateAsync_ThrowsOperationNotSupportedException()
    {
        var rpc    = Substitute.For<IEthereumRpcClient>();
        var method = MakeMethod(rpc);
        var keyGen = new DefaultKeyGenerator();
        var signer = MakeSigner(keyGen.Generate(KeyType.Secp256k1));

        var act = () => method.UpdateAsync("did:ethr:sepolia:0x001d3f1ef827552ae1114027bd3ecf1f086ba0f9",
            new DidEthrUpdateOptions { ControllerKey = signer });
        await act.Should().ThrowAsync<Core.Exceptions.OperationNotSupportedException>();
    }

    [Fact]
    public async Task DeactivateAsync_ThrowsOperationNotSupportedException()
    {
        var rpc    = Substitute.For<IEthereumRpcClient>();
        var method = MakeMethod(rpc);
        var keyGen = new DefaultKeyGenerator();
        var signer = MakeSigner(keyGen.Generate(KeyType.Secp256k1));

        var act = () => method.DeactivateAsync("did:ethr:sepolia:0x001d3f1ef827552ae1114027bd3ecf1f086ba0f9",
            new DidEthrDeactivateOptions { ControllerKey = signer });
        await act.Should().ThrowAsync<Core.Exceptions.OperationNotSupportedException>();
    }

    // ── Multi-network routing ─────────────────────────────────────────────────

    [Fact]
    public async Task ResolveAsync_MultipleNetworks_RoutesRpcCallsToCorrectEndpoint()
    {
        // Two networks, each backed by a distinct RPC mock.
        const string mainnetIdentity = "0x001d3f1ef827552ae1114027bd3ecf1f086ba0f9";
        const string sepoliaIdentity = "0xdbf03b407c01e7cd3cbea99509d93f8dddc8c6fb";

        var mainnetConfig = new EthereumNetworkConfig
        {
            Name            = "mainnet",
            RpcUrl          = "https://mainnet.example",
            ChainId         = "0x1",
            RegistryAddress = "0xdCa7EF03e98e0DC2B855bE647C39ABe984fcF21B",
        };

        var mainnetRpc = Substitute.For<IEthereumRpcClient>();
        var sepoliaRpc = Substitute.For<IEthereumRpcClient>();

        // Both return "no events" so resolution completes without further RPC calls.
        var zero = "0x" + new string('0', 64);
        mainnetRpc.CallAsync(default!, default!, default).ReturnsForAnyArgs(zero);
        sepoliaRpc.CallAsync(default!, default!, default).ReturnsForAnyArgs(zero);

        var factory = Substitute.For<IEthereumRpcClientFactory>();
        factory.GetOrCreate(Arg.Is<EthereumNetworkConfig>(n => n.Name == "mainnet")).Returns(mainnetRpc);
        factory.GetOrCreate(Arg.Is<EthereumNetworkConfig>(n => n.Name == "sepolia")).Returns(sepoliaRpc);

        var method = new DidEthrMethod(factory, [mainnetConfig, SepoliaConfig], new DefaultKeyGenerator());

        // Resolve a mainnet DID — only mainnet RPC should be called.
        await method.ResolveAsync($"did:ethr:mainnet:{mainnetIdentity}");
        await mainnetRpc.Received().CallAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
        await sepoliaRpc.DidNotReceive().CallAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>());

        // Resolve a sepolia DID — only sepolia RPC should be called.
        sepoliaRpc.ClearReceivedCalls();
        mainnetRpc.ClearReceivedCalls();
        await method.ResolveAsync($"did:ethr:sepolia:{sepoliaIdentity}");
        await sepoliaRpc.Received().CallAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
        await mainnetRpc.DidNotReceive().CallAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    // ── Resolve — public-key DID ─────────────────────────────────────────────

    // Known compressed secp256k1 public key (Mastering Ethereum test vector)
    private static readonly byte[] KnownPubKey =
        Convert.FromHexString("026e145ccef1033dea239875dd00dfb4fee6e3348b84985c92f103444683bae07b");

    [Fact]
    public async Task ResolveAsync_PubkeyDid_NoEvents_AddsControllerKeyVm()
    {
        var rpc = Substitute.For<IEthereumRpcClient>();
        // changed() = 0  →  no event history
        rpc.CallAsync(default!, default!, default)
           .ReturnsForAnyArgs("0x" + new string('0', 64));

        var method = MakeMethod(rpc);
        var pubkeyHex = Convert.ToHexString(KnownPubKey).ToLowerInvariant();
        var did = $"did:ethr:sepolia:0x{pubkeyHex}";

        var result = await method.ResolveAsync(did);

        result.ResolutionMetadata.Error.Should().BeNull();
        var vms = result.DidDocument!.VerificationMethod!;
        vms.Should().HaveCount(2, "#controller + #controllerKey");
        var ckVm = vms.SingleOrDefault(v => v.Id.EndsWith("#controllerKey"));
        ckVm.Should().NotBeNull();
        ckVm!.Type.Should().Be("EcdsaSecp256k1VerificationKey2019");
        ckVm.PublicKeyJwk.Should().NotBeNull();
        // Both relationships must reference #controllerKey
        result.DidDocument.Authentication!.Should().Contain(e => e.Reference!.EndsWith("#controllerKey"));
        result.DidDocument.AssertionMethod!.Should().Contain(e => e.Reference!.EndsWith("#controllerKey"));
    }

    [Fact]
    public async Task ResolveAsync_PubkeyDid_OwnerChanged_ControllerKeyAbsent()
    {
        // When the owner transfers the identity to a different address the
        // #controllerKey VM must disappear — the pubkey no longer controls the DID.
        var derivedAddress = NetDid.Method.Ethr.Crypto.EthereumAddress
            .FromCompressedPublicKey(KnownPubKey).ToLowerInvariant();
        const string newOwner  = "0xdbf03b407c01e7cd3cbea99509d93f8dddc8c6fb";
        const ulong  eventBlock = 77;

        var rpc = Substitute.For<IEthereumRpcClient>();
        rpc.CallAsync(default!, default!, default)
           .ReturnsForAnyArgs("0x" + eventBlock.ToString("x64"));
        rpc.GetLogsAsync(default!, default).ReturnsForAnyArgs(call =>
        {
            var filter = call.Arg<EthereumLogFilter>();
            return Task.FromResult(filter.FromBlock == eventBlock
                ? BuildOwnerChangedLog(derivedAddress, newOwner, eventBlock)
                : (IReadOnlyList<EthereumLogEntry>)[]);
        });

        var method    = MakeMethod(rpc);
        var pubkeyHex = Convert.ToHexString(KnownPubKey).ToLowerInvariant();
        var did       = $"did:ethr:sepolia:0x{pubkeyHex}";

        var result = await method.ResolveAsync(did);

        result.ResolutionMetadata.Error.Should().BeNull();
        var vms = result.DidDocument!.VerificationMethod!;
        vms.Should().HaveCount(1, "only #controller — owner changed away from derived address");
        vms.Should().NotContain(v => v.Id.EndsWith("#controllerKey"));
        // #controller must reflect the new owner (case-insensitive — address is EIP-55 checksummed)
        vms[0].BlockchainAccountId!.ToLowerInvariant().Should().Contain(newOwner.ToLowerInvariant());
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static IReadOnlyList<EthereumLogEntry> BuildOwnerChangedLog(
        string identity, string newOwner, ulong block)
    {
        var newOwnerHex = newOwner.StartsWith("0x") ? newOwner[2..] : newOwner;
        var data = "0x"
            + "000000000000000000000000" + newOwnerHex
            + "0000000000000000000000000000000000000000000000000000000000000000";
        return [new EthereumLogEntry
        {
            Address     = "0xdCa7EF03e98e0DC2B855bE647C39ABe984fcF21B",
            Topics      = [Erc1056Topics.DIDOwnerChanged, PadAddress(identity)],
            Data        = data,
            BlockNumber = "0x" + block.ToString("x"),
        }];
    }

    private static IReadOnlyList<EthereumLogEntry> BuildDelegateLog(
        string identity, string delegate20, string delegateType,
        ulong validTo, ulong prev, ulong block)
    {
        var delHex  = delegate20.StartsWith("0x") ? delegate20[2..] : delegate20;
        var typeWord = new byte[32];
        System.Text.Encoding.ASCII.GetBytes(delegateType).CopyTo(typeWord, 0);

        var data = "0x"
            + Convert.ToHexString(typeWord).ToLowerInvariant()
            + "000000000000000000000000" + delHex
            + validTo.ToString("x64")
            + prev.ToString("x64");
        return [new EthereumLogEntry
        {
            Address     = "0xdCa7EF03e98e0DC2B855bE647C39ABe984fcF21B",
            Topics      = [Erc1056Topics.DIDDelegateChanged, PadAddress(identity)],
            Data        = data,
            BlockNumber = "0x" + block.ToString("x"),
        }];
    }

    private static EthereumLogEntry SingleDelegateLog(
        string identity, string delegate20, string delegateType,
        ulong validTo, ulong prev, ulong block)
        => BuildDelegateLog(identity, delegate20, delegateType, validTo, prev, block)[0];

    // ── topics[1] identity filter ───────────────────────────────────────────────

    /// <summary>
    /// eth_getLogs MUST constrain topics[1] to the specific identity address so we
    /// don't pull every event emitted by the registry for other identities at the
    /// same block.  This is essential on busy networks where many DIDs change in
    /// the same block.
    /// </summary>
    [Fact]
    public async Task ResolveAsync_EventChainWalking_FiltersLogsByIdentityAddressAtTopicsPosition1()
    {
        const string identity = "0x001d3f1ef827552ae1114027bd3ecf1f086ba0f9";
        const ulong  eventBlock = 7;

        EthereumLogFilter? capturedFilter = null;
        var rpc = Substitute.For<IEthereumRpcClient>();

        // changed() returns block 7 — triggers one trip through the walker
        rpc.CallAsync(default!, default!, default)
           .ReturnsForAnyArgs("0x" + eventBlock.ToString("x64"));

        rpc.GetLogsAsync(Arg.Any<EthereumLogFilter>(), Arg.Any<CancellationToken>())
           .Returns(call =>
           {
               capturedFilter = call.Arg<EthereumLogFilter>();
               return Task.FromResult<IReadOnlyList<EthereumLogEntry>>([]);
           });

        await MakeMethod(rpc).ResolveAsync($"did:ethr:sepolia:{identity}");

        capturedFilter.Should().NotBeNull("GetLogsAsync must have been called");

        // topics[0] = event signature OR-list
        capturedFilter!.Topics.Should().NotBeNull();
        capturedFilter.Topics!.Count.Should().BeGreaterThanOrEqualTo(2,
            "filter must specify at least topics[0] (signatures) and topics[1] (identity)");

        // topics[1] must be exactly the 32-byte padded identity address
        var expectedTopic1 = "0x" + identity[2..].PadLeft(64, '0');
        capturedFilter.Topics[1].Should().ContainSingle()
            .Which.Should().Be(expectedTopic1,
                "filtering on topics[1] avoids fetching events for unrelated identities");
    }

    // ── Walker non-termination regression ───────────────────────────────────────

    /// <summary>
    /// When a block contains multiple events for the same identity, later transactions
    /// in that block emit previousChange == block.number (the value that changed[identity]
    /// was set to by an earlier transaction in the same block).  The old walker took
    /// max(previousChange), which equalled the current block and looped forever.
    ///
    /// This test detects the regression by throwing on the second visit to the same block,
    /// so a buggy walker fails fast instead of hanging the test runner.
    /// </summary>
    [Fact]
    public async Task ResolveAsync_TwoEventsInSameBlock_WalkerTerminatesAndCollectsBothDelegates()
    {
        const string identity   = "0x001d3f1ef827552ae1114027bd3ecf1f086ba0f9";
        const string keyA       = "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed";
        const string keyB       = "0xdbf03b407c01e7cd3cbea99509d93f8dddc8c6fb";
        const ulong  eventBlock = 50UL;
        var future = (ulong)(DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 3600);

        var rpc = Substitute.For<IEthereumRpcClient>();

        // changed() returns block 50
        rpc.CallAsync(default!, default!, default)
           .ReturnsForAnyArgs("0x" + eventBlock.ToString("x64"));

        // Guard: throw if any block is fetched more than once (detects the old infinite loop)
        var fetchCounts = new Dictionary<ulong, int>();
        rpc.GetLogsAsync(Arg.Any<EthereumLogFilter>(), Arg.Any<CancellationToken>())
           .Returns(call =>
           {
               var filter = call.Arg<EthereumLogFilter>();
               fetchCounts.TryGetValue(filter.FromBlock, out var n);
               if (n >= 1)
                   throw new InvalidOperationException(
                       $"Block {filter.FromBlock} was fetched {n + 1} times — walker did not terminate.");
               fetchCounts[filter.FromBlock] = n + 1;

               if (filter.FromBlock != eventBlock)
                   return Task.FromResult<IReadOnlyList<EthereumLogEntry>>([]);

               // Block 50 has two delegate events:
               //   Tx 0 — prevChange = 0          (first event ever for this identity)
               //   Tx 1 — prevChange = eventBlock  (same-block back-reference, the problematic case)
               return Task.FromResult<IReadOnlyList<EthereumLogEntry>>(
               [
                   SingleDelegateLog(identity, keyA, "veriKey", future, 0UL,         eventBlock),
                   SingleDelegateLog(identity, keyB, "veriKey", future, eventBlock,  eventBlock),
               ]);
           });

        var result = await MakeMethod(rpc).ResolveAsync($"did:ethr:sepolia:{identity}");

        result.ResolutionMetadata.Error.Should().BeNull();
        result.DidDocument!.VerificationMethod.Should().HaveCount(3,
            "#controller + keyA (#delegate-1) + keyB (#delegate-2)");
        // Block 50 must have been fetched exactly once
        fetchCounts[eventBlock].Should().Be(1);
    }

    private static string PadAddress(string addr)
    {
        var hex = addr.StartsWith("0x") ? addr[2..] : addr;
        return "0x" + hex.PadLeft(64, '0');
    }
}
