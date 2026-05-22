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
        => new(rpc, [SepoliaConfig], new DefaultKeyGenerator());

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
        const string newOwner  = "0xdbf03b407c01e7cd3cbea99509d93f8dddc8c6fb";
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
        controller.BlockchainAccountId.Should().Contain(newOwner);
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

    private static string PadAddress(string addr)
    {
        var hex = addr.StartsWith("0x") ? addr[2..] : addr;
        return "0x" + hex.PadLeft(64, '0');
    }
}
