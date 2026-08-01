using FluentAssertions;
using NetCrypto;
using NetDid.Core.Exceptions;
using NetDid.Method.Ethr.Erc1056;
using NetDid.Method.Ethr.Rpc;
using NSubstitute;
using Xunit;

namespace NetDid.Method.Ethr.Tests;

/// <summary>
/// Issue #116: RPC infrastructure failures (pruned/non-archive nodes, hostile-node
/// detection, transport errors, internal timeouts) must resolve with
/// resolutionMetadata.error = "internalError", never "notFound". Per the W3C DID
/// Resolution spec, notFound is a statement that the DID does not exist; an endpoint
/// that cannot serve the DID's history is a resolver-infrastructure failure.
/// A genuinely unregistered identity never errors at all — it resolves to the
/// ERC-1056 genesis document.
/// </summary>
public class Issue116ResolutionErrorMappingTests
{
    private const string Identity = "0x001d3f1ef827552ae1114027bd3ecf1f086ba0f9";
    private const string Registry = "0xdCa7EF03e98e0DC2B855bE647C39ABe984fcF21B";

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

    // ── Pruned/non-archive node: changed() asserts a block, node has no logs ─────

    [Fact]
    public async Task Issue116_PointerBlockEmpty_PrunedNode_ReturnsInternalError()
    {
        // The issue's canonical repro: changed()=77 asserts an event at block 77, but
        // the (pruned/non-archive) node returns no logs. Resolution stops — and the
        // failure belongs to the endpoint, not the DID.
        var rpc = Substitute.For<IEthereumRpcClient>();
        rpc.CallAsync(default!, default!, default)
           .ReturnsForAnyArgs("0x" + 77UL.ToString("x64"));
        rpc.GetLogsAsync(default!, default)
           .ReturnsForAnyArgs(Task.FromResult<IReadOnlyList<EthereumLogEntry>>([]));

        var result = await MakeMethod(rpc).ResolveAsync($"did:ethr:sepolia:{Identity}");

        result.DidDocument.Should().BeNull();
        result.ResolutionMetadata.Error.Should().Be("internalError");
    }

    [Fact]
    public async Task Issue116_PrunedNodeReason_SurfacesInMetadataMessage()
    {
        // Callers must be able to tell "pruned node" from generic failure: the
        // walker's diagnostic (which names the incomplete block) is carried as a
        // "message" beside "error", mirroring the reference resolver's metadata shape.
        var rpc = Substitute.For<IEthereumRpcClient>();
        rpc.CallAsync(default!, default!, default)
           .ReturnsForAnyArgs("0x" + 77UL.ToString("x64"));
        rpc.GetLogsAsync(default!, default)
           .ReturnsForAnyArgs(Task.FromResult<IReadOnlyList<EthereumLogEntry>>([]));

        var result = await MakeMethod(rpc).ResolveAsync($"did:ethr:sepolia:{Identity}");

        result.ResolutionMetadata.Error.Should().Be("internalError");
        result.ResolutionMetadata.AdditionalProperties.Should().ContainKey("message")
            .WhoseValue.Should().BeOfType<string>()
            .Which.Should().Contain("incomplete", "the pruned-node diagnostic must reach the caller");
    }

    // ── Transport failures ───────────────────────────────────────────────────────

    [Fact]
    public async Task Issue116_TransportFailureOnGetLogs_ReturnsInternalError()
    {
        // Raw HttpRequestException (DNS failure, connection refused) escapes the RPC
        // client unwrapped — a transport error is not a statement about the DID.
        var rpc = Substitute.For<IEthereumRpcClient>();
        rpc.CallAsync(default!, default!, default)
           .ReturnsForAnyArgs("0x" + 5UL.ToString("x64"));
        rpc.GetLogsAsync(default!, default)
           .ReturnsForAnyArgs<Task<IReadOnlyList<EthereumLogEntry>>>(
               _ => throw new HttpRequestException("connection refused"));

        var result = await MakeMethod(rpc).ResolveAsync($"did:ethr:sepolia:{Identity}");

        result.DidDocument.Should().BeNull();
        result.ResolutionMetadata.Error.Should().Be("internalError");
    }

    [Fact]
    public async Task Issue116_TransportFailureOnChangedCall_ReturnsInternalError()
    {
        var rpc = Substitute.For<IEthereumRpcClient>();
        rpc.CallAsync(default!, default!, default)
           .ReturnsForAnyArgs<Task<string>>(_ => throw new HttpRequestException("no route to host"));

        var result = await MakeMethod(rpc).ResolveAsync($"did:ethr:sepolia:{Identity}");

        result.DidDocument.Should().BeNull();
        result.ResolutionMetadata.Error.Should().Be("internalError");
    }

    // ── Internal timeouts vs caller cancellation ─────────────────────────────────

    [Fact]
    public async Task Issue116_InternalRpcTimeout_ReturnsInternalError()
    {
        // The RPC client's per-request timeout surfaces as an OperationCanceledException
        // on a token the CALLER never canceled. That is resolver infrastructure, not
        // caller intent — it must map to internalError, not throw and not notFound.
        var rpc = Substitute.For<IEthereumRpcClient>();
        rpc.CallAsync(default!, default!, default)
           .ReturnsForAnyArgs<Task<string>>(
               _ => throw new OperationCanceledException("per-request RPC timeout"));

        var result = await MakeMethod(rpc).ResolveAsync($"did:ethr:sepolia:{Identity}");

        result.DidDocument.Should().BeNull();
        result.ResolutionMetadata.Error.Should().Be("internalError");
    }

    [Fact]
    public async Task Issue116_CallerCancellation_StillPropagates()
    {
        // Genuine caller cancellation is never converted into a resolution error.
        using var cts = new CancellationTokenSource();
        var rpc = Substitute.For<IEthereumRpcClient>();
        rpc.CallAsync(default!, default!, default)
           .ReturnsForAnyArgs<Task<string>>(_ =>
           {
               cts.Cancel();
               throw new OperationCanceledException(cts.Token);
           });

        var act = () => MakeMethod(rpc)
            .ResolveAsync($"did:ethr:sepolia:{Identity}", options: null, cts.Token);

        await act.Should().ThrowAsync<OperationCanceledException>();
    }

    // ── Acceptance pins: absent DID and invalid identifier are unchanged ─────────

    [Fact]
    public async Task Issue116_UnregisteredIdentity_HealthyNode_ResolvesGenesisDocument()
    {
        // changed() == 0 on a healthy node: the identity has no on-chain history.
        // did:ethr defines this as the ERC-1056 genesis document — success, no error.
        var rpc = Substitute.For<IEthereumRpcClient>();
        rpc.CallAsync(default!, default!, default)
           .ReturnsForAnyArgs("0x" + 0UL.ToString("x64"));

        var result = await MakeMethod(rpc).ResolveAsync($"did:ethr:sepolia:{Identity}");

        result.ResolutionMetadata.Error.Should().BeNull();
        result.DidDocument.Should().NotBeNull();
        result.DidDocument!.VerificationMethod.Should().ContainSingle()
            .Which.Id.Should().EndWith("#controller");
    }

    [Fact]
    public async Task Issue116_InvalidIdentifier_StillInvalidDid()
    {
        var rpc = Substitute.For<IEthereumRpcClient>();

        var result = await MakeMethod(rpc).ResolveAsync("did:ethr:sepolia:0xnothex");

        result.ResolutionMetadata.Error.Should().Be("invalidDid");
    }

    // ── Hostile dependency exception must not defeat the mapping ─────────────────

    private sealed class ThrowingMessageException : EthereumInteractionException
    {
        public ThrowingMessageException() : base("placeholder") { }
        public override string Message => throw new InvalidOperationException("hostile Message getter");
    }

    [Fact]
    public async Task Issue116_HostileExceptionSubclass_ThrowingMessageGetter_StillInternalError()
    {
        // Exception.Message is virtual; an injected RPC client can throw a subclass whose
        // getter itself throws. The mapping must not read hostile Message text — it falls
        // back to fixed library-owned wording and still returns internalError.
        var rpc = Substitute.For<IEthereumRpcClient>();
        rpc.CallAsync(default!, default!, default)
           .ReturnsForAnyArgs<Task<string>>(_ => throw new ThrowingMessageException());

        var result = await MakeMethod(rpc).ResolveAsync($"did:ethr:sepolia:{Identity}");

        result.ResolutionMetadata.Error.Should().Be("internalError");
        result.ResolutionMetadata.AdditionalProperties.Should().ContainKey("message")
            .WhoseValue.Should().BeOfType<string>()
            .Which.Should().NotContain("hostile");
    }
}
