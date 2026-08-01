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

    // ── Adversarial-review pins: other infrastructure paths in the try block ─────

    [Fact]
    public async Task Issue116_ChainIdRpcFallbackFailure_ReturnsInternalError()
    {
        // With no configured ChainId the resolver falls back to eth_chainId over RPC;
        // a transport failure there is infrastructure like any other.
        var noChainId = new EthereumNetworkConfig
        {
            Name = "sepolia", RpcUrl = "https://rpc.sepolia.example",
            RegistryAddress = Registry,
        };
        var rpc = Substitute.For<IEthereumRpcClient>();
        rpc.GetChainIdAsync(default)
           .ReturnsForAnyArgs<Task<ulong>>(_ => throw new HttpRequestException("down"));
        var factory = Substitute.For<IEthereumRpcClientFactory>();
        factory.GetOrCreate(Arg.Any<EthereumNetworkConfig>()).Returns(rpc);
        var method = new DidEthrMethod(factory, [noChainId], new DefaultKeyGenerator());

        var result = await method.ResolveAsync($"did:ethr:sepolia:{Identity}");

        result.ResolutionMetadata.Error.Should().Be("internalError");
    }

    [Fact]
    public async Task Issue116_BlockTimestampFailureDuringVersionId_ReturnsInternalError()
    {
        // Historical (versionId) resolution fans out to eth_getBlockByNumber for the
        // reference timestamp; a failure there must not surface as notFound either.
        const ulong block = 10;
        var rpc = Substitute.For<IEthereumRpcClient>();
        rpc.CallAsync(default!, default!, default)
           .ReturnsForAnyArgs("0x" + block.ToString("x64"));
        rpc.GetLogsAsync(default!, default)
           .ReturnsForAnyArgs(call => Task.FromResult<IReadOnlyList<EthereumLogEntry>>(
               call.Arg<EthereumLogFilter>().FromBlock == block
                   ? [OwnerChangedLog(Identity, Identity, block, 0)]
                   : []));
        rpc.GetBlockTimestampAsync(default, default)
           .ReturnsForAnyArgs<Task<ulong>>(_ => throw new HttpRequestException("pruned"));

        var result = await MakeMethod(rpc).ResolveAsync(
            $"did:ethr:sepolia:{Identity}", new DidEthrResolveOptions { VersionId = "10" });

        result.ResolutionMetadata.Error.Should().Be("internalError");
    }

    [Fact]
    public async Task Issue116_RpcClientFactoryThrows_ReturnsInternalError()
    {
        // The factory is an injected dependency; a throw from it must not escape
        // ResolveAsync (adversarial finding: it used to sit outside the try block).
        var factory = Substitute.For<IEthereumRpcClientFactory>();
        factory.GetOrCreate(Arg.Any<EthereumNetworkConfig>())
               .Returns(_ => throw new InvalidOperationException("hostile factory"));
        var method = new DidEthrMethod(factory, [Sepolia], new DefaultKeyGenerator());

        var result = await method.ResolveAsync($"did:ethr:sepolia:{Identity}");

        result.ResolutionMetadata.Error.Should().Be("internalError");
    }

    // ── Metadata reason sanitization ─────────────────────────────────────────────

    [Fact]
    public async Task Issue116_ReasonWithControlCharacters_IsSanitizedSingleLine()
    {
        // Node-supplied fragments interpolated into library messages can carry
        // newlines/control chars; the caller-facing reason must be single-line.
        var rpc = Substitute.For<IEthereumRpcClient>();
        rpc.CallAsync(default!, default!, default)
           .ReturnsForAnyArgs<Task<string>>(_ => throw new EthereumInteractionException(
               "RPC error for 'eth_call': {\n\"message\": \"evil text\"\r\n}"));

        var result = await MakeMethod(rpc).ResolveAsync($"did:ethr:sepolia:{Identity}");

        result.ResolutionMetadata.Error.Should().Be("internalError");
        var message = (string)result.ResolutionMetadata.AdditionalProperties!["message"];
        message.Should().NotContainAny("\n", "\r");
        message.Should().Contain("evil text", "control chars are replaced, content retained");
    }

    [Fact]
    public async Task Issue116_OversizedReason_TruncatedWithoutSplittingSurrogatePair()
    {
        // The 500-char bound must not cut a surrogate pair in half: a node can pad
        // the hostile fragment so an astral char straddles the boundary, handing
        // callers invalid UTF-16.
        var padded = new string('a', 499) + "\U0001F600" + new string('b', 100);
        var rpc = Substitute.For<IEthereumRpcClient>();
        rpc.CallAsync(default!, default!, default)
           .ReturnsForAnyArgs<Task<string>>(
               _ => throw new EthereumInteractionException(padded));

        var result = await MakeMethod(rpc).ResolveAsync($"did:ethr:sepolia:{Identity}");

        var message = (string)result.ResolutionMetadata.AdditionalProperties!["message"];
        message.Length.Should().BeLessThanOrEqualTo(500);
        char.IsHighSurrogate(message[^1]).Should().BeFalse(
            "truncation must never produce a lone surrogate");
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

    /// <summary>
    /// A logging provider that formats the exception EAGERLY (ToString → Message),
    /// like console/file providers do — unlike NullLogger, which touches nothing.
    /// </summary>
    private sealed class EagerFormattingLogger : Microsoft.Extensions.Logging.ILogger<DidEthrMethod>
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(Microsoft.Extensions.Logging.LogLevel logLevel) => true;
        public void Log<TState>(
            Microsoft.Extensions.Logging.LogLevel logLevel,
            Microsoft.Extensions.Logging.EventId eventId,
            TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            _ = formatter(state, exception);
            _ = exception?.ToString();   // the eager render a real provider performs
        }
    }

    [Fact]
    public async Task Issue116_HostileException_EagerFormattingLogger_DoesNotEscapeResolveAsync()
    {
        // Adversarial finding (round 1, High): with a REAL logger the LogWarning call
        // itself rendered the hostile exception before the type-exactness guard ran,
        // and the provider's throw escaped ResolveAsync. The logging path must be
        // guarded so the never-throw contract holds under any logging provider.
        var rpc = Substitute.For<IEthereumRpcClient>();
        rpc.CallAsync(default!, default!, default)
           .ReturnsForAnyArgs<Task<string>>(_ => throw new ThrowingMessageException());
        var factory = Substitute.For<IEthereumRpcClientFactory>();
        factory.GetOrCreate(Arg.Any<EthereumNetworkConfig>()).Returns(rpc);
        var method = new DidEthrMethod(
            factory, [Sepolia], new DefaultKeyGenerator(), new EagerFormattingLogger());

        var result = await method.ResolveAsync($"did:ethr:sepolia:{Identity}");

        result.ResolutionMetadata.Error.Should().Be("internalError");
    }

    // ── Log-entry fixtures ───────────────────────────────────────────────────────

    private static EthereumLogEntry OwnerChangedLog(
        string identity, string newOwner, ulong block, ulong prev)
    {
        var ownerHex = newOwner.StartsWith("0x") ? newOwner[2..] : newOwner;
        var identityHex = identity.StartsWith("0x") ? identity[2..] : identity;
        return new EthereumLogEntry
        {
            Address = Registry,
            Topics = [Erc1056Topics.DIDOwnerChanged, "0x" + identityHex.PadLeft(64, '0')],
            Data = "0x" + "000000000000000000000000" + ownerHex + prev.ToString("x64"),
            BlockNumber = "0x" + block.ToString("x"),
            LogIndex = 0,
        };
    }
}
