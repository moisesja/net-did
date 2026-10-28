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
        // Callers must be able to tell "pruned node" from generic failure: a FIXED
        // library-owned incomplete-history message (selected by the internal marker
        // exception type, never by untrusted message content) is carried as a
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

    // ── Reason provenance: injected-seam text never reaches metadata ─────────────

    [Fact]
    public async Task Issue116_ExactTypeExceptionMessage_NeverPublishedToMetadata()
    {
        // PR #122 review finding 2: EthereumInteractionException has a PUBLIC
        // constructor, so the exact runtime type is not provenance — an injected RPC
        // client can throw it with arbitrary (even secret-bearing) text. The metadata
        // reason must be fixed library-owned wording, never Exception.Message.
        var rpc = Substitute.For<IEthereumRpcClient>();
        rpc.CallAsync(default!, default!, default)
           .ReturnsForAnyArgs<Task<string>>(_ => throw new EthereumInteractionException(
               "Authorization: Bearer secret-token-value"));

        var result = await MakeMethod(rpc).ResolveAsync($"did:ethr:sepolia:{Identity}");

        result.ResolutionMetadata.Error.Should().Be("internalError");
        var message = (string)result.ResolutionMetadata.AdditionalProperties!["message"];
        message.Should().NotContain("secret", "injected-seam exception text is untrusted");
        message.Should().Be("Ethereum RPC interaction failed.");
    }

    // ── Never-completing, cancellation-ignoring dependency ───────────────────────

    [Fact]
    public async Task Issue116_CancellationIgnoringRpcClient_BoundedByResolutionDeadline()
    {
        // PR #122 review: the deadline must bind the RETURNED task, not merely pass a
        // token — an injected client that ignores cancellation and never completes
        // must not hang resolution forever.
        var rpc = Substitute.For<IEthereumRpcClient>();
        rpc.CallAsync(default!, default!, default)
           .ReturnsForAnyArgs(new TaskCompletionSource<string>().Task);
        var factory = Substitute.For<IEthereumRpcClientFactory>();
        factory.GetOrCreate(Arg.Any<EthereumNetworkConfig>()).Returns(rpc);
        var method = new DidEthrMethod(factory, [Sepolia], new DefaultKeyGenerator())
        {
            ResolutionDeadline = TimeSpan.FromMilliseconds(250),
        };

        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        var resolve = method.ResolveAsync($"did:ethr:sepolia:{Identity}");
        var winner = await Task.WhenAny(resolve, Task.Delay(TimeSpan.FromSeconds(30)));
        stopwatch.Stop();

        winner.Should().BeSameAs(resolve, "the deadline must fire even when the client ignores cancellation");
        // Well below the 30 s fallback: the configured 250 ms deadline (plus scheduler
        // slack) is what returned control, not some larger implicit timeout.
        stopwatch.Elapsed.Should().BeLessThan(TimeSpan.FromSeconds(10));
        (await resolve).ResolutionMetadata.Error.Should().Be("internalError");
    }

    [Fact]
    public async Task Issue116_SharedHungRpcTask_NoPerCallRetention_NoLateRpcFanout()
    {
        // PR #122 review round 2, finding 1: bounding only the OUTER ResolveFromChainAsync
        // task abandoned the inner state machine at its bare dependency await — a client
        // returning ONE shared forever-pending task retained one continuation per
        // resolution, and completing it later resumed every abandoned resolution,
        // fanning out post-deadline GetLogsAsync calls. With every dependency await
        // individually bounded: BCL WaitAsync removes its continuation on cancellation
        // (at most the single deduped fault observer remains), and late completion
        // resumes nothing.
        const int Resolutions = 20;
        var shared = new TaskCompletionSource<string>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var getLogsCalls = 0;
        var rpc = Substitute.For<IEthereumRpcClient>();
        rpc.CallAsync(default!, default!, default).ReturnsForAnyArgs(shared.Task);
        rpc.GetLogsAsync(default!, default).ReturnsForAnyArgs(_ =>
        {
            Interlocked.Increment(ref getLogsCalls);
            return Task.FromResult<IReadOnlyList<EthereumLogEntry>>([]);
        });
        var factory = Substitute.For<IEthereumRpcClientFactory>();
        factory.GetOrCreate(Arg.Any<EthereumNetworkConfig>()).Returns(rpc);
        var method = new DidEthrMethod(factory, [Sepolia], new DefaultKeyGenerator())
        {
            ResolutionDeadline = TimeSpan.FromMilliseconds(100),
        };

        var results = await Task.WhenAll(Enumerable.Range(0, Resolutions)
            .Select(_ => method.ResolveAsync($"did:ethr:sepolia:{Identity}")));

        results.Should().OnlyContain(r => r.ResolutionMetadata.Error == "internalError");
        // WaitAsync removes its source continuation asynchronously relative to the
        // caller-visible cancellation completion. Under CI load, the steady-state
        // observer can briefly coexist with one BCL wait continuation. Wait for that
        // transient cleanup, then assert the permanent-retention invariant.
        var continuationCount = await WaitForContinuationCountAtMostAsync(
            shared.Task, maximum: 1, timeout: TimeSpan.FromSeconds(2));
        continuationCount.Should().BeLessThanOrEqualTo(1,
            "cancelled waits must remove their continuations from the shared dependency " +
            "task; only the single deduped fault observer may remain");

        // Late completion: a block-5 changed() answer. No abandoned state machine may
        // resume — zero RPC calls after every caller has already received its result.
        shared.SetResult("0x" + 5UL.ToString("x64"));
        await Task.Delay(250);
        getLogsCalls.Should().Be(0,
            "an abandoned resolution must never issue RPC calls after its caller timed out");
    }

    [Fact]
    public async Task Issue116_CompletedTaskFastPath_CallerCancellation_StopsTheWalkImmediately()
    {
        // PR #122 review round 3, finding 1: WaitAsyncObserved deliberately lets an
        // already-completed task win over a fired token, so a token-ignoring client
        // returning COMPLETED tasks kept the whole synchronous walk running after
        // cancellation (reviewer repro: all 1,000 hops issued post-cancel). With the
        // explicit per-call token checks, cancelling during hop 1 means hop 2 never
        // happens.
        const ulong startBlock = 10_000;
        using var cts = new CancellationTokenSource();
        var getLogsCalls = 0;
        var rpc = Substitute.For<IEthereumRpcClient>();
        rpc.CallAsync(default!, default!, default)
           .ReturnsForAnyArgs("0x" + startBlock.ToString("x64"));
        rpc.GetLogsAsync(default!, default).ReturnsForAnyArgs(call =>
        {
            Interlocked.Increment(ref getLogsCalls);
            cts.Cancel();   // caller cancels while the walk is on its first hop
            var block = call.Arg<EthereumLogFilter>().FromBlock;
            return Task.FromResult<IReadOnlyList<EthereumLogEntry>>(
                [OwnerChangedLog(Identity, Identity, block, block - 1)]);
        });

        var act = () => MakeMethod(rpc)
            .ResolveAsync($"did:ethr:sepolia:{Identity}", options: null, cts.Token);

        await act.Should().ThrowAsync<OperationCanceledException>(
            "caller cancellation propagates even on the completed-task fast path");
        getLogsCalls.Should().Be(1,
            "no dependency call may be issued after cancellation");
    }

    [Fact]
    public async Task Issue116_CompletedTaskFastPath_DeadlineExpiry_StopsTheWalkImmediately()
    {
        // Deadline variant of the same class: the first hop outlives the 50 ms
        // deadline synchronously (token-ignoring client, completed tasks); the
        // per-hop check must stop the walk on the next iteration — internalError,
        // exactly one GetLogsAsync call, not the full 10,000-hop chain.
        const ulong startBlock = 10_000;
        var getLogsCalls = 0;
        var rpc = Substitute.For<IEthereumRpcClient>();
        rpc.CallAsync(default!, default!, default)
           .ReturnsForAnyArgs("0x" + startBlock.ToString("x64"));
        rpc.GetLogsAsync(default!, default).ReturnsForAnyArgs(call =>
        {
            if (Interlocked.Increment(ref getLogsCalls) == 1)
                Thread.Sleep(300);   // synchronously outlive the deadline
            var block = call.Arg<EthereumLogFilter>().FromBlock;
            return Task.FromResult<IReadOnlyList<EthereumLogEntry>>(
                [OwnerChangedLog(Identity, Identity, block, block - 1)]);
        });
        var factory = Substitute.For<IEthereumRpcClientFactory>();
        factory.GetOrCreate(Arg.Any<EthereumNetworkConfig>()).Returns(rpc);
        var method = new DidEthrMethod(factory, [Sepolia], new DefaultKeyGenerator())
        {
            ResolutionDeadline = TimeSpan.FromMilliseconds(50),
        };

        var result = await method.ResolveAsync($"did:ethr:sepolia:{Identity}");

        result.ResolutionMetadata.Error.Should().Be("internalError");
        getLogsCalls.Should().Be(1,
            "the walk must observe the expired deadline before issuing the next hop");
    }

    // ── Round 4: the TERMINAL dependency call has no next iteration ──────────────

    [Fact]
    public async Task Issue116_ChangedZero_CallerCancelledDuringCompletedCall_NoSuccessReturned()
    {
        // Cancellation lands during the very first (and only) dependency call, which
        // returns a completed changed()=0 result. Pre-call-only guards would fall
        // through to a "successful" genesis document for a caller that already
        // cancelled — the post-await check must propagate instead.
        using var cts = new CancellationTokenSource();
        var rpc = Substitute.For<IEthereumRpcClient>();
        rpc.CallAsync(default!, default!, default).ReturnsForAnyArgs(_ =>
        {
            cts.Cancel();
            return Task.FromResult("0x" + 0UL.ToString("x64"));
        });

        var act = () => MakeMethod(rpc)
            .ResolveAsync($"did:ethr:sepolia:{Identity}", options: null, cts.Token);

        await act.Should().ThrowAsync<OperationCanceledException>(
            "a cancelled caller must never receive a document");
    }

    [Fact]
    public async Task Issue116_ChangedZero_DeadlineExpiredDuringCompletedCall_InternalError()
    {
        var rpc = Substitute.For<IEthereumRpcClient>();
        rpc.CallAsync(default!, default!, default).ReturnsForAnyArgs(_ =>
        {
            Thread.Sleep(300);   // synchronously outlive the 50 ms deadline
            return Task.FromResult("0x" + 0UL.ToString("x64"));
        });
        var factory = Substitute.For<IEthereumRpcClientFactory>();
        factory.GetOrCreate(Arg.Any<EthereumNetworkConfig>()).Returns(rpc);
        var method = new DidEthrMethod(factory, [Sepolia], new DefaultKeyGenerator())
        {
            ResolutionDeadline = TimeSpan.FromMilliseconds(50),
        };

        var result = await method.ResolveAsync($"did:ethr:sepolia:{Identity}");

        result.ResolutionMetadata.Error.Should().Be("internalError",
            "an expired deadline must not fall through to a stale genesis document");
        result.DidDocument.Should().BeNull();
    }

    /// <summary>
    /// Dependency-owned log collection whose enumerator sleeps past the deadline
    /// before yielding its single (valid, terminal) event — the reviewer's round-4
    /// repro: result materialization outliving the deadline on the LAST hop.
    /// </summary>
    private sealed class SlowEnumerationLogList(EthereumLogEntry entry, TimeSpan delay)
        : IReadOnlyList<EthereumLogEntry>
    {
        public int Count => 1;
        public EthereumLogEntry this[int index] => entry;
        public IEnumerator<EthereumLogEntry> GetEnumerator()
        {
            Thread.Sleep(delay);
            yield return entry;
        }
        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator()
            => GetEnumerator();
    }

    [Fact]
    public async Task Issue116_TerminalHop_SlowEnumerationPastDeadline_InternalError_NotSuccess()
    {
        // changed()=1 with a terminal event (previousChange=0): there is no second
        // walk iteration, so only the post-await / per-item checks can observe the
        // deadline that expires while the hostile list is being enumerated.
        const ulong block = 1;
        var getLogsCalls = 0;
        var rpc = Substitute.For<IEthereumRpcClient>();
        rpc.CallAsync(default!, default!, default)
           .ReturnsForAnyArgs("0x" + block.ToString("x64"));
        rpc.GetLogsAsync(default!, default).ReturnsForAnyArgs(_ =>
        {
            Interlocked.Increment(ref getLogsCalls);
            return Task.FromResult<IReadOnlyList<EthereumLogEntry>>(
                new SlowEnumerationLogList(
                    OwnerChangedLog(Identity, Identity, block, prev: 0),
                    TimeSpan.FromMilliseconds(300)));
        });
        var factory = Substitute.For<IEthereumRpcClientFactory>();
        factory.GetOrCreate(Arg.Any<EthereumNetworkConfig>()).Returns(rpc);
        var method = new DidEthrMethod(factory, [Sepolia], new DefaultKeyGenerator())
        {
            ResolutionDeadline = TimeSpan.FromMilliseconds(50),
        };

        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        var result = await method.ResolveAsync($"did:ethr:sepolia:{Identity}");
        stopwatch.Stop();

        result.ResolutionMetadata.Error.Should().Be("internalError");
        result.DidDocument.Should().BeNull();
        getLogsCalls.Should().Be(1);
        stopwatch.Elapsed.Should().BeLessThan(TimeSpan.FromSeconds(10));
    }

    [Fact]
    public async Task Issue116_TerminalHop_CallerCancelledDuringFinalGetLogs_Propagates()
    {
        const ulong block = 1;
        using var cts = new CancellationTokenSource();
        var rpc = Substitute.For<IEthereumRpcClient>();
        rpc.CallAsync(default!, default!, default)
           .ReturnsForAnyArgs("0x" + block.ToString("x64"));
        rpc.GetLogsAsync(default!, default).ReturnsForAnyArgs(_ =>
        {
            cts.Cancel();   // fires during the LAST hop — no next iteration exists
            return Task.FromResult<IReadOnlyList<EthereumLogEntry>>(
                [OwnerChangedLog(Identity, Identity, block, prev: 0)]);
        });

        var act = () => MakeMethod(rpc)
            .ResolveAsync($"did:ethr:sepolia:{Identity}", options: null, cts.Token);

        await act.Should().ThrowAsync<OperationCanceledException>();
    }

    /// <summary>
    /// Empty dependency collection whose terminal MoveNext cancels the caller and
    /// returns false. A foreach-body token check never runs for this shape.
    /// </summary>
    private sealed class CancelOnEmptyEnumerationLogList(CancellationTokenSource cts)
        : IReadOnlyList<EthereumLogEntry>
    {
        public int Count => 0;
        public EthereumLogEntry this[int index] => throw new ArgumentOutOfRangeException(nameof(index));
        public IEnumerator<EthereumLogEntry> GetEnumerator()
        {
            cts.Cancel();
            yield break;
        }
        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator()
            => GetEnumerator();
    }

    [Fact]
    public async Task Issue116_EmptyEnumeration_CallerCancelledOnTerminalMoveNext_Propagates()
    {
        // The enumerator cancels and returns false on its first MoveNext. The loop
        // body never runs, so cancellation must be checked after enumeration before
        // the empty-history error can incorrectly win and map to internalError.
        const ulong block = 1;
        using var cts = new CancellationTokenSource();
        var rpc = Substitute.For<IEthereumRpcClient>();
        rpc.CallAsync(default!, default!, default)
           .ReturnsForAnyArgs("0x" + block.ToString("x64"));
        rpc.GetLogsAsync(default!, default).ReturnsForAnyArgs(_ =>
            Task.FromResult<IReadOnlyList<EthereumLogEntry>>(
                new CancelOnEmptyEnumerationLogList(cts)));

        var act = () => MakeMethod(rpc)
            .ResolveAsync($"did:ethr:sepolia:{Identity}", options: null, cts.Token);

        await act.Should().ThrowAsync<OperationCanceledException>(
            "genuine caller cancellation must win over empty-history classification");
    }

    /// <summary>
    /// Dependency enumerator that yields one valid event, then cancels the caller and
    /// throws while foreach disposes it. The post-loop token gate is never reached.
    /// </summary>
    private sealed class CancelAndThrowOnDisposeLogList(
        CancellationTokenSource cts, EthereumLogEntry entry)
        : IReadOnlyList<EthereumLogEntry>
    {
        public int Count => 1;
        public EthereumLogEntry this[int index] => index == 0
            ? entry
            : throw new ArgumentOutOfRangeException(nameof(index));
        public IEnumerator<EthereumLogEntry> GetEnumerator()
            => new Enumerator(cts, entry);
        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator()
            => GetEnumerator();

        private sealed class Enumerator(
            CancellationTokenSource cts, EthereumLogEntry entry)
            : IEnumerator<EthereumLogEntry>
        {
            private bool _yielded;
            public EthereumLogEntry Current => entry;
            object System.Collections.IEnumerator.Current => Current;
            public bool MoveNext()
            {
                if (_yielded)
                    return false;
                _yielded = true;
                return true;
            }
            public void Reset() => throw new NotSupportedException();
            public void Dispose()
            {
                cts.Cancel();
                throw new InvalidOperationException("hostile enumerator dispose");
            }
        }
    }

    [Fact]
    public async Task Issue116_EnumeratorDisposeFaultAfterCallerCancellation_PropagatesCancellation()
    {
        // A fault can bypass every local post-operation token gate. The outer trust
        // boundary must prioritize a genuinely cancelled caller over a simultaneous
        // dependency-owned enumeration fault.
        const ulong block = 1;
        using var cts = new CancellationTokenSource();
        var rpc = Substitute.For<IEthereumRpcClient>();
        rpc.CallAsync(default!, default!, default)
           .ReturnsForAnyArgs("0x" + block.ToString("x64"));
        rpc.GetLogsAsync(default!, default).ReturnsForAnyArgs(_ =>
            Task.FromResult<IReadOnlyList<EthereumLogEntry>>(
                new CancelAndThrowOnDisposeLogList(
                    cts, OwnerChangedLog(Identity, Identity, block, prev: 0))));

        var act = () => MakeMethod(rpc)
            .ResolveAsync($"did:ethr:sepolia:{Identity}", options: null, cts.Token);

        await act.Should().ThrowAsync<OperationCanceledException>(
            "caller cancellation must win over a simultaneous dependency fault");
    }

    /// <summary>
    /// Hostile dependency-owned list whose enumerator never terminates. Count lies.
    /// </summary>
    private sealed class NonterminatingLogList(Func<int, EthereumLogEntry> make)
        : IReadOnlyList<EthereumLogEntry>
    {
        public int Count => 1;
        public EthereumLogEntry this[int index] => make(index);
        public IEnumerator<EthereumLogEntry> GetEnumerator()
        {
            for (var i = 0; ; i++)
                yield return make(i);
        }
        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator()
            => GetEnumerator();
    }

    [Fact]
    public async Task Issue116_NonterminatingLogEnumeration_BoundedByCount_InternalError()
    {
        // A bare .ToList() on the dependency-owned collection would spin forever.
        // The resolver's own bounded materialization must stop at the count cap.
        const ulong block = 1;
        var rpc = Substitute.For<IEthereumRpcClient>();
        rpc.CallAsync(default!, default!, default)
           .ReturnsForAnyArgs("0x" + block.ToString("x64"));
        rpc.GetLogsAsync(default!, default).ReturnsForAnyArgs(_ =>
            Task.FromResult<IReadOnlyList<EthereumLogEntry>>(new NonterminatingLogList(
                i => OwnerChangedLog(Identity, Identity, block, prev: 0) with
                {
                    LogIndex = (ulong)i,
                })));

        var result = await MakeMethod(rpc).ResolveAsync($"did:ethr:sepolia:{Identity}");

        result.ResolutionMetadata.Error.Should().Be("internalError");
        result.DidDocument.Should().BeNull();
    }

    [Fact]
    public async Task Issue116_FinalVersionIdTimestamp_DeadlineExpired_InternalError()
    {
        // The versionId block-timestamp fetch is the LAST dependency call on that
        // path — a deadline expiring inside it must not fall through to success.
        const ulong block = 10;
        var rpc = Substitute.For<IEthereumRpcClient>();
        rpc.CallAsync(default!, default!, default)
           .ReturnsForAnyArgs("0x" + block.ToString("x64"));
        rpc.GetLogsAsync(default!, default)
           .ReturnsForAnyArgs(call => Task.FromResult<IReadOnlyList<EthereumLogEntry>>(
               call.Arg<EthereumLogFilter>().FromBlock == block
                   ? [OwnerChangedLog(Identity, Identity, block, prev: 0)]
                   : []));
        rpc.GetBlockTimestampAsync(default, default).ReturnsForAnyArgs(_ =>
        {
            Thread.Sleep(300);
            return Task.FromResult(100UL);
        });
        var factory = Substitute.For<IEthereumRpcClientFactory>();
        factory.GetOrCreate(Arg.Any<EthereumNetworkConfig>()).Returns(rpc);
        var method = new DidEthrMethod(factory, [Sepolia], new DefaultKeyGenerator())
        {
            ResolutionDeadline = TimeSpan.FromMilliseconds(50),
        };

        var result = await method.ResolveAsync(
            $"did:ethr:sepolia:{Identity}", new DidEthrResolveOptions { VersionId = "10" });

        result.ResolutionMetadata.Error.Should().Be("internalError");
        result.DidDocument.Should().BeNull();
    }

    [Fact]
    public async Task Issue116_FinalVersionTimeTimestamp_CallerCancelled_Propagates()
    {
        // The last iteration of the versionTime timestamp loop has no following
        // loop-head check — cancellation during its await must still propagate.
        const ulong block = 10;
        using var cts = new CancellationTokenSource();
        var rpc = Substitute.For<IEthereumRpcClient>();
        rpc.CallAsync(default!, default!, default)
           .ReturnsForAnyArgs("0x" + block.ToString("x64"));
        rpc.GetLogsAsync(default!, default)
           .ReturnsForAnyArgs(call => Task.FromResult<IReadOnlyList<EthereumLogEntry>>(
               call.Arg<EthereumLogFilter>().FromBlock == block
                   ? [OwnerChangedLog(Identity, Identity, block, prev: 0)]
                   : []));
        rpc.GetBlockTimestampAsync(default, default).ReturnsForAnyArgs(_ =>
        {
            cts.Cancel();
            return Task.FromResult(100UL);
        });

        var act = () => MakeMethod(rpc).ResolveAsync(
            $"did:ethr:sepolia:{Identity}",
            new DidEthrResolveOptions { VersionTime = "2020-01-01T00:00:00Z" },
            cts.Token);

        await act.Should().ThrowAsync<OperationCanceledException>();
    }

    /// <summary>
    /// Counts continuations on the BCL-internal slot (same pin as the Issue109 suite:
    /// .NET 10 field name, failing loudly if it moves).
    /// </summary>
    private static int RegisteredContinuationCount(Task task)
    {
        var field = typeof(Task).GetField(
            "m_continuationObject",
            System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic);
        field.Should().NotBeNull(
            "the retention pin reads Task's internal continuation slot; update this " +
            "helper if the BCL renames it");
        return field!.GetValue(task) switch
        {
            null => 0,
            List<object?> list => list.Count(entry => entry is not null),
            _ => 1,
        };
    }

    private static async Task<int> WaitForContinuationCountAtMostAsync(
        Task task, int maximum, TimeSpan timeout)
    {
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        var count = RegisteredContinuationCount(task);
        while (count > maximum && stopwatch.Elapsed < timeout)
        {
            await Task.Delay(10);
            count = RegisteredContinuationCount(task);
        }

        return count;
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

    /// <summary>
    /// A provider that throws on EVERY Log call — including the type-name-only
    /// fallback. PR #122 review finding 1: the fallback log call was unguarded, so
    /// this provider let the exception escape ResolveAsync.
    /// </summary>
    private sealed class AlwaysThrowingLogger : Microsoft.Extensions.Logging.ILogger<DidEthrMethod>
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(Microsoft.Extensions.Logging.LogLevel logLevel) => true;
        public void Log<TState>(
            Microsoft.Extensions.Logging.LogLevel logLevel,
            Microsoft.Extensions.Logging.EventId eventId,
            TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
            => throw new InvalidOperationException("logger failed");
    }

    [Fact]
    public async Task Issue116_AlwaysThrowingLogger_FactoryThrow_StillReturnsInternalError()
    {
        var factory = Substitute.For<IEthereumRpcClientFactory>();
        factory.GetOrCreate(Arg.Any<EthereumNetworkConfig>())
               .Returns(_ => throw new InvalidOperationException("hostile factory"));
        var method = new DidEthrMethod(
            factory, [Sepolia], new DefaultKeyGenerator(), new AlwaysThrowingLogger());

        var result = await method.ResolveAsync($"did:ethr:sepolia:{Identity}");

        result.ResolutionMetadata.Error.Should().Be("internalError");
    }

    [Fact]
    public async Task Issue116_AlwaysThrowingLogger_InvalidIdentifier_StillReturnsInvalidDid()
    {
        // The never-throw contract covers the pre-RPC warning sites too (identifier
        // parse, network lookup): logging is best-effort on every resolution path.
        var factory = Substitute.For<IEthereumRpcClientFactory>();
        var method = new DidEthrMethod(
            factory, [Sepolia], new DefaultKeyGenerator(), new AlwaysThrowingLogger());

        var result = await method.ResolveAsync("did:ethr:sepolia:0xnothex");

        result.ResolutionMetadata.Error.Should().Be("invalidDid");
    }

    [Fact]
    public async Task Issue116_AlwaysThrowingLogger_UnconfiguredNetwork_StillReturnsResult()
    {
        var factory = Substitute.For<IEthereumRpcClientFactory>();
        var method = new DidEthrMethod(
            factory, [Sepolia], new DefaultKeyGenerator(), new AlwaysThrowingLogger());

        var result = await method.ResolveAsync($"did:ethr:polygon:{Identity}");

        result.ResolutionMetadata.Error.Should().NotBeNull();
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
