using System.Reflection;
using System.Runtime.CompilerServices;
using FluentAssertions;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using NetCrypto;
using NetDid.Core.Exceptions;
using NetDid.Method.Ethr.Crypto;
using NetDid.Method.Ethr.Deployment;
using NetDid.Method.Ethr.Emulator;
using NetDid.Method.Ethr.Rpc;
using Xunit;

namespace NetDid.Method.Ethr.Tests;

/// <summary>
/// Issue #109: <c>Task.WaitAsync(ct)</c> abandons the underlying dependency task rather than
/// cancelling it. A fault raised after abandonment used to reach nobody, so the task's
/// finalizer escalated it through <see cref="TaskScheduler.UnobservedTaskException"/> — host
/// telemetry noise, and a process kill under <c>ThrowUnobservedTaskExceptions</c>. Every
/// deadline-bounded await now goes through
/// <see cref="AbandonableTaskExtensions.WaitAsyncObserved{T}"/>, which observes the orphan's
/// fault while leaving deadline, cancellation, and transaction-evidence behavior untouched.
///
/// Escalations are process-global and the suite runs in parallel, so each test correlates
/// them via a unique marker carried by <see cref="Issue109MarkerException"/>.
/// </summary>
public class Issue109UnobservedTaskTests
{
    private const string Registry = "0x03d5003bf0e79c5f5223588f347eba39afbc3818";
    private sealed record Actor(KeyPair KeyPair, KeyPairSigner Signer, string Address);

    private static Actor NewActor()
    {
        var pair = new DefaultKeyGenerator().Generate(KeyType.Secp256k1);
        return new Actor(
            pair,
            new KeyPairSigner(pair, new DefaultCryptoProvider()),
            EthereumAddress.FromCompressedPublicKey(pair.PublicKey).ToLowerInvariant());
    }

    private static DidEthrMethod MethodFor(IEthereumRpcClient client)
        => new(
            new SingleNetworkRpcFactory("sepolia", client),
            [KnownNetworks.Sepolia with { RpcUrl = "http://emulated.local" }],
            new DefaultKeyGenerator());

    private static DidEthrServiceAttribute Svc()
        => new() { ServiceType = "Hub", ServiceEndpoint = "https://hub.example" };

    private static string[] Confirmed(Exception exception)
        => Assert.IsType<string[]>(exception.Data[DidEthrMethod.LandedTransactionsKey]);

    private static string[] InFlight(Exception exception)
        => Assert.IsType<string[]>(exception.Data[DidEthrMethod.InFlightTransactionsKey]);

    // ── Helper unit ──────────────────────────────────────────────────────────

    [Fact]
    public async Task Issue109_AbandonedTaskFaultingAfterCancellation_RaisesNoEscalation()
    {
        var marker = Guid.NewGuid().ToString("N");
        using var probe = new UnobservedEscalationProbe(marker);

        await AbandonThenFaultAsync(marker);
        await ForceFinalizationAsync();

        probe.EscalationCount.Should().Be(0,
            "WaitAsyncObserved must observe a fault raised after the bounded wait abandons it");
    }

    // The abandoned/faulted references must live in a frame the test method no longer
    // holds when finalization is forced, or they would never become collectible.
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static async Task AbandonThenFaultAsync(string marker)
    {
        var dependency = new TaskCompletionSource<int>();
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        var act = () => dependency.Task.WaitAsyncObserved(cts.Token);
        await act.Should().ThrowAsync<OperationCanceledException>(
            "a canceled token must still bound the await");

        // The dependency ignores cancellation and faults only after abandonment.
        dependency.SetException(new Issue109MarkerException(marker));
    }

    private static readonly AsyncLocal<object?> AmbientRequestState = new();

    [Fact]
    public async Task Issue109_AbandonmentObserver_DoesNotRetainAbandoningExecutionContext()
    {
        // PR #113 review finding 1: a static ContinueWith delegate prevents a closure but
        // not ExecutionContext capture. The observer lives as long as the hung dependency
        // task, so without suppressed flow it pins the abandoning request's AsyncLocal
        // graph (HttpContext, Activity baggage, credentials) after the deadline returned.
        var hungDependency = new TaskCompletionSource<int>();
        var weakPayload = await AbandonWithAmbientPayloadAsync(hungDependency);

        for (var i = 0; i < 3; i++)
        {
            GC.Collect();
            GC.WaitForPendingFinalizers();
            GC.Collect();
        }

        weakPayload.IsAlive.Should().BeFalse(
            "the abandonment observer must not retain the abandoning request's ambient " +
            "state while the dependency task is still hung");

        // Rooted through the whole probe: the retention must be gone WHILE the source
        // task is still alive and pending, not because the task itself was collected.
        hungDependency.SetResult(0);
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static async Task<WeakReference> AbandonWithAmbientPayloadAsync(
        TaskCompletionSource<int> hungDependency)
    {
        var payload = new byte[1024 * 1024];
        var weak = new WeakReference(payload);
        AmbientRequestState.Value = payload;
        try
        {
            using var cts = new CancellationTokenSource();
            cts.Cancel();
            var act = () => hungDependency.Task.WaitAsyncObserved(cts.Token);
            await act.Should().ThrowAsync<OperationCanceledException>();
            return weak;
        }
        finally
        {
            AmbientRequestState.Value = null;
        }
    }

    [Fact]
    public async Task Issue109_PendingCancellationMonitor_DoesNotRetainRegistrationExecutionContext()
    {
        // Review round 4: the earlier retention test pre-canceled its token, so the
        // bounded-task monitor ran synchronously and only pinned the persistent source
        // observer. Keep both source and bounded wait pending and rooted to prove the
        // monitor registration itself does not capture the request ExecutionContext.
        var source = new TaskCompletionSource<int>();
        using var cts = new CancellationTokenSource();
        var (bounded, weakPayload) =
            RegisterPendingMonitorWithAmbientPayload(source.Task, cts.Token);

        for (var i = 0; i < 3; i++)
        {
            GC.Collect();
            GC.WaitForPendingFinalizers();
            GC.Collect();
        }

        weakPayload.IsAlive.Should().BeFalse(
            "the live cancellation monitor must not retain ambient request state");

        source.SetResult(7);
        (await bounded).Should().Be(7);
        GC.KeepAlive(source);
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static (Task<int> Bounded, WeakReference Payload)
        RegisterPendingMonitorWithAmbientPayload(Task<int> source, CancellationToken token)
    {
        var payload = new byte[1024 * 1024];
        var weak = new WeakReference(payload);
        AmbientRequestState.Value = payload;
        try
        {
            return (source.WaitAsyncObserved(token), weak);
        }
        finally
        {
            AmbientRequestState.Value = null;
        }
    }

    [Fact]
    public void Issue109_FreshCompletedTaskAwaits_PayNoObserverStateOverBareWaitAsync()
    {
        // PR #113 review finding 2: a completed task cannot be abandoned, so it must take
        // bare WaitAsync's same-instance fast path — no observer bookkeeping, no lock, no
        // per-await allocation. Fresh task per await is the shape that matters: the
        // in-memory signer returns a new completed task on every write, and a fresh task
        // always misses a dedupe cache. Differential against bare WaitAsync so the
        // Task.FromResult baseline cancels out.
        using var live = new CancellationTokenSource();

        static long AllocatedBy(Func<Task<int>, CancellationToken, Task<int>> boundedAwait,
            CancellationToken token)
        {
            for (var i = 0; i < 1_000; i++)
                _ = boundedAwait(Task.FromResult(i), token);
            var before = GC.GetAllocatedBytesForCurrentThread();
            for (var i = 0; i < 10_000; i++)
                _ = boundedAwait(Task.FromResult(i), token);
            return GC.GetAllocatedBytesForCurrentThread() - before;
        }

        var bare = AllocatedBy(static (t, ct) => t.WaitAsync(ct), live.Token);
        var observed = AllocatedBy(static (t, ct) => t.WaitAsyncObserved(ct), live.Token);

        (observed - bare).Should().BeLessThan(160_000,
            "10k fresh completed-task awaits must not pay per-await observer state " +
            "(the unfixed shape added ~224 B and a table insert per await)");

        var completed = Task.FromResult(42);
        ReferenceEquals(completed.WaitAsyncObserved(live.Token), completed).Should().BeTrue(
            "a completed task takes WaitAsync's same-instance fast path");
    }

    [Fact]
    public async Task Issue109_WaitAsyncObserved_PreservesBareWaitAsyncSemantics()
    {
        // Success propagates the result.
        (await Task.FromResult(7).WaitAsyncObserved(CancellationToken.None)).Should().Be(7);

        // A fault before the deadline propagates the original exception to the awaiter.
        var boom = new InvalidOperationException("boom");
        var faultedAct = () => Task.FromException<int>(boom)
            .WaitAsyncObserved(CancellationToken.None);
        (await faultedAct.Should().ThrowAsync<InvalidOperationException>())
            .Which.Should().BeSameAs(boom);

        // A pending task with a firing token surfaces cancellation, and the dependency
        // completing afterwards raises nothing.
        var pending = new TaskCompletionSource<int>();
        using var cts = new CancellationTokenSource();
        var bounded = pending.Task.WaitAsyncObserved(cts.Token);
        cts.Cancel();
        var canceledAct = () => bounded;
        await canceledAct.Should().ThrowAsync<OperationCanceledException>();
        pending.SetResult(1);

        // The deliberate already-completed-task race semantics (TransactionPipeline relies
        // on them and re-checks the token explicitly): a completed task wins over a
        // canceled token.
        using var canceled = new CancellationTokenSource();
        canceled.Cancel();
        (await Task.FromResult(42).WaitAsyncObserved(canceled.Token)).Should().Be(42);
    }

    [Fact]
    public async Task Issue109_PendingSourceFaultedWithOperationCanceledException_StaysFaulted()
    {
        // PR #113 re-review: an async wrapper that catches every OCE transforms a
        // dependency FAULT carrying OCE into wrapper CANCELLATION. Bare WaitAsync does
        // not: its task remains Faulted, retains AggregateException, and awaiting it
        // throws the original dependency exception instance.
        using var waitCts = new CancellationTokenSource();
        using var dependencyCts = new CancellationTokenSource();
        var source = new TaskCompletionSource<int>();
        var original = new OperationCanceledException(
            "dependency fault, not wait cancellation", dependencyCts.Token);

        var bare = source.Task.WaitAsync(waitCts.Token);
        var observed = source.Task.WaitAsyncObserved(waitCts.Token);
        source.SetException(original);

        (await Task.WhenAny(observed, Task.Delay(TimeSpan.FromSeconds(1))))
            .Should().BeSameAs(observed, "the bounded await must settle with its source");
        bare.Status.Should().Be(TaskStatus.Faulted);
        observed.Status.Should().Be(bare.Status);
        observed.Exception.Should().NotBeNull();
        observed.Exception!.InnerExceptions.Should().ContainSingle()
            .Which.Should().BeSameAs(original);

        var bareAct = () => bare;
        var observedAct = () => observed;
        (await bareAct.Should().ThrowAsync<OperationCanceledException>())
            .Which.Should().BeSameAs(original);
        (await observedAct.Should().ThrowAsync<OperationCanceledException>())
            .Which.Should().BeSameAs(original);
    }

    [Fact]
    public async Task Issue109_SourceSelfCancellation_PreservesTokenWithoutObserverState()
    {
        // A live wait token did not win here: the dependency canceled itself. Bare
        // WaitAsync propagates that cancellation token. The helper must do the same and
        // must not register the source as an abandoned task that could later fault.
        using var waitCts = new CancellationTokenSource();
        using var dependencyCts = new CancellationTokenSource();
        var source = new TaskCompletionSource<int>();

        var bare = source.Task.WaitAsync(waitCts.Token);
        var observed = source.Task.WaitAsyncObserved(waitCts.Token);
        source.SetCanceled(dependencyCts.Token);

        var bareAct = () => bare;
        var observedAct = () => observed;
        var bareCancellation =
            (await bareAct.Should().ThrowAsync<OperationCanceledException>()).Which;
        var observedCancellation =
            (await observedAct.Should().ThrowAsync<OperationCanceledException>()).Which;

        observed.Status.Should().Be(bare.Status);
        observed.Exception.Should().BeNull();
        observedCancellation.GetType().Should().Be(bareCancellation.GetType());
        observedCancellation.CancellationToken.Should().Be(dependencyCts.Token);
        HasAbandonmentObserver(source.Task).Should().BeFalse(
            "source self-cancellation is completion, not abandonment");
    }

    private static bool HasAbandonmentObserver(Task source)
    {
        var field = typeof(AbandonableTaskExtensions).GetField(
            "ObservedTasks", BindingFlags.Static | BindingFlags.NonPublic);
        field.Should().NotBeNull(
            "the state characterization is pinned to the helper's observer table; " +
            "update this probe if the implementation moves it");
        var table = Assert.IsType<ConditionalWeakTable<Task, object>>(field!.GetValue(null));
        return table.TryGetValue(source, out _);
    }

    [Fact]
    public async Task Issue109_CancellationMonitor_SourceFaultedBeforeCallback_ObservesRaceFault()
    {
        // The bounded wait can cancel just before the source faults. If the cancellation
        // monitor then sees an already-faulted source, bare WaitAsync no longer owns that
        // fault; the monitor must consume it directly rather than install a later observer.
        var marker = Guid.NewGuid().ToString("N");
        using var probe = new UnobservedEscalationProbe(marker);

        InvokeCancellationMonitorForAlreadyFaultedSource(marker);
        await ForceFinalizationAsync();

        probe.EscalationCount.Should().Be(0,
            "a source fault that lands before the cancellation callback must be observed");
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void InvokeCancellationMonitorForAlreadyFaultedSource(string marker)
    {
        var source = Task.FromException<int>(new Issue109MarkerException(marker));
        var callback = typeof(AbandonableTaskExtensions).GetMethod(
            "ObserveAfterBoundedCancellation", BindingFlags.Static | BindingFlags.NonPublic);
        callback.Should().NotBeNull(
            "this probe directly pins the cancellation/source-fault race branch; update " +
            "it if that branch moves");
        callback!.Invoke(null, [source]);
    }

    [Fact]
    public async Task Issue109_RepeatedAbandonedAwaitsOfOneSharedTask_AttachOneObserverStillObserved()
    {
        var marker = Guid.NewGuid().ToString("N");
        using var probe = new UnobservedEscalationProbe(marker);

        // Adversarial-review finding: WaitAsync removes its own continuation when the
        // token fires, but a ContinueWith observer is permanent — a hostile client
        // returning ONE shared forever-pending task from a retried call must not grow
        // one observer per attempt. Counted on the specific task rather than via
        // process-global heap deltas (PR #113 review finding 3: the suite runs in
        // parallel, so global memory is not a valid retention oracle).
        var observerCount = await AbandonManyTimesThenFaultAsync(marker);

        observerCount.Should().BeLessThanOrEqualTo(1,
            "repeated abandoned awaits of one shared task must not accumulate observers");

        // The helper owned the TaskCompletionSource, so the faulted task is collectible
        // here and an unobserved fault WOULD escalate — the zero assertion is probative.
        await ForceFinalizationAsync();
        probe.EscalationCount.Should().Be(0,
            "one observer per task instance is sufficient to observe its fault");
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static async Task<int> AbandonManyTimesThenFaultAsync(string marker)
    {
        var shared = new TaskCompletionSource<int>();
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        for (var i = 0; i < 10_000; i++)
        {
            try
            {
                _ = await shared.Task.WaitAsyncObserved(cts.Token);
            }
            catch (OperationCanceledException)
            {
            }
        }

        var count = RegisteredContinuationCount(shared.Task);
        shared.SetException(new Issue109MarkerException(marker));
        return count;
    }

    /// <summary>
    /// Counts continuations registered on <paramref name="task"/> via the BCL-internal
    /// continuation slot (pinned to .NET 10; fails loudly if the field moves). Canceled
    /// WaitAsync proxies remove their own registrations, so what remains is observer state.
    /// </summary>
    private static int RegisteredContinuationCount(Task task)
    {
        var field = typeof(Task).GetField(
            "m_continuationObject", BindingFlags.Instance | BindingFlags.NonPublic);
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

    // ── End-to-end: the write path's abandonment sites ───────────────────────

    [Fact]
    public async Task Issue109_UpdateReceiptPollFaultingAfterAbandonment_NoEscalation_EvidenceIntact()
    {
        var marker = Guid.NewGuid().ToString("N");
        using var probe = new UnobservedEscalationProbe(marker);
        var chain = new EmulatedEthereumChain(Registry);
        var owner = NewActor();
        using var cts = new CancellationTokenSource();
        var abandoned = new TaskCompletionSource();

        // The issue's probe: a receipt poll that ignores the token, is abandoned by the
        // caller's cancellation, and faults afterwards.
        var client = new TokenIgnoringRpcClient(chain)
        {
            ReceiptFactory = () =>
            {
                cts.Cancel();
                return FaultAfterAsync<EthereumTransactionReceipt?>(abandoned.Task, marker);
            },
        };

        var act = () => MethodFor(client).UpdateAsync(
            $"did:ethr:sepolia:{owner.Address}",
            new DidEthrUpdateOptions { ControllerKey = owner.Signer, AddServices = [Svc()] },
            cts.Token);

        var thrown = (await act.Should().ThrowAsync<OperationCanceledException>()).Which;

        // Acceptance criterion: the evidence contract is unchanged on the abandonment path.
        Confirmed(thrown).Should().BeEmpty("no receipt was observed");
        InFlight(thrown).Should().ContainSingle().Which.Should().MatchRegex("^0x[0-9a-f]{64}$");

        abandoned.SetResult();
        await ForceFinalizationAsync();
        probe.EscalationCount.Should().Be(0,
            "an abandoned receipt poll that faults later must be observed, not escalated");
    }

    [Fact]
    public async Task Issue109_UpdateOwnerPreflightFaultingAfterAbandonment_NoEscalation()
    {
        var marker = Guid.NewGuid().ToString("N");
        using var probe = new UnobservedEscalationProbe(marker);
        var chain = new EmulatedEthereumChain(Registry);
        var owner = NewActor();
        using var cts = new CancellationTokenSource();
        var abandoned = new TaskCompletionSource();

        // Covers the DidEthrMethod sites: the identityOwner pre-flight eth_call is the
        // first dependency await on the update path.
        var client = new TokenIgnoringRpcClient(chain)
        {
            FirstCallFactory = () =>
            {
                cts.Cancel();
                return FaultAfterAsync<string>(abandoned.Task, marker);
            },
        };

        var act = () => MethodFor(client).UpdateAsync(
            $"did:ethr:sepolia:{owner.Address}",
            new DidEthrUpdateOptions { ControllerKey = owner.Signer, AddServices = [Svc()] },
            cts.Token);

        await act.Should().ThrowAsync<OperationCanceledException>(
            "caller cancellation keeps its type");

        abandoned.SetResult();
        await ForceFinalizationAsync();
        probe.EscalationCount.Should().Be(0);
    }

    [Fact]
    public async Task Issue109_DeployChainIdFaultingAfterAbandonment_NoEscalation()
    {
        var marker = Guid.NewGuid().ToString("N");
        using var probe = new UnobservedEscalationProbe(marker);
        var chain = new EmulatedEthereumChain(Registry);
        var deployer = NewActor();
        using var cts = new CancellationTokenSource();
        var abandoned = new TaskCompletionSource();

        // Covers the Erc1056Registry.DeployAsync site — the same defect class, even though
        // the issue only names TransactionPipeline and DidEthrMethod.
        var client = new TokenIgnoringRpcClient(chain)
        {
            ChainIdFactory = () =>
            {
                cts.Cancel();
                return FaultAfterAsync<ulong>(abandoned.Task, marker);
            },
        };

        var act = () => Erc1056Registry.DeployAsync(
            client, deployer.Signer, chainId: 11155111, ct: cts.Token);

        await act.Should().ThrowAsync<OperationCanceledException>();

        abandoned.SetResult();
        await ForceFinalizationAsync();
        probe.EscalationCount.Should().Be(0);
    }

    [Fact]
    public async Task Issue109_TokenIgnoringHangingReceipt_StillCannotOutliveWriteDeadline()
    {
        var chain = new EmulatedEthereumChain(Registry);
        var owner = NewActor();
        // Never completes and never looks at the token — the strongest token-ignoring
        // client. Held by the closure so it neither faults nor finalizes.
        var hung = new TaskCompletionSource<EthereumTransactionReceipt?>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var client = new TokenIgnoringRpcClient(chain) { ReceiptFactory = () => hung.Task };
        var method = MethodFor(client);
        method.WriteDeadline = TimeSpan.FromMilliseconds(250);

        var act = () => method.UpdateAsync(
            $"did:ethr:sepolia:{owner.Address}",
            new DidEthrUpdateOptions { ControllerKey = owner.Signer, AddServices = [Svc()] });

        var thrown = (await act.Should().ThrowAsync<EthereumInteractionException>()).Which;

        thrown.Message.Should().Contain("deadline");
        Confirmed(thrown).Should().BeEmpty();
        InFlight(thrown).Should().ContainSingle();
    }

    // ── Class guard ──────────────────────────────────────────────────────────

    [Theory]
    [InlineData("await dependency.WaitAsync\n    (ct);")]
    [InlineData("await dependency.WaitAsync /* block comment */ (ct);")]
    [InlineData("await dependency.WaitAsync // line comment\n    (ct);")]
    public void Issue109_SourceGuard_DetectsBareWaitAsyncAcrossTrivia(string source)
    {
        FindBareWaitAsyncCalls("Synthetic.cs", source).Should().ContainSingle(
            "legal whitespace or comment trivia must not hide a bare dependency wait");
    }

    [Theory]
    [InlineData("// await dependency.WaitAsync(ct);")]
    [InlineData("var text = \".WaitAsync(ct)\";")]
    [InlineData("var text = @\".WaitAsync(ct)\";")]
    [InlineData("var text = \"\"\".WaitAsync(ct)\"\"\";")]
    public void Issue109_SourceGuard_IgnoresCommentsAndStringLiterals(string source)
    {
        FindBareWaitAsyncCalls("Synthetic.cs", source).Should().BeEmpty(
            "comments and string contents are not executable invocations");
        CountInvocations(source, "WaitAsyncObserved").Should().Be(0,
            "comments and strings must not spoof the positive inventory");
    }

    [Fact]
    public void Issue109_DeadlineBoundedAwaitInventory_NoBareSitesAndCountsPinned()
    {
        // A bare .WaitAsync( on a dependency task reintroduces the abandonment leak, and
        // DELETING a WaitAsyncObserved wrapper silently un-bounds an await — so pin both
        // directions: zero bare sites AND the exact per-file observed-call inventory
        // (update the counts when a dependency await is legitimately added or removed).
        // Walked from the repo checkout; passes vacuously when the sources are not
        // present (packaged test run) — but never on CI, where a silent disarm would be
        // indistinguishable from a real scan.
        var root = FindRepositoryRoot();
        if (root is null)
        {
            Environment.GetEnvironmentVariable("CI").Should().BeNullOrEmpty(
                "the source guard must not silently disarm on CI");
            return;
        }

        var sources = Directory
            .EnumerateFiles(Path.Combine(root, "src", "NetDid.Method.Ethr"), "*.cs",
                SearchOption.AllDirectories)
            .Where(f => !f.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}")
                && !f.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}")
                && Path.GetFileName(f) != "AbandonableTaskExtensions.cs")
            .Select(f => (
                Path: Path.GetRelativePath(root, f).Replace('\\', '/'),
                Source: File.ReadAllText(f)))
            .ToList();

        var offenders = sources
            .SelectMany(s => FindBareWaitAsyncCalls(s.Path, s.Source))
            .ToList();
        offenders.Should().BeEmpty(
            "every deadline-bounded await must observe abandonment via WaitAsyncObserved");

        var inventory = sources
            .Select(s => (s.Path, Count: CountInvocations(s.Source, "WaitAsyncObserved")))
            .Where(s => s.Count > 0)
            .ToDictionary(s => s.Path, s => s.Count);
        inventory.Should().Equal(new Dictionary<string, int>
        {
            // 9th site added by issue #116: the resolution deadline binds the returned
            // ResolveFromChainAsync task, so a cancellation-ignoring RPC client cannot
            // hang resolution.
            ["src/NetDid.Method.Ethr/DidEthrMethod.cs"] = 9,
            ["src/NetDid.Method.Ethr/Transactions/TransactionPipeline.cs"] = 6,
            ["src/NetDid.Method.Ethr/Deployment/Erc1056Registry.cs"] = 1,
        }, "removing a WaitAsyncObserved wrapper un-bounds a dependency await; update " +
           "this inventory only for a deliberate call-site change");
    }

    private static IReadOnlyList<string> FindBareWaitAsyncCalls(string path, string source)
        => InvocationsNamed(source, "WaitAsync")
            .Select(invocation =>
                $"{path}:{invocation.GetLocation().GetLineSpan().StartLinePosition.Line + 1}")
            .ToList();

    private static int CountInvocations(string source, string methodName)
        => InvocationsNamed(source, methodName).Count();

    private static IEnumerable<InvocationExpressionSyntax> InvocationsNamed(
        string source, string methodName)
        => CSharpSyntaxTree
            .ParseText(source)
            .GetRoot()
            .DescendantNodes()
            .OfType<InvocationExpressionSyntax>()
            .Where(invocation => InvokedMethodName(invocation.Expression) == methodName);

    private static string? InvokedMethodName(ExpressionSyntax expression)
        => expression switch
        {
            MemberAccessExpressionSyntax member => member.Name.Identifier.ValueText,
            MemberBindingExpressionSyntax binding => binding.Name.Identifier.ValueText,
            IdentifierNameSyntax identifier => identifier.Identifier.ValueText,
            _ => null,
        };

    private static string? FindRepositoryRoot()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
            if (File.Exists(Path.Combine(dir.FullName, "netdid.sln")))
                return dir.FullName;
        return null;
    }

    // ── Harness ──────────────────────────────────────────────────────────────

    /// <summary>Faults with the marker only after the abandonment signal completes.</summary>
    private static async Task<T> FaultAfterAsync<T>(Task abandonedSignal, string marker)
    {
        await abandonedSignal.ConfigureAwait(false);
        throw new Issue109MarkerException(marker);
    }

    private static async Task ForceFinalizationAsync()
    {
        // Give the just-signaled dependency continuation a beat to transition to Faulted,
        // then force the unobserved-exception holders through finalization.
        await Task.Delay(50);
        for (var i = 0; i < 3; i++)
        {
            GC.Collect();
            GC.WaitForPendingFinalizers();
            GC.Collect();
        }
    }

    private sealed class Issue109MarkerException(string marker) : Exception(marker);

    /// <summary>
    /// Counts only escalations carrying this test's marker: the event is process-global and
    /// the suite runs in parallel, so anything else is another test's business.
    /// </summary>
    private sealed class UnobservedEscalationProbe : IDisposable
    {
        private readonly string _marker;
        private readonly EventHandler<UnobservedTaskExceptionEventArgs> _handler;
        private int _count;

        public UnobservedEscalationProbe(string marker)
        {
            _marker = marker;
            _handler = (_, args) =>
            {
                if (args.Exception.Flatten().InnerExceptions
                    .Any(e => e is Issue109MarkerException m && m.Message == _marker))
                {
                    args.SetObserved();
                    Interlocked.Increment(ref _count);
                }
            };
            TaskScheduler.UnobservedTaskException += _handler;
        }

        public int EscalationCount => Volatile.Read(ref _count);

        public void Dispose() => TaskScheduler.UnobservedTaskException -= _handler;
    }

    /// <summary>
    /// Delegates to the emulated chain except where a test injects a token-ignoring,
    /// abandonment-faulting dependency task.
    /// </summary>
    private sealed class TokenIgnoringRpcClient(EmulatedEthereumChain inner) : IEthereumRpcClient
    {
        public Func<Task<EthereumTransactionReceipt?>>? ReceiptFactory { get; init; }
        public Func<Task<string>>? FirstCallFactory { get; init; }
        public Func<Task<ulong>>? ChainIdFactory { get; init; }

        private int _callCount;

        public Task<string> CallAsync(string to, string data, CancellationToken ct = default)
            => FirstCallFactory is not null && Interlocked.Increment(ref _callCount) == 1
                ? FirstCallFactory()
                : inner.CallAsync(to, data, ct);

        public Task<ulong> GetChainIdAsync(CancellationToken ct = default)
            => ChainIdFactory is not null ? ChainIdFactory() : inner.GetChainIdAsync(ct);

        public Task<EthereumTransactionReceipt?> GetTransactionReceiptAsync(
            string transactionHash, CancellationToken ct = default)
            => ReceiptFactory is not null
                ? ReceiptFactory()
                : inner.GetTransactionReceiptAsync(transactionHash, ct);

        public Task<IReadOnlyList<EthereumLogEntry>> GetLogsAsync(
            EthereumLogFilter filter, CancellationToken ct = default)
            => inner.GetLogsAsync(filter, ct);
        public Task<ulong> GetBlockNumberAsync(CancellationToken ct = default)
            => inner.GetBlockNumberAsync(ct);
        public Task<ulong> GetBlockTimestampAsync(ulong blockNumber, CancellationToken ct = default)
            => inner.GetBlockTimestampAsync(blockNumber, ct);
        public Task<string> SendRawTransactionAsync(
            byte[] signedTransaction, CancellationToken ct = default)
            => inner.SendRawTransactionAsync(signedTransaction, ct);
        public Task<ulong> GetTransactionCountAsync(string address, CancellationToken ct = default)
            => inner.GetTransactionCountAsync(address, ct);
        public Task<ulong> GetGasPriceAsync(CancellationToken ct = default)
            => inner.GetGasPriceAsync(ct);
        public Task<ulong> EstimateGasAsync(
            string from, string? to, string data, CancellationToken ct = default)
            => inner.EstimateGasAsync(from, to, data, ct);
    }
}
