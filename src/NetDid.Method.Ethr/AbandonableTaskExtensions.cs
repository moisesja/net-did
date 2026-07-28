using System.Runtime.CompilerServices;

namespace NetDid.Method.Ethr;

/// <summary>
/// Deadline-bounding for awaits on dependency-produced tasks (RPC clients, signers).
/// <see cref="Task.WaitAsync(CancellationToken)"/> abandons the underlying task rather
/// than cancelling it; if the abandoned task later faults, nothing awaits the exception
/// and the finalizer raises <see cref="TaskScheduler.UnobservedTaskException"/> in the
/// host — telemetry noise at best, a process kill under
/// <c>ThrowUnobservedTaskExceptions</c>. Every <c>WaitAsync</c> in this library goes
/// through <see cref="WaitAsyncObserved{T}"/>, which observes the orphan's fault when
/// cancellation actually abandons it.
/// </summary>
internal static class AbandonableTaskExtensions
{
    // Unlike WaitAsync — which removes its own continuation when the token fires — a
    // ContinueWith observer is permanent for the source task's lifetime. A hostile
    // dependency returning one shared forever-pending task from a retried call would
    // grow one continuation per attempt, so register at most one observer per task
    // instance. Reference-identity keyed; the entry dies with the task.
    private static readonly ConditionalWeakTable<Task, object> ObservedTasks = [];
    private static readonly object ObservedSentinel = new();

    /// <summary>
    /// <see cref="Task.WaitAsync(CancellationToken)"/> with abandonment faults observed.
    /// Identical semantics on every non-fault path, including returning an
    /// already-completed task's result even when <paramref name="ct"/> has fired —
    /// call sites that must not proceed after cancellation re-check the token
    /// explicitly, exactly as with bare <c>WaitAsync</c>. Completed tasks and
    /// non-cancelable waits take the bare fast path. A pending cancelable wait carries
    /// a short-lived, flow-suppressed cancellation monitor; persistent source-observer
    /// state exists only when cancellation leaves the source task still pending.
    /// </summary>
    public static Task<T> WaitAsyncObserved<T>(this Task<T> task, CancellationToken ct)
    {
        // A completed task or a token that can never fire cannot be abandoned. This is
        // also the same-instance fast path that preserves the deliberate
        // completed-task-beats-canceled-token race semantics.
        if (!ct.CanBeCanceled || task.IsCompleted)
            return task.WaitAsync(ct);

        // Return WaitAsync's task unchanged. In particular, a dependency fault carrying
        // OperationCanceledException must remain a Faulted task with a non-null
        // AggregateException; an async catch/rethrow wrapper would turn it into Canceled.
        var bounded = task.WaitAsync(ct);
        MonitorCancellation(task, bounded);
        return bounded;
    }

    private static void MonitorCancellation(Task source, Task bounded)
    {
        // The monitor is attached to the bounded task, not the source: OnlyOnCanceled
        // therefore runs precisely when bare WaitAsync reports cancellation. Suppress
        // flow because even this short-lived continuation must not retain an ambient
        // request graph while a hostile dependency ignores cancellation.
        var suppress = !ExecutionContext.IsFlowSuppressed();
        var flow = suppress ? ExecutionContext.SuppressFlow() : default;
        try
        {
            _ = bounded.ContinueWith(
                static (_, state) => ObserveAfterBoundedCancellation((Task)state!),
                source,
                CancellationToken.None,
                TaskContinuationOptions.OnlyOnCanceled |
                TaskContinuationOptions.ExecuteSynchronously,
                TaskScheduler.Default);
        }
        finally
        {
            if (suppress)
                flow.Undo();
        }
    }

    private static void ObserveAfterBoundedCancellation(Task source)
    {
        if (!source.IsCompleted)
        {
            // Wait-token cancellation won while the source was still pending. Attach
            // one source observer so a later fault cannot escalate in the host.
            ObserveFaultOf(source);
        }
        else if (source.IsFaulted)
        {
            // The wait token won the bounded-task race, but the source faulted before
            // this monitor ran. Bare WaitAsync no longer owns that fault, so consume it
            // directly. Success and source self-cancellation need no observer.
            _ = source.Exception;
        }
    }

    private static void ObserveFaultOf(Task source)
    {
        // TryGetValue first: it is lock-free, while TryAdd locks the table even on a
        // dedupe hit. TryAdd still closes the two-registrant race.
        if (ObservedTasks.TryGetValue(source, out _) || !ObservedTasks.TryAdd(source, ObservedSentinel))
            return;

        // ContinueWith captures the current ExecutionContext even with a static
        // delegate, and the observer lives as long as the hung task — unsuppressed, it
        // would pin the abandoning request's AsyncLocal graph (HttpContext, Activity
        // baggage, scoped state) for as long as the dependency ignores the token.
        var suppress = !ExecutionContext.IsFlowSuppressed();
        var flow = suppress ? ExecutionContext.SuppressFlow() : default;
        try
        {
            // OnlyOnFaulted: on success or cancellation the continuation is itself
            // canceled, and canceled tasks never raise UnobservedTaskException.
            // CancellationToken.None: the observer must outlive every caller token.
            _ = source.ContinueWith(
                static t => _ = t.Exception,
                CancellationToken.None,
                TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously,
                TaskScheduler.Default);
        }
        finally
        {
            if (suppress)
                flow.Undo();
        }
    }
}
