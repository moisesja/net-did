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
    /// explicitly, exactly as with bare <c>WaitAsync</c>. Observer state exists only
    /// once cancellation actually abandons a still-pending task; completed tasks and
    /// normally completing awaits pay nothing.
    /// </summary>
    public static Task<T> WaitAsyncObserved<T>(this Task<T> task, CancellationToken ct)
    {
        // A completed task or a token that can never fire cannot be abandoned. This is
        // also the same-instance fast path that preserves the deliberate
        // completed-task-beats-canceled-token race semantics.
        if (!ct.CanBeCanceled || task.IsCompleted)
            return task.WaitAsync(ct);
        return AwaitObservingAbandonment(task, task.WaitAsync(ct));
    }

    private static async Task<T> AwaitObservingAbandonment<T>(Task<T> source, Task<T> bounded)
    {
        try
        {
            return await bounded.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // Cancellation is the only path on which WaitAsync detaches from a
            // still-pending source. Attach the observer now, while this frame still
            // roots the source, so a fault raised after abandonment is observed
            // rather than escalated. If the source completed in the race anyway,
            // OnlyOnFaulted resolves immediately and harmlessly.
            ObserveFaultOf(source);
            throw;
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
