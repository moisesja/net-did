using System.Runtime.CompilerServices;

namespace NetDid.Method.Ethr;

/// <summary>
/// Deadline-bounding for awaits on dependency-produced tasks (RPC clients, signers).
/// <see cref="Task.WaitAsync(CancellationToken)"/> abandons the underlying task rather
/// than cancelling it; if the abandoned task later faults, nothing awaits the exception
/// and the finalizer raises <see cref="TaskScheduler.UnobservedTaskException"/> in the
/// host — telemetry noise at best, a process kill under
/// <c>ThrowUnobservedTaskExceptions</c>. Every <c>WaitAsync</c> in this library goes
/// through <see cref="WaitAsyncObserved{T}"/>, which attaches a fault observer before
/// abandoning.
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
    /// <see cref="Task.WaitAsync(CancellationToken)"/> with the abandonment fault
    /// observed. Identical semantics on every non-fault path, including returning an
    /// already-completed task's result even when <paramref name="ct"/> has fired —
    /// call sites that must not proceed after cancellation re-check the token
    /// explicitly, exactly as with bare <c>WaitAsync</c>.
    /// </summary>
    public static Task<T> WaitAsyncObserved<T>(this Task<T> task, CancellationToken ct)
    {
        // A token that can never fire cannot abandon: WaitAsync returns the task
        // itself and the call site's await observes any fault directly.
        if (ct.CanBeCanceled && ObservedTasks.TryAdd(task, ObservedSentinel))
        {
            // OnlyOnFaulted: on success or cancellation the continuation is itself
            // canceled, and canceled tasks never raise UnobservedTaskException.
            // CancellationToken.None: the observer must outlive every caller token.
            _ = task.ContinueWith(
                static t => _ = t.Exception,
                CancellationToken.None,
                TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously,
                TaskScheduler.Default);
        }
        return task.WaitAsync(ct);
    }
}
