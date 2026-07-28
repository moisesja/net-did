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
    /// <summary>
    /// <see cref="Task.WaitAsync(CancellationToken)"/> with the abandonment fault
    /// observed. Identical semantics on every non-fault path, including returning an
    /// already-completed task's result even when <paramref name="ct"/> has fired —
    /// call sites that must not proceed after cancellation re-check the token
    /// explicitly, exactly as with bare <c>WaitAsync</c>.
    /// </summary>
    public static Task<T> WaitAsyncObserved<T>(this Task<T> task, CancellationToken ct)
    {
        // OnlyOnFaulted: on success or cancellation the continuation is itself
        // canceled, and canceled tasks never raise UnobservedTaskException.
        // CancellationToken.None: the observer must outlive every caller token.
        _ = task.ContinueWith(
            static t => _ = t.Exception,
            CancellationToken.None,
            TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously,
            TaskScheduler.Default);
        return task.WaitAsync(ct);
    }
}
