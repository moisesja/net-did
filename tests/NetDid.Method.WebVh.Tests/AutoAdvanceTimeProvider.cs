namespace NetDid.Method.WebVh.Tests;

/// <summary>
/// Deterministic authoring clock: time stands still until something awaits a delay against
/// it, at which point the clock jumps forward by exactly the requested amount and the timer
/// fires synchronously. This makes the bounded same-second wait in
/// <c>DidWebVhMethod.GetNextVersionTimeAsync</c> instant and exact in tests, so whole-second
/// boundary cases can be pinned without real sleeps or wall-clock races.
/// </summary>
internal sealed class AutoAdvanceTimeProvider : TimeProvider
{
    private DateTimeOffset _utcNow;

    public AutoAdvanceTimeProvider(DateTimeOffset start) => _utcNow = start.ToUniversalTime();

    public override DateTimeOffset GetUtcNow() => _utcNow;

    public override ITimer CreateTimer(
        TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
    {
        if (dueTime > TimeSpan.Zero)
            _utcNow += dueTime;
        callback(state);
        return new FiredTimer();
    }

    private sealed class FiredTimer : ITimer
    {
        public bool Change(TimeSpan dueTime, TimeSpan period) => true;
        public void Dispose()
        {
        }

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
