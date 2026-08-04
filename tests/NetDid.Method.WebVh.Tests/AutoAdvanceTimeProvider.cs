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
    private long _timestamp;

    public AutoAdvanceTimeProvider(DateTimeOffset start) => _utcNow = start.ToUniversalTime();

    public override DateTimeOffset GetUtcNow() => _utcNow;
    public override long GetTimestamp() => _timestamp;
    public override long TimestampFrequency => TimeSpan.TicksPerSecond;

    public override ITimer CreateTimer(
        TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
    {
        if (dueTime > TimeSpan.Zero)
        {
            _utcNow += dueTime;
            _timestamp += dueTime.Ticks;
        }
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

/// <summary>
/// UTC remains frozen while monotonic elapsed time advances. The timer-count guard makes an
/// unbounded retry loop fail quickly instead of wedging the test process.
/// </summary>
internal sealed class FrozenUtcTimeProvider : TimeProvider
{
    private readonly DateTimeOffset _utcNow;
    private readonly int _maximumTimerCount;
    private long _timestamp;
    private int _timerCount;

    public FrozenUtcTimeProvider(DateTimeOffset start, int maximumTimerCount = 2)
    {
        _utcNow = start.ToUniversalTime();
        _maximumTimerCount = maximumTimerCount;
    }

    public override DateTimeOffset GetUtcNow() => _utcNow;
    public override long GetTimestamp() => _timestamp;
    public override long TimestampFrequency => TimeSpan.TicksPerSecond;

    public override ITimer CreateTimer(
        TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
    {
        if (++_timerCount > _maximumTimerCount)
            throw new InvalidOperationException("The UTC-stalled wait exceeded its aggregate budget.");

        if (dueTime > TimeSpan.Zero)
            _timestamp += dueTime.Ticks;
        callback(state);
        return new TestTimer();
    }
}

/// <summary>
/// The first delay advances monotonic time but moves UTC backward by 500 ms. Later delays advance
/// UTC normally, allowing the pre-fix per-iteration budget to succeed after exceeding two seconds.
/// </summary>
internal sealed class BackwardStepTimeProvider : TimeProvider
{
    private DateTimeOffset _utcNow;
    private long _timestamp;
    private int _timerCount;

    public BackwardStepTimeProvider(DateTimeOffset start) => _utcNow = start.ToUniversalTime();

    public override DateTimeOffset GetUtcNow() => _utcNow;
    public override long GetTimestamp() => _timestamp;
    public override long TimestampFrequency => TimeSpan.TicksPerSecond;

    public override ITimer CreateTimer(
        TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
    {
        if (dueTime > TimeSpan.Zero)
        {
            _timestamp += dueTime.Ticks;
            _utcNow = ++_timerCount == 1
                ? _utcNow.AddMilliseconds(-500)
                : _utcNow + dueTime;
        }

        callback(state);
        return new TestTimer();
    }
}

/// <summary>
/// UTC reaches the requested target, but the monotonic clock records a three-second timer
/// oversleep. This models process suspension or thread-pool starvation after a timer is armed.
/// </summary>
internal sealed class OversleptTimerTimeProvider : TimeProvider
{
    private DateTimeOffset _utcNow;
    private long _timestamp;

    public OversleptTimerTimeProvider(DateTimeOffset start) => _utcNow = start.ToUniversalTime();

    public override DateTimeOffset GetUtcNow() => _utcNow;
    public override long GetTimestamp() => _timestamp;
    public override long TimestampFrequency => TimeSpan.TicksPerSecond;

    public override ITimer CreateTimer(
        TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
    {
        if (dueTime > TimeSpan.Zero)
        {
            _utcNow += dueTime;
            _timestamp += TimeSpan.FromSeconds(3).Ticks;
        }

        callback(state);
        return new TestTimer();
    }
}

/// <summary>A clock whose delay never fires, used to prove caller cancellation propagation.</summary>
internal sealed class NonFiringTimeProvider : TimeProvider
{
    private readonly DateTimeOffset _utcNow;

    public NonFiringTimeProvider(DateTimeOffset start) => _utcNow = start.ToUniversalTime();

    public Task TimerCreated => _timerCreated.Task;

    private readonly TaskCompletionSource _timerCreated =
        new(TaskCreationOptions.RunContinuationsAsynchronously);

    public override DateTimeOffset GetUtcNow() => _utcNow;
    public override long GetTimestamp() => 0;
    public override long TimestampFrequency => TimeSpan.TicksPerSecond;

    public override ITimer CreateTimer(
        TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
    {
        _timerCreated.TrySetResult();
        return new TestTimer();
    }
}

internal sealed class TestTimer : ITimer
{
    public bool Change(TimeSpan dueTime, TimeSpan period) => true;
    public void Dispose()
    {
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;
}
