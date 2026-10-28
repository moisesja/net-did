using System.Text;
using AwesomeAssertions;
using NetCrypto;
using NetDid.Core.Exceptions;
using NetDid.Core.Model;
using NetDid.Method.WebVh.Model;

namespace NetDid.Method.WebVh.Tests;

/// <summary>
/// Issue #131: did:webvh v1.0 Read (Resolve) step 4 — "The <c>versionTime</c> of every entry
/// MUST NOT be more than a small, implementation-defined tolerance in the future relative to
/// the resolver's current time. Resolvers SHOULD use a tolerance of no more than 5 minutes.
/// Entries that exceed this tolerance MUST cause resolution to fail." NetDid uses exactly
/// 5 minutes, inclusive. Every fixture is authored and resolved on injected clocks at fixed
/// instants, so no assertion depends on the wall clock.
/// </summary>
public sealed class Issue131VersionTimeFutureSkewTests
{
    private static readonly DateTimeOffset T0 = new(2026, 7, 10, 12, 0, 0, TimeSpan.Zero);

    #region Issue #131

    [Theory]
    [InlineData(0, true)]
    [InlineData(299, true)]
    [InlineData(300, true)]   // exactly at the tolerance: "MUST NOT be MORE than"
    [InlineData(301, false)]  // smallest authorable step beyond it (whole-second versionTime)
    [InlineData(3600, false)]
    public async Task Issue131_ResolveLatest_LaterEntryAheadOfResolverClock_FailsBeyondFiveMinutes(
        int headAheadSeconds, bool accepted)
    {
        var head = T0.AddMinutes(10);
        var fixture = await AuthorAsync(T0, [head]);

        var result = await ResolveAsync(fixture, head.AddSeconds(-headAheadSeconds));

        if (accepted)
        {
            result.ResolutionMetadata.Error.Should().BeNull();
            result.DidDocument.Should().NotBeNull();
            result.DocumentMetadata!.VersionId.Should().Be(fixture.Entries[1].VersionId);
        }
        else
        {
            ShouldBeInvalidDidLog(result);
        }
    }

    [Theory]
    [InlineData(300, true)]
    [InlineData(301, false)]
    public async Task Issue131_ResolveLatest_GenesisAheadOfResolverClock_FailsBeyondFiveMinutes(
        int genesisAheadSeconds, bool accepted)
    {
        var fixture = await AuthorAsync(T0, []);

        var result = await ResolveAsync(fixture, T0.AddSeconds(-genesisAheadSeconds));

        if (accepted)
            result.DidDocument.Should().NotBeNull();
        else
            ShouldBeInvalidDidLog(result);
    }

    [Fact]
    public async Task Issue131_FarFutureEntriesAndExtremeClocks_AreRejectedWithoutOverflow()
    {
        // Year-9999 genesis: the comparison must not overflow, and must still map to
        // invalidDidLog (an escaped OverflowException would surface as a different error).
        var farFuture = new DateTimeOffset(9999, 12, 31, 23, 59, 59, TimeSpan.Zero);
        var farFutureLog = await AuthorAsync(farFuture, []);

        ShouldBeInvalidDidLog(await ResolveAsync(farFutureLog, T0));
        ShouldBeInvalidDidLog(await ResolveAsync(farFutureLog, DateTimeOffset.MinValue));

        // The opposite extreme: a resolver clock at the end of time accepts an ordinary log.
        var ordinaryLog = await AuthorAsync(T0, []);
        (await ResolveAsync(ordinaryLog, DateTimeOffset.MaxValue)).DidDocument.Should().NotBeNull();
    }

    [Fact]
    public async Task Issue131_ValidateChainWithoutExplicitTime_UsesSystemClockAndRejectsFarFuture()
    {
        var farFuture = new DateTimeOffset(9999, 12, 31, 23, 59, 59, TimeSpan.Zero);
        var fixture = await AuthorAsync(farFuture, []);

        var act = () => new LogChainValidator().ValidateChainAsync(fixture.Entries);

        await act.Should().ThrowAsync<LogChainValidationException>()
            .WithMessage("*version 1 is more than 5 minutes ahead*");
    }

    [Theory]
    [InlineData(1)]   // both later entries are future-dated
    [InlineData(12)]  // only the deactivation entry is future-dated
    public async Task Issue131_HistoricalResolution_FutureDatedTail_ReturnsValidPrefixWithoutDeactivation(
        int resolverMinutesAfterGenesis)
    {
        // did:webvh v1.0 Read steps 10-11.2: a versionId that references a valid entry is
        // returned "even if later entries in the log are invalid". A future-dated tail is such
        // an invalid tail: it fails latest resolution, but neither revokes the earlier version
        // nor gets to assert deactivation over it.
        var fixture = await AuthorAsync(T0, [T0.AddMinutes(10)], deactivateAt: T0.AddMinutes(20));
        var resolverNow = T0.AddMinutes(resolverMinutesAfterGenesis);

        ShouldBeInvalidDidLog(await ResolveAsync(fixture, resolverNow));

        var historical = await ResolveAsync(fixture, resolverNow, new DidResolutionOptions
        {
            VersionId = fixture.Entries[0].VersionId,
            IncludeLog = true
        });

        historical.ResolutionMetadata.Error.Should().BeNull();
        historical.DidDocument.Should().NotBeNull();
        historical.DocumentMetadata!.VersionId.Should().Be(fixture.Entries[0].VersionId);
        historical.DocumentMetadata.Deactivated.Should().NotBe(true,
            "an unverifiable (future-dated) deactivation tail must not be asserted");
        ((IReadOnlyList<LogEntry>)historical.Artifacts![DidWebVhArtifacts.LogEntries])
            .Should().HaveCount(1, "only the validated prefix is resolution evidence");
    }

    [Fact]
    public async Task Issue131_HistoricalResolution_TailWithinTolerance_StillAssertsDeactivation()
    {
        // Control for the test above: once the resolver clock reaches the tail, the same
        // historical resolution reports the verified deactivation.
        var fixture = await AuthorAsync(T0, [T0.AddMinutes(10)], deactivateAt: T0.AddMinutes(20));

        var historical = await ResolveAsync(fixture, T0.AddMinutes(20), new DidResolutionOptions
        {
            VersionId = fixture.Entries[0].VersionId
        });

        historical.DidDocument.Should().NotBeNull();
        historical.DocumentMetadata!.Deactivated.Should().BeTrue();
    }

    [Fact]
    public async Task Issue131_VersionTimeQuery_SelectingFutureEntry_FailsWhileEarlierSelectionSucceeds()
    {
        var future = T0.AddMinutes(10);
        var fixture = await AuthorAsync(T0, [future]);
        var resolverNow = T0.AddMinutes(1);

        var earlier = await ResolveAsync(fixture, resolverNow, new DidResolutionOptions
        {
            VersionTime = WebVhTimestamp.Format(T0.AddSeconds(30))
        });
        earlier.DidDocument.Should().NotBeNull();
        earlier.DocumentMetadata!.VersionId.Should().Be(fixture.Entries[0].VersionId);

        var selectsFuture = await ResolveAsync(fixture, resolverNow, new DidResolutionOptions
        {
            VersionTime = WebVhTimestamp.Format(future)
        });
        ShouldBeInvalidDidLog(selectsFuture);
    }

    [Fact]
    public async Task Issue131_ResolutionReadsTheResolverClockExactlyOnce_AcrossPrefixAndTailPasses()
    {
        // A historical target below a deactivated tail runs two chain-validation passes. Both
        // must judge "the future" against ONE observation, or a clock step between them could
        // accept an entry in the prefix pass and reject the same entry in the tail pass.
        var fixture = await AuthorAsync(T0, [T0.AddMinutes(10)], deactivateAt: T0.AddMinutes(20));
        var clock = new ManualTimeProvider(T0.AddMinutes(30));

        var historical = await ResolveAsync(fixture, clock, new DidResolutionOptions
        {
            VersionId = fixture.Entries[0].VersionId
        });

        historical.DocumentMetadata!.Deactivated.Should().BeTrue("both passes ran");
        clock.UtcNowReads.Should().Be(1);
    }

    [Fact]
    public async Task Issue131_AllOperations_JudgeTheFutureByTheInjectedClock()
    {
        // A log dated 2030 is "the future" for the system clock but not for an injected clock
        // set to 2030; resolution, Update and Deactivate must all use the injected one.
        var start = new DateTimeOffset(2030, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var fixture = await AuthorAsync(start, [start.AddMinutes(1)]);
        var clock = new ManualTimeProvider(start.AddMinutes(2));

        (await ResolveAsync(fixture, clock)).DidDocument.Should().NotBeNull();

        var method = new DidWebVhMethod(new MockWebVhHttpClient()) { Clock = clock };
        var updated = await method.UpdateAsync(fixture.Did, new DidWebVhUpdateOptions
        {
            CurrentLogContent = fixture.Log,
            SigningKey = fixture.Signer
        });
        var deactivated = await method.DeactivateAsync(fixture.Did, new DidWebVhDeactivateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(
                (string)updated.Artifacts![DidWebVhArtifacts.DidJsonl]),
            SigningKey = fixture.Signer
        });
        deactivated.Artifacts.Should().ContainKey(DidWebVhArtifacts.DidJsonl);
    }

    [Theory]
    [InlineData(false, 301, true)]
    [InlineData(true, 301, true)]
    [InlineData(false, 300, false)]
    [InlineData(true, 300, false)]
    public async Task Issue131_WriteOperations_RejectSuppliedLogBeyondFiveMinutes_AsInvalidLog(
        bool deactivate, int headAheadSeconds, bool beyondTolerance)
    {
        // Update and Deactivate share the resolver's chain validation, so a supplied log the
        // resolver would reject is rejected as invalid (LogChainValidationException). A head
        // inside the tolerance is a valid log that still cannot be appended to without
        // authoring future time — that remains the #127 honest-failure ArgumentException.
        var head = T0.AddMinutes(10);
        var fixture = await AuthorAsync(T0, [head]);
        var writerNow = head.AddSeconds(-headAheadSeconds);
        var clock = new ManualTimeProvider(writerNow);
        var method = new DidWebVhMethod(new MockWebVhHttpClient()) { Clock = clock };

        Func<Task> act = deactivate
            ? () => method.DeactivateAsync(fixture.Did, new DidWebVhDeactivateOptions
            {
                CurrentLogContent = fixture.Log,
                SigningKey = fixture.Signer
            })
            : () => method.UpdateAsync(fixture.Did, new DidWebVhUpdateOptions
            {
                CurrentLogContent = fixture.Log,
                SigningKey = fixture.Signer
            });

        if (beyondTolerance)
        {
            await act.Should().ThrowAsync<LogChainValidationException>()
                .WithMessage("*version 2 is more than 5 minutes ahead*");
        }
        else
        {
            await act.Should().ThrowAsync<ArgumentException>()
                .WithMessage("*aggregate authoring wait*");
        }

        clock.UtcNow.Should().Be(writerNow, "rejection must not wait toward a future head");
    }

    [Theory]
    [InlineData(0, true)]
    [InlineData(4 * 60, true)]
    [InlineData(6 * 60, false)]
    public async Task Issue131_NetDidAuthoredBurst_ResolvesOnTheAuthoringClock_AndWithinSkew(
        int resolverLagSeconds, bool accepted)
    {
        // NetDid never authors a versionTime later than its own clock (#127), so a same-second
        // burst always resolves on that clock. A resolver host whose clock lags the author's
        // by more than the tolerance rejects it — the documented operational consequence.
        var authorClock = new ManualTimeProvider(T0);
        var fixture = await AuthorAsync(authorClock, updates: 3);
        fixture.Entries[^1].VersionTime.Should().Be(T0.AddSeconds(3));

        var result = await ResolveAsync(
            fixture, authorClock.UtcNow.AddSeconds(-resolverLagSeconds));

        if (accepted)
            result.DocumentMetadata!.VersionId.Should().Be(fixture.Entries[^1].VersionId);
        else
            ShouldBeInvalidDidLog(result);
    }

    #endregion

    private sealed record Fixture(string Did, ISigner Signer, byte[] Log, IReadOnlyList<LogEntry> Entries);

    private static async Task<Fixture> AuthorAsync(
        DateTimeOffset genesisAt, DateTimeOffset[] updatesAt, DateTimeOffset? deactivateAt = null)
    {
        var clock = new ManualTimeProvider(genesisAt);
        var method = new DidWebVhMethod(new MockWebVhHttpClient()) { Clock = clock };
        var signer = CreateSigner();
        var created = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = signer
        });
        var did = created.Did.Value;
        var log = (string)created.Artifacts![DidWebVhArtifacts.DidJsonl];

        foreach (var at in updatesAt)
        {
            clock.UtcNow = at;
            var updated = await method.UpdateAsync(did, new DidWebVhUpdateOptions
            {
                CurrentLogContent = Encoding.UTF8.GetBytes(log),
                SigningKey = signer
            });
            log = (string)updated.Artifacts![DidWebVhArtifacts.DidJsonl];
        }

        if (deactivateAt is { } deactivationTime)
        {
            clock.UtcNow = deactivationTime;
            var deactivated = await method.DeactivateAsync(did, new DidWebVhDeactivateOptions
            {
                CurrentLogContent = Encoding.UTF8.GetBytes(log),
                SigningKey = signer
            });
            log = (string)deactivated.Artifacts![DidWebVhArtifacts.DidJsonl];
        }

        return ToFixture(did, signer, log);
    }

    private static async Task<Fixture> AuthorAsync(ManualTimeProvider clock, int updates)
    {
        var method = new DidWebVhMethod(new MockWebVhHttpClient()) { Clock = clock };
        var signer = CreateSigner();
        var created = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = signer
        });
        var did = created.Did.Value;
        var log = (string)created.Artifacts![DidWebVhArtifacts.DidJsonl];

        for (var i = 0; i < updates; i++)
        {
            var updated = await method.UpdateAsync(did, new DidWebVhUpdateOptions
            {
                CurrentLogContent = Encoding.UTF8.GetBytes(log),
                SigningKey = signer
            });
            log = (string)updated.Artifacts![DidWebVhArtifacts.DidJsonl];
        }

        return ToFixture(did, signer, log);
    }

    private static Fixture ToFixture(string did, ISigner signer, string log)
    {
        var bytes = Encoding.UTF8.GetBytes(log);
        return new Fixture(did, signer, bytes, LogEntrySerializer.ParseJsonLines(bytes));
    }

    private static Task<DidResolutionResult> ResolveAsync(
        Fixture fixture, DateTimeOffset resolverNow, DidResolutionOptions? options = null)
        => ResolveAsync(fixture, new ManualTimeProvider(resolverNow), options);

    private static async Task<DidResolutionResult> ResolveAsync(
        Fixture fixture, ManualTimeProvider clock, DidResolutionOptions? options = null)
    {
        var httpClient = new MockWebVhHttpClient();
        httpClient.SetLogResponse(DidUrlMapper.MapToLogUrl(fixture.Did), fixture.Log);
        var resolver = new DidWebVhMethod(httpClient) { Clock = clock };
        return await resolver.ResolveAsync(fixture.Did, options);
    }

    private static void ShouldBeInvalidDidLog(DidResolutionResult result)
    {
        result.DidDocument.Should().BeNull();
        result.ResolutionMetadata.Error.Should().Be("invalidDidLog");
    }

    private static ISigner CreateSigner()
        => new KeyPairSigner(
            new DefaultKeyGenerator().Generate(KeyType.Ed25519),
            new DefaultCryptoProvider());

    /// <summary>
    /// Settable UTC clock that counts <see cref="GetUtcNow"/> reads. Like
    /// <see cref="AutoAdvanceTimeProvider"/>, an awaited delay fires at once and advances both
    /// UTC and monotonic time by exactly the requested amount.
    /// </summary>
    private sealed class ManualTimeProvider(DateTimeOffset utcNow) : TimeProvider
    {
        private long _timestamp;

        public DateTimeOffset UtcNow { get; set; } = utcNow;
        public int UtcNowReads { get; private set; }

        public override DateTimeOffset GetUtcNow()
        {
            UtcNowReads++;
            return UtcNow;
        }

        public override long GetTimestamp() => _timestamp;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;

        public override ITimer CreateTimer(
            TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
        {
            if (dueTime > TimeSpan.Zero)
            {
                UtcNow += dueTime;
                _timestamp += dueTime.Ticks;
            }
            callback(state);
            return new TestTimer();
        }
    }
}
