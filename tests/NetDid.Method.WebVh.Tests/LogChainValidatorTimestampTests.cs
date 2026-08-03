using System.Text;
using System.Text.Json;
using DataProofsDotnet.DataIntegrity;
using FluentAssertions;
using NetCrypto;
using NetDid.Core.Exceptions;
using NetDid.Method.WebVh.Model;

namespace NetDid.Method.WebVh.Tests;

public sealed class LogChainValidatorTimestampTests
{
    private readonly EddsaJcs2022Cryptosuite _suite = new();

    [Fact]
    public async Task ValidateChain_RejectsEqualAdjacentVersionTimes()
    {
        var (_, _, entries) = await CreateAuthenticatedChainAsync(time => time);
        var validator = new LogChainValidator();

        var act = () => validator.ValidateChainAsync(entries);

        await act.Should().ThrowAsync<LogChainValidationException>()
            .WithMessage("*strictly later*");
    }

    [Fact]
    public async Task ValidateChain_RejectsDecreasingAdjacentVersionTimes()
    {
        var (_, _, entries) = await CreateAuthenticatedChainAsync(time => time.AddTicks(-1));
        var validator = new LogChainValidator();

        var act = () => validator.ValidateChainAsync(entries);

        await act.Should().ThrowAsync<LogChainValidationException>()
            .WithMessage("*strictly later*");
    }

    [Fact]
    public async Task ValidateChain_AcceptsFractionalSecondIncrease()
    {
        var (_, _, entries) = await CreateAuthenticatedChainAsync(time => time.AddTicks(1));
        var validator = new LogChainValidator();

        var act = () => validator.ValidateChainAsync(entries);

        await act.Should().NotThrowAsync();
    }

    [Fact]
    public void ValidateVersionTime_AcceptsIncreasingWholeSecondSequence()
    {
        var previous = new DateTimeOffset(2026, 7, 10, 12, 0, 0, TimeSpan.Zero);
        var current = previous.AddSeconds(1);

        var act = () => LogChainValidator.ValidateVersionTime(previous, current, version: 2);

        act.Should().NotThrow();
    }

    [Fact]
    public async Task Resolve_AuthenticatedEqualVersionTimes_ReturnsInvalidDidLog()
    {
        var (did, _, entries) = await CreateAuthenticatedChainAsync(time => time);
        var httpClient = new MockWebVhHttpClient();
        httpClient.SetLogResponse(DidUrlMapper.MapToLogUrl(did), LogEntrySerializer.ToJsonLines(entries));
        var method = new DidWebVhMethod(httpClient);

        var result = await method.ResolveAsync(did);

        result.DidDocument.Should().BeNull();
        result.ResolutionMetadata.Error.Should().Be("invalidDidLog");
    }

    [Fact]
    public async Task Resolve_HistoricalVersion_DoesNotExposeUnvalidatedTailTimestamp()
    {
        var (did, _, entries) = await CreateAuthenticatedChainAsync(time => time.AddTicks(-1));
        var httpClient = new MockWebVhHttpClient();
        httpClient.SetLogResponse(DidUrlMapper.MapToLogUrl(did), LogEntrySerializer.ToJsonLines(entries));
        var method = new DidWebVhMethod(httpClient);

        var result = await method.ResolveAsync(did, new DidWebVhResolveOptions
        {
            VersionId = entries[0].VersionId
        });

        result.DidDocument.Should().NotBeNull();
        result.ResolutionMetadata.Error.Should().BeNull();
        result.DocumentMetadata!.VersionTime.Should().Be(entries[0].VersionTime);
        result.DocumentMetadata.Updated.Should().BeNull(
            "metadata must not surface a timestamp from an unvalidated later entry");
    }

    [Fact]
    public async Task ValidateChain_RejectsMalformedLaterWitnessPolicy()
    {
        var witnessId = $"did:key:{CreateSigner().MultibasePublicKey}";
        var malformedPolicy = new WitnessConfig
        {
            Threshold = 1,
            Witnesses =
            [
                new WitnessEntry { Id = witnessId },
                new WitnessEntry { Id = witnessId }
            ]
        };
        var (_, _, entries) = await CreateAuthenticatedChainAsync(
            time => time.AddTicks(1),
            new LogEntryParameters { Witness = malformedPolicy });
        var validator = new LogChainValidator();

        var act = () => validator.ValidateChainAsync(entries);

        await act.Should().ThrowAsync<LogChainValidationException>()
            .WithMessage("*duplicated*");
    }

    [Fact]
    public async Task Resolve_MalformedLaterWitnessPolicy_ReturnsInvalidDidLog()
    {
        var witnessId = $"did:key:{CreateSigner().MultibasePublicKey}";
        var malformedPolicy = new WitnessConfig
        {
            Threshold = 2,
            Witnesses = [new WitnessEntry { Id = witnessId }]
        };
        var (did, _, entries) = await CreateAuthenticatedChainAsync(
            time => time.AddTicks(1),
            new LogEntryParameters { Witness = malformedPolicy });
        var httpClient = new MockWebVhHttpClient();
        httpClient.SetLogResponse(DidUrlMapper.MapToLogUrl(did), LogEntrySerializer.ToJsonLines(entries));
        var method = new DidWebVhMethod(httpClient);

        var result = await method.ResolveAsync(did);

        result.DidDocument.Should().BeNull();
        result.ResolutionMetadata.Error.Should().Be("invalidDidLog");
    }

    [Fact]
    public async Task ValidateChain_AcceptsEmptyWitnessDisableTransition()
    {
        var (_, _, entries) = await CreateAuthenticatedChainAsync(
            time => time.AddTicks(1),
            new LogEntryParameters { Witness = new WitnessConfig() });
        var validator = new LogChainValidator();

        var act = () => validator.ValidateChainAsync(entries);

        await act.Should().NotThrowAsync();
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task WriteOperations_RejectAuthenticatedNonMonotonicCurrentLog(bool deactivate)
    {
        var (did, signer, entries) = await CreateAuthenticatedChainAsync(time => time.AddTicks(-1));
        var method = new DidWebVhMethod(new MockWebVhHttpClient());
        var currentLog = LogEntrySerializer.ToJsonLines(entries);

        Func<Task> act = deactivate
            ? () => method.DeactivateAsync(did, new DidWebVhDeactivateOptions
            {
                CurrentLogContent = currentLog,
                SigningKey = signer
            })
            : () => method.UpdateAsync(did, new DidWebVhUpdateOptions
            {
                CurrentLogContent = currentLog,
                SigningKey = signer
            });

        await act.Should().ThrowAsync<LogChainValidationException>()
            .WithMessage("*strictly later*");
    }

    [Fact]
    public async Task Issue127_Update_WaitsForNextWholeSecond_NeverAuthorsFutureTime()
    {
        // Exact boundary, deterministic clock: with the clock at T and the head at T+1s,
        // the next authorable whole second is T+2s — a wait of exactly the 2-second bound.
        // Update must WAIT for that instant to arrive (did:webvh: the entry timestamp must
        // be the retrieval time or before; resolver skew tolerance is not authoring
        // permission), then stamp a versionTime that is not later than the clock.
        var clock = new AutoAdvanceTimeProvider(
            new DateTimeOffset(2026, 7, 10, 12, 0, 0, TimeSpan.Zero));
        var (did, signer, entries) = await CreateAuthenticatedChainAsync(
            time => time.AddSeconds(1), clock: clock);
        var method = new DidWebVhMethod(new MockWebVhHttpClient()) { Clock = clock };

        var result = await method.UpdateAsync(did, new DidWebVhUpdateOptions
        {
            CurrentLogContent = LogEntrySerializer.ToJsonLines(entries),
            SigningKey = signer
        });
        var updatedEntries = LogEntrySerializer.ParseJsonLines(
            Encoding.UTF8.GetBytes((string)result.Artifacts![DidWebVhArtifacts.DidJsonl]));

        updatedEntries[2].VersionTime.Should().BeAfter(updatedEntries[1].VersionTime);
        updatedEntries[2].VersionTime.Should().BeOnOrBefore(clock.GetUtcNow(),
            "an authored versionTime must never be later than the authoring clock");
        updatedEntries[2].VersionTime.Should().Be(
            new DateTimeOffset(2026, 7, 10, 12, 0, 2, TimeSpan.Zero),
            "the writer waits for the next whole second after the head instead of " +
            "manufacturing future time");
        await new LogChainValidator().ValidateChainAsync(updatedEntries);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Issue127_WriteOperations_FailHonestly_WhenHeadIsAheadOfClock(
        bool deactivate)
    {
        // A head 2 minutes ahead of the clock (only producible by a non-NetDid author or
        // severe clock skew) cannot be appended past without authoring future time, which
        // did:webvh forbids. Both Update and Deactivate must fail honestly with a
        // retry-after-the-clock-catches-up contract — returning success for an entry
        // conforming resolvers reject would be false assurance. (+2 minutes also pins the
        // no-future-authoring design against regressing to any minutes-scale budget: it sat
        // inside the earlier 5-minute budget this replaced.)
        var clock = new AutoAdvanceTimeProvider(
            new DateTimeOffset(2026, 7, 10, 12, 0, 0, TimeSpan.Zero));
        var (did, signer, entries) = await CreateAuthenticatedChainAsync(
            time => time.AddMinutes(2), clock: clock);
        var method = new DidWebVhMethod(new MockWebVhHttpClient()) { Clock = clock };
        var currentLog = LogEntrySerializer.ToJsonLines(entries);

        Func<Task> act = deactivate
            ? () => method.DeactivateAsync(did, new DidWebVhDeactivateOptions
            {
                CurrentLogContent = currentLog,
                SigningKey = signer
            })
            : () => method.UpdateAsync(did, new DidWebVhUpdateOptions
            {
                CurrentLogContent = currentLog,
                SigningKey = signer
            });

        await act.Should().ThrowAsync<ArgumentException>()
            .WithMessage("*ahead of the local clock*");
        clock.GetUtcNow().Should().Be(
            new DateTimeOffset(2026, 7, 10, 12, 0, 0, TimeSpan.Zero),
            "failing closed must not wait toward a far-future head");
    }

    [Fact]
    public async Task Issue127_Update_FailsHonestly_JustBeyondBoundedWait()
    {
        // Exact boundary complement: head at T+2s needs a 3-second wait — one second past
        // the 2-second bound — so authoring refuses rather than waits or stamps future time.
        var clock = new AutoAdvanceTimeProvider(
            new DateTimeOffset(2026, 7, 10, 12, 0, 0, TimeSpan.Zero));
        var (did, signer, entries) = await CreateAuthenticatedChainAsync(
            time => time.AddSeconds(2), clock: clock);
        var method = new DidWebVhMethod(new MockWebVhHttpClient()) { Clock = clock };

        var act = () => method.UpdateAsync(did, new DidWebVhUpdateOptions
        {
            CurrentLogContent = LogEntrySerializer.ToJsonLines(entries),
            SigningKey = signer
        });

        await act.Should().ThrowAsync<ArgumentException>()
            .WithMessage("*ahead of the local clock*");
    }

    private async Task<(string Did, ISigner Signer, IReadOnlyList<LogEntry> Entries)>
        CreateAuthenticatedChainAsync(
            Func<DateTimeOffset, DateTimeOffset> selectSecondTime,
            LogEntryParameters? secondParameters = null,
            TimeProvider? clock = null)
    {
        var signer = CreateSigner();
        var method = new DidWebVhMethod(new MockWebVhHttpClient())
        {
            Clock = clock ?? TimeProvider.System
        };
        var created = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = signer
        });
        var genesisJson = (string)created.Artifacts![DidWebVhArtifacts.DidJsonl];
        var genesis = LogEntrySerializer.ParseJsonLines(Encoding.UTF8.GetBytes(genesisJson))[0];
        var versionTime = selectSecondTime(genesis.VersionTime);

        var entryForHashing = new LogEntry
        {
            VersionId = genesis.VersionId,
            VersionTime = versionTime,
            Parameters = secondParameters ?? new LogEntryParameters(),
            State = genesis.State
        };
        var entryHash = ScidGenerator.ComputeEntryHash(
            LogEntrySerializer.SerializeWithoutProof(entryForHashing));
        var second = entryForHashing with { VersionId = $"2-{entryHash}" };
        second = second with { Proof = [await SignEntryAsync(second, signer)] };

        return (created.Did.Value, signer, new[] { genesis, second });
    }

    private static ISigner CreateSigner()
        => new KeyPairSigner(
            new DefaultKeyGenerator().Generate(KeyType.Ed25519),
            new DefaultCryptoProvider());

    private async Task<DataIntegrityProofValue> SignEntryAsync(LogEntry entry, ISigner signer)
    {
        var options = new DataIntegrityProof
        {
            Cryptosuite = EddsaJcs2022Cryptosuite.CryptosuiteName,
            VerificationMethod = $"did:key:{signer.MultibasePublicKey}#{signer.MultibasePublicKey}",
            Created = WebVhTimestamp.Format(entry.VersionTime),
            ProofPurpose = "assertionMethod"
        };
        using var document = JsonDocument.Parse(LogEntrySerializer.SerializeWithoutProof(entry));
        var proof = await _suite.CreateProofAsync(document.RootElement, options, signer);

        return new DataIntegrityProofValue
        {
            Type = proof.Type,
            Cryptosuite = proof.Cryptosuite!,
            VerificationMethod = proof.VerificationMethod!,
            Created = proof.Created!,
            ProofPurpose = proof.ProofPurpose!,
            ProofValue = proof.ProofValue!
        };
    }
}
