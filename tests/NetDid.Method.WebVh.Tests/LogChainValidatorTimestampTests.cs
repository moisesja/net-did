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
        var validator = new LogChainValidator(_suite);

        var act = () => validator.ValidateChain(entries);

        act.Should().Throw<LogChainValidationException>()
            .WithMessage("*strictly later*");
    }

    [Fact]
    public async Task ValidateChain_RejectsDecreasingAdjacentVersionTimes()
    {
        var (_, _, entries) = await CreateAuthenticatedChainAsync(time => time.AddTicks(-1));
        var validator = new LogChainValidator(_suite);

        var act = () => validator.ValidateChain(entries);

        act.Should().Throw<LogChainValidationException>()
            .WithMessage("*strictly later*");
    }

    [Fact]
    public async Task ValidateChain_AcceptsFractionalSecondIncrease()
    {
        var (_, _, entries) = await CreateAuthenticatedChainAsync(time => time.AddTicks(1));
        var validator = new LogChainValidator(_suite);

        var act = () => validator.ValidateChain(entries);

        act.Should().NotThrow();
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
        var validator = new LogChainValidator(_suite);

        var act = () => validator.ValidateChain(entries);

        act.Should().Throw<LogChainValidationException>()
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
        var validator = new LogChainValidator(_suite);

        var act = () => validator.ValidateChain(entries);

        act.Should().NotThrow();
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
    public async Task Update_FutureDatedCurrentLog_StillEmitsStrictlyIncreasingVersionTime()
    {
        var (did, signer, entries) = await CreateAuthenticatedChainAsync(
            time => time.AddMinutes(5));
        var method = new DidWebVhMethod(new MockWebVhHttpClient());

        var result = await method.UpdateAsync(did, new DidWebVhUpdateOptions
        {
            CurrentLogContent = LogEntrySerializer.ToJsonLines(entries),
            SigningKey = signer
        });
        var updatedEntries = LogEntrySerializer.ParseJsonLines(
            Encoding.UTF8.GetBytes((string)result.Artifacts![DidWebVhArtifacts.DidJsonl]));

        updatedEntries[2].VersionTime.Should().BeAfter(updatedEntries[1].VersionTime);
        new LogChainValidator(_suite).ValidateChain(updatedEntries);
    }

    private async Task<(string Did, ISigner Signer, IReadOnlyList<LogEntry> Entries)>
        CreateAuthenticatedChainAsync(
            Func<DateTimeOffset, DateTimeOffset> selectSecondTime,
            LogEntryParameters? secondParameters = null)
    {
        var signer = CreateSigner();
        var method = new DidWebVhMethod(new MockWebVhHttpClient());
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
