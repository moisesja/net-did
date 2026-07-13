using System.Globalization;
using System.Text;
using System.Text.Json;
using DataProofsDotnet.DataIntegrity;
using FluentAssertions;
using NetCrypto;
using NetDid.Core.Exceptions;
using NetDid.Core.Model;
using NetDid.Method.WebVh;
using NetDid.Method.WebVh.Model;

namespace NetDid.Method.WebVh.Tests;

/// <summary>
/// Regression coverage for did:webvh v1.0 pre-rotation authorization (issue #93).
/// These tests deliberately separate the prior-effective parameters from the current raw
/// parameters: ordinary entries use the former, while entries governed by a prior non-empty
/// nextKeyHashes use the latter.
/// </summary>
public class PreRotationConformanceTests
{
    [Fact]
    public async Task Update_ActivePreRotation_RejectsPreviousUpdateKeySigner()
    {
        var (method, _, did, log, previousKey, committedKey) =
            await CreateWithPreRotationAsync();

        var act = () => method.UpdateAsync(did, new DidWebVhUpdateOptions
        {
            CurrentLogContent = log,
            SigningKey = previousKey,
            ParameterUpdates = new DidWebVhParameterUpdates
            {
                UpdateKeys = [committedKey.MultibasePublicKey],
                NextKeyHashes = []
            }
        });

        await act.Should().ThrowAsync<ArgumentException>()
            .WithMessage("*not an authorized update key*");
    }

    [Fact]
    public async Task Update_ActivePreRotation_RequiresExplicitNextKeyHashes()
    {
        var (method, _, did, log, _, committedKey) = await CreateWithPreRotationAsync();

        var act = () => method.UpdateAsync(did, new DidWebVhUpdateOptions
        {
            CurrentLogContent = log,
            SigningKey = committedKey,
            ParameterUpdates = new DidWebVhParameterUpdates
            {
                UpdateKeys = [committedKey.MultibasePublicKey]
            }
        });

        await act.Should().ThrowAsync<ArgumentException>()
            .WithMessage("*nextKeyHashes*explicitly provided*");
    }

    [Fact]
    public async Task Update_ActivePreRotation_ValidatesEveryCurrentUpdateKey()
    {
        var (method, _, did, log, _, committedKey) = await CreateWithPreRotationAsync();
        var uncommittedKey = CreateSigner();

        var act = () => method.UpdateAsync(did, new DidWebVhUpdateOptions
        {
            CurrentLogContent = log,
            SigningKey = committedKey,
            ParameterUpdates = new DidWebVhParameterUpdates
            {
                UpdateKeys =
                [
                    committedKey.MultibasePublicKey,
                    uncommittedKey.MultibasePublicKey
                ],
                NextKeyHashes = []
            }
        });

        await act.Should().ThrowAsync<LogChainValidationException>()
            .WithMessage("*commitment does not match*");
    }

    [Fact]
    public async Task Update_ActivePreRotation_RejectsCommittedMalformedExtraUpdateKey()
    {
        var method = new DidWebVhMethod(new MockWebVhHttpClient());
        var previousKey = CreateSigner();
        var committedKey = CreateSigner();
        const string malformedKey = "not-a-multikey";
        var created = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = previousKey,
            PreRotationCommitments =
            [
                PreRotationManager.ComputeKeyCommitment(committedKey.MultibasePublicKey),
                PreRotationManager.ComputeKeyCommitment(malformedKey)
            ]
        });

        var act = () => method.UpdateAsync(created.Did.Value, new DidWebVhUpdateOptions
        {
            CurrentLogContent = GetLog(created),
            SigningKey = committedKey,
            ParameterUpdates = new DidWebVhParameterUpdates
            {
                UpdateKeys = [committedKey.MultibasePublicKey, malformedKey],
                NextKeyHashes = []
            }
        });

        await act.Should().ThrowAsync<LogChainValidationException>()
            .WithMessage("*not a valid Ed25519 Multikey*");
    }

    [Fact]
    public async Task Update_ActivationEntry_IsAuthorizedByPriorUpdateKey()
    {
        var httpClient = new MockWebVhHttpClient();
        var method = new DidWebVhMethod(httpClient);
        var currentKey = CreateSigner();
        var futureKey = CreateSigner();
        var created = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = currentKey
        });

        var updated = await method.UpdateAsync(created.Did.Value, new DidWebVhUpdateOptions
        {
            CurrentLogContent = GetLog(created),
            SigningKey = currentKey,
            ParameterUpdates = new DidWebVhParameterUpdates
            {
                NextKeyHashes =
                [PreRotationManager.ComputeKeyCommitment(futureKey.MultibasePublicKey)]
            }
        });

        var updatedLog = GetLog(updated);
        httpClient.SetLogResponse(DidUrlMapper.MapToLogUrl(created.Did.Value), updatedLog);
        var resolved = await method.ResolveAsync(created.Did.Value);

        resolved.ResolutionMetadata.Error.Should().BeNull();
        updated.UpdateKeyChange.Should().Be(AuthorizationChangeStatus.Unchanged);
        updated.EffectiveUpdateKeys.Should().BeNull();
        updated.RevealedUpdateKeys.Should().BeEquivalentTo([currentKey.MultibasePublicKey]);
    }

    [Fact]
    public async Task Update_ActivationEntry_RejectsFutureCommittedKeySigner()
    {
        var method = new DidWebVhMethod(new MockWebVhHttpClient());
        var currentKey = CreateSigner();
        var futureKey = CreateSigner();
        var created = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = currentKey
        });

        var act = () => method.UpdateAsync(created.Did.Value, new DidWebVhUpdateOptions
        {
            CurrentLogContent = GetLog(created),
            SigningKey = futureKey,
            ParameterUpdates = new DidWebVhParameterUpdates
            {
                NextKeyHashes =
                [PreRotationManager.ComputeKeyCommitment(futureKey.MultibasePublicKey)]
            }
        });

        await act.Should().ThrowAsync<ArgumentException>()
            .WithMessage("*not an authorized update key*");
    }

    [Fact]
    public async Task Resolve_ActivationEntry_RejectsFutureCommittedKeySigner()
    {
        var method = new DidWebVhMethod(new MockWebVhHttpClient());
        var currentKey = CreateSigner();
        var futureKey = CreateSigner();
        var created = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = currentKey
        });
        var genesis = LogEntrySerializer.ParseJsonLines(GetLog(created))[0];
        var activation = await AppendEntryAsync(genesis, new LogEntryParameters
        {
            NextKeyHashes =
            [PreRotationManager.ComputeKeyCommitment(futureKey.MultibasePublicKey)]
        }, futureKey);
        var validator = new LogChainValidator(new EddsaJcs2022Cryptosuite());

        validator.Invoking(v => v.ValidateChain([genesis, activation]))
            .Should().Throw<LogChainValidationException>()
            .WithMessage("*authorized update key*");
    }

    [Fact]
    public async Task Update_ActivePreRotation_ContinuesAcrossCommittedKeyGenerations()
    {
        var (method, httpClient, did, log, _, key2) = await CreateWithPreRotationAsync();
        var key3 = CreateSigner();
        var key4 = CreateSigner();
        var second = await method.UpdateAsync(did, new DidWebVhUpdateOptions
        {
            CurrentLogContent = log,
            SigningKey = key2,
            ParameterUpdates = new DidWebVhParameterUpdates
            {
                UpdateKeys = [key2.MultibasePublicKey],
                NextKeyHashes =
                [PreRotationManager.ComputeKeyCommitment(key3.MultibasePublicKey)]
            }
        });
        var third = await method.UpdateAsync(did, new DidWebVhUpdateOptions
        {
            CurrentLogContent = GetLog(second),
            SigningKey = key3,
            ParameterUpdates = new DidWebVhParameterUpdates
            {
                UpdateKeys = [key3.MultibasePublicKey],
                NextKeyHashes =
                [PreRotationManager.ComputeKeyCommitment(key4.MultibasePublicKey)]
            }
        });
        var thirdLog = GetLog(third);
        httpClient.SetLogResponse(DidUrlMapper.MapToLogUrl(did), thirdLog);

        var resolved = await method.ResolveAsync(did);

        resolved.ResolutionMetadata.Error.Should().BeNull();
        LogEntrySerializer.ParseJsonLines(thirdLog).Should().HaveCount(3);
        second.UpdateKeyChange.Should().Be(AuthorizationChangeStatus.Changed);
        second.EffectiveUpdateKeys.Should().BeNull();
        second.RevealedUpdateKeys.Should().BeEquivalentTo([key2.MultibasePublicKey]);
        third.UpdateKeyChange.Should().Be(AuthorizationChangeStatus.Changed);
        third.EffectiveUpdateKeys.Should().BeNull();
        third.RevealedUpdateKeys.Should().BeEquivalentTo([key3.MultibasePublicKey]);
    }

    [Fact]
    public async Task Resolve_ActivePreRotation_AcceptsCommittedMultiKeySetAndRejectsExtraKey()
    {
        var method = new DidWebVhMethod(new MockWebVhHttpClient());
        var previousKey = CreateSigner();
        var key2 = CreateSigner();
        var key3 = CreateSigner();
        var extraKey = CreateSigner();
        var created = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = previousKey,
            PreRotationCommitments =
            [
                PreRotationManager.ComputeKeyCommitment(key2.MultibasePublicKey),
                PreRotationManager.ComputeKeyCommitment(key3.MultibasePublicKey)
            ]
        });
        var genesis = LogEntrySerializer.ParseJsonLines(GetLog(created))[0];
        var valid = await AppendEntryAsync(genesis, new LogEntryParameters
        {
            UpdateKeys = [key2.MultibasePublicKey, key3.MultibasePublicKey],
            NextKeyHashes = []
        }, key3);
        var invalid = await AppendEntryAsync(genesis, new LogEntryParameters
        {
            UpdateKeys =
            [key2.MultibasePublicKey, key3.MultibasePublicKey, extraKey.MultibasePublicKey],
            NextKeyHashes = []
        }, key3);
        var validator = new LogChainValidator(new EddsaJcs2022Cryptosuite());

        validator.Invoking(v => v.ValidateChain([genesis, valid]))
            .Should().NotThrow();
        validator.Invoking(v => v.ValidateChain([genesis, invalid]))
            .Should().Throw<LogChainValidationException>()
            .WithMessage("*commitment does not match*");
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Resolve_ActivePreRotation_RequiresBothExplicitArrays(bool omitUpdateKeys)
    {
        var (method, httpClient, did, log, _, committedKey) =
            await CreateWithPreRotationAsync();
        var genesis = LogEntrySerializer.ParseJsonLines(log)[0];
        var parameters = new LogEntryParameters
        {
            UpdateKeys = omitUpdateKeys ? null : [committedKey.MultibasePublicKey],
            NextKeyHashes = omitUpdateKeys ? [] : null
        };
        var invalidEntry = await AppendEntryAsync(genesis, parameters, committedKey);
        var invalidLog = LogEntrySerializer.ToJsonLines([genesis, invalidEntry]);
        httpClient.SetLogResponse(DidUrlMapper.MapToLogUrl(did), invalidLog);

        var resolved = await method.ResolveAsync(did);

        resolved.DidDocument.Should().BeNull();
        resolved.ResolutionMetadata.Error.Should().Be("invalidDidLog");
    }

    [Fact]
    public async Task Resolve_ActivePreRotation_AcceptsCurrentKeyAndRejectsPreviousKey()
    {
        var (_, _, _, log, previousKey, committedKey) = await CreateWithPreRotationAsync();
        var genesis = LogEntrySerializer.ParseJsonLines(log)[0];
        var parameters = new LogEntryParameters
        {
            UpdateKeys = [committedKey.MultibasePublicKey],
            NextKeyHashes = []
        };
        var validEntry = await AppendEntryAsync(genesis, parameters, committedKey);
        var invalidEntry = await AppendEntryAsync(genesis, parameters, previousKey);
        var validator = new LogChainValidator(new EddsaJcs2022Cryptosuite());

        validator.Invoking(v => v.ValidateChain([genesis, validEntry]))
            .Should().NotThrow();
        validator.Invoking(v => v.ValidateChain([genesis, invalidEntry]))
            .Should().Throw<LogChainValidationException>()
            .WithMessage("*authorized update key*");
    }

    [Fact]
    public async Task Update_AfterPreRotationExit_UsesPriorEffectiveUpdateKey()
    {
        var (method, httpClient, did, log, _, committedKey) =
            await CreateWithPreRotationAsync();
        var exited = await method.UpdateAsync(did, new DidWebVhUpdateOptions
        {
            CurrentLogContent = log,
            SigningKey = committedKey,
            ParameterUpdates = new DidWebVhParameterUpdates
            {
                UpdateKeys = [committedKey.MultibasePublicKey],
                NextKeyHashes = []
            }
        });

        var next = await method.UpdateAsync(did, new DidWebVhUpdateOptions
        {
            CurrentLogContent = GetLog(exited),
            SigningKey = committedKey,
            ParameterUpdates = new DidWebVhParameterUpdates { Ttl = 300 }
        });
        var nextLog = GetLog(next);
        httpClient.SetLogResponse(DidUrlMapper.MapToLogUrl(did), nextLog);

        var resolved = await method.ResolveAsync(did);

        resolved.ResolutionMetadata.Error.Should().BeNull();
        LogEntrySerializer.ParseJsonLines(nextLog).Should().HaveCount(3);
    }

    [Fact]
    public async Task Deactivate_ActivePreRotation_RevealsCommittedSignerAndEndsPreRotation()
    {
        var (method, httpClient, did, log, _, committedKey) =
            await CreateWithPreRotationAsync();

        var deactivated = await method.DeactivateAsync(did, new DidWebVhDeactivateOptions
        {
            CurrentLogContent = log,
            SigningKey = committedKey
        });
        var deactivatedLog = Encoding.UTF8.GetBytes(
            (string)deactivated.Artifacts![DidWebVhArtifacts.DidJsonl]);
        var entries = LogEntrySerializer.ParseJsonLines(deactivatedLog);
        var finalParameters = entries[^1].Parameters;

        finalParameters.Deactivated.Should().BeTrue();
        finalParameters.UpdateKeys.Should().Equal(committedKey.MultibasePublicKey);
        finalParameters.NextKeyHashes.Should().NotBeNull().And.BeEmpty();
        new LogChainValidator(new EddsaJcs2022Cryptosuite()).ValidateChain(entries);

        httpClient.SetLogResponse(DidUrlMapper.MapToLogUrl(did), deactivatedLog);
        var resolved = await method.ResolveAsync(did);
        resolved.DidDocument.Should().BeNull();
        resolved.DocumentMetadata!.Deactivated.Should().BeTrue();
    }

    [Fact]
    public async Task Deactivate_ActivePreRotation_RejectsUncommittedPreviousSigner()
    {
        var (method, _, did, log, previousKey, _) = await CreateWithPreRotationAsync();

        var act = () => method.DeactivateAsync(did, new DidWebVhDeactivateOptions
        {
            CurrentLogContent = log,
            SigningKey = previousKey
        });

        await act.Should().ThrowAsync<LogChainValidationException>()
            .WithMessage("*commitment does not match*");
    }

    [Fact]
    public async Task Resolve_LegacyPrerotationParameter_ReturnsInvalidDidLog()
    {
        var httpClient = new MockWebVhHttpClient();
        var method = new DidWebVhMethod(httpClient);
        var created = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = CreateSigner()
        });
        var legacyJson = Encoding.UTF8.GetString(GetLog(created)).Replace(
            "\"parameters\":{",
            "\"parameters\":{\"prerotation\":true,",
            StringComparison.Ordinal);
        var legacyLog = Encoding.UTF8.GetBytes(legacyJson);
        httpClient.SetLogResponse(DidUrlMapper.MapToLogUrl(created.Did.Value), legacyLog);

        var resolved = await method.ResolveAsync(created.Did.Value);

        resolved.DidDocument.Should().BeNull();
        resolved.ResolutionMetadata.Error.Should().Be("invalidDidLog");
        ((Action)(() => LogEntrySerializer.ParseJsonLines(legacyLog)))
            .Should().Throw<FormatException>()
            .WithMessage("*removed before did:webvh v1.0*");
    }

    [Fact]
    public async Task Resolve_UnknownParameterInjection_ReturnsInvalidDidLog()
    {
        var httpClient = new MockWebVhHttpClient();
        var method = new DidWebVhMethod(httpClient);
        var created = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = CreateSigner()
        });
        var injectedJson = Encoding.UTF8.GetString(GetLog(created)).Replace(
            "\"parameters\":{",
            "\"parameters\":{\"futureAuthority\":true,",
            StringComparison.Ordinal);
        var injectedLog = Encoding.UTF8.GetBytes(injectedJson);
        httpClient.SetLogResponse(DidUrlMapper.MapToLogUrl(created.Did.Value), injectedLog);

        var resolved = await method.ResolveAsync(created.Did.Value);

        resolved.DidDocument.Should().BeNull();
        resolved.ResolutionMetadata.Error.Should().Be("invalidDidLog");
        ((Action)(() => LogEntrySerializer.ParseJsonLines(injectedLog)))
            .Should().Throw<FormatException>()
            .WithMessage("*Unknown did:webvh v1.0 parameter*");
    }

    [Fact]
    public async Task Watchers_RoundTripAndCanBeDisabled()
    {
        var httpClient = new MockWebVhHttpClient();
        var method = new DidWebVhMethod(httpClient);
        var signer = CreateSigner();
        var created = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = signer,
            Watchers = ["https://watcher.example/notify"]
        });
        var createdEntries = LogEntrySerializer.ParseJsonLines(GetLog(created));
        createdEntries[0].Parameters.Watchers.Should()
            .Equal("https://watcher.example/notify");

        var updated = await method.UpdateAsync(created.Did.Value, new DidWebVhUpdateOptions
        {
            CurrentLogContent = GetLog(created),
            SigningKey = signer,
            ParameterUpdates = new DidWebVhParameterUpdates { Watchers = [] }
        });
        var updatedLog = GetLog(updated);
        var updatedEntries = LogEntrySerializer.ParseJsonLines(updatedLog);
        updatedEntries[^1].Parameters.Watchers.Should().NotBeNull().And.BeEmpty();
        httpClient.SetLogResponse(DidUrlMapper.MapToLogUrl(created.Did.Value), updatedLog);

        var resolved = await method.ResolveAsync(created.Did.Value);
        resolved.ResolutionMetadata.Error.Should().BeNull();
    }

    [Theory]
    [InlineData("not a URL")]
    [InlineData("ftp://watcher.example")]
    [InlineData("https://user@watcher.example")]
    public async Task Create_InvalidWatcherUrl_IsRejected(string watcher)
    {
        var method = new DidWebVhMethod(new MockWebVhHttpClient());

        var act = () => method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = CreateSigner(),
            Watchers = [watcher]
        });

        await act.Should().ThrowAsync<LogChainValidationException>()
            .WithMessage("*invalid HTTP(S) URL*");
    }

    [Fact]
    public async Task Resolve_NullWatcherEntry_ReturnsInvalidDidLog()
    {
        var httpClient = new MockWebVhHttpClient();
        var method = new DidWebVhMethod(httpClient);
        var created = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = CreateSigner()
        });
        var injectedJson = Encoding.UTF8.GetString(GetLog(created)).Replace(
            "\"parameters\":{",
            "\"parameters\":{\"watchers\":[null],",
            StringComparison.Ordinal);
        var injectedLog = Encoding.UTF8.GetBytes(injectedJson);
        httpClient.SetLogResponse(DidUrlMapper.MapToLogUrl(created.Did.Value), injectedLog);

        var resolved = await method.ResolveAsync(created.Did.Value);

        resolved.DidDocument.Should().BeNull();
        resolved.ResolutionMetadata.Error.Should().Be("invalidDidLog");
    }

    [Fact]
    public async Task Resolve_PriorVersion_DoesNotTrustDeactivationWithDifferentScid()
    {
        var httpClient = new MockWebVhHttpClient();
        var method = new DidWebVhMethod(httpClient);
        var signer = CreateSigner();
        var created = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = signer
        });
        var other = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "other.example",
            UpdateKey = CreateSigner()
        });
        var genesis = LogEntrySerializer.ParseJsonLines(GetLog(created))[0];
        var mismatchedDeactivation = await AppendEntryAsync(
            genesis,
            new LogEntryParameters { Deactivated = true },
            signer,
            other.DidDocument);
        httpClient.SetLogResponse(
            DidUrlMapper.MapToLogUrl(created.Did.Value),
            LogEntrySerializer.ToJsonLines([genesis, mismatchedDeactivation]));

        var resolved = await method.ResolveAsync(created.Did.Value, new DidWebVhResolveOptions
        {
            VersionId = genesis.VersionId
        });

        resolved.DidDocument.Should().NotBeNull();
        resolved.DocumentMetadata!.Deactivated.Should().BeNull();
    }

    [Fact]
    public async Task ValidateChain_UnsupportedMethodVersion_IsRejected()
    {
        var method = new DidWebVhMethod(new MockWebVhHttpClient());
        var created = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = CreateSigner()
        });
        var genesis = LogEntrySerializer.ParseJsonLines(GetLog(created))[0];
        var invalidGenesis = genesis with
        {
            Parameters = new LogEntryParameters
            {
                Method = "did:webvh:99.0",
                Scid = genesis.Parameters.Scid,
                UpdateKeys = genesis.Parameters.UpdateKeys,
                NextKeyHashes = genesis.Parameters.NextKeyHashes,
                Deactivated = genesis.Parameters.Deactivated,
                Portable = genesis.Parameters.Portable,
                Ttl = genesis.Parameters.Ttl,
                Witness = genesis.Parameters.Witness
            }
        };
        var validator = new LogChainValidator(new EddsaJcs2022Cryptosuite());

        validator.Invoking(v => v.ValidateChain([invalidGenesis]))
            .Should().Throw<LogChainValidationException>()
            .WithMessage("*Unsupported did:webvh method version*");
    }

    private static async Task<(
        DidWebVhMethod Method,
        MockWebVhHttpClient HttpClient,
        string Did,
        byte[] Log,
        ISigner PreviousKey,
        ISigner CommittedKey)> CreateWithPreRotationAsync()
    {
        var httpClient = new MockWebVhHttpClient();
        var method = new DidWebVhMethod(httpClient);
        var previousKey = CreateSigner();
        var committedKey = CreateSigner();
        var created = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = previousKey,
            PreRotationCommitments =
            [PreRotationManager.ComputeKeyCommitment(committedKey.MultibasePublicKey)]
        });

        return (method, httpClient, created.Did.Value, GetLog(created), previousKey, committedKey);
    }

    private static async Task<LogEntry> AppendEntryAsync(
        LogEntry previous,
        LogEntryParameters parameters,
        ISigner signer,
        DidDocument? state = null)
    {
        var versionNumber = previous.VersionNumber + 1;
        var versionText = versionNumber.ToString(CultureInfo.InvariantCulture);
        var entryForHashing = new LogEntry
        {
            VersionId = previous.VersionId,
            VersionTime = previous.VersionTime.AddTicks(1),
            Parameters = parameters,
            State = state ?? previous.State
        };
        var entryHash = ScidGenerator.ComputeEntryHash(
            LogEntrySerializer.SerializeWithoutProof(entryForHashing));
        var entry = entryForHashing with { VersionId = $"{versionText}-{entryHash}" };
        return entry with { Proof = [await SignEntryAsync(entry, signer)] };
    }

    private static async Task<DataIntegrityProofValue> SignEntryAsync(LogEntry entry, ISigner signer)
    {
        var suite = new EddsaJcs2022Cryptosuite();
        var proofOptions = new DataIntegrityProof
        {
            Cryptosuite = EddsaJcs2022Cryptosuite.CryptosuiteName,
            VerificationMethod = $"did:key:{signer.MultibasePublicKey}#{signer.MultibasePublicKey}",
            Created = WebVhTimestamp.Format(entry.VersionTime),
            ProofPurpose = "assertionMethod"
        };
        using var document = JsonDocument.Parse(LogEntrySerializer.SerializeWithoutProof(entry));
        var proof = await suite.CreateProofAsync(document.RootElement, proofOptions, signer);
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

    private static ISigner CreateSigner()
        => new KeyPairSigner(
            new DefaultKeyGenerator().Generate(KeyType.Ed25519),
            new DefaultCryptoProvider());

    private static byte[] GetLog(DidCreateResult result)
        => Encoding.UTF8.GetBytes((string)result.Artifacts![DidWebVhArtifacts.DidJsonl]);

    private static byte[] GetLog(DidUpdateResult result)
        => Encoding.UTF8.GetBytes((string)result.Artifacts![DidWebVhArtifacts.DidJsonl]);
}
