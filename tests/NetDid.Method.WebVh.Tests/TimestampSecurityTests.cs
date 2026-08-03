using System.Globalization;
using System.Text;
using System.Text.Json;
using DataProofsDotnet.DataIntegrity;
using FluentAssertions;
using NetCrypto;
using NetDid.Core.Model;
using NetDid.Method.WebVh.Model;

namespace NetDid.Method.WebVh.Tests;

[Collection("Culture-sensitive")]
public sealed class TimestampSecurityTests
{
    [Fact]
    public async Task CreateAndResolve_UseInvariantTimestampsAcrossCultures()
    {
        var httpClient = new MockWebVhHttpClient();
        var method = new DidWebVhMethod(httpClient);
        var signer = CreateEd25519Signer();
        string did;
        string logContent;
        string versionTime;

        using (new CultureScope("th-TH"))
        {
            var createResult = await method.CreateAsync(new DidWebVhCreateOptions
            {
                Domain = "example.com",
                UpdateKey = signer
            });

            did = createResult.Did.Value;
            logContent = (string)createResult.Artifacts![DidWebVhArtifacts.DidJsonl];

            using var log = JsonDocument.Parse(logContent);
            versionTime = log.RootElement.GetProperty("versionTime").GetString()!;
            var proofCreated = log.RootElement.GetProperty("proof")[0]
                .GetProperty("created").GetString();

            versionTime.Should().EndWith("Z");
            WebVhTimestamp.Parse(versionTime).Should().BeCloseTo(
                DateTimeOffset.UtcNow,
                TimeSpan.FromMinutes(1));
            proofCreated.Should().Be(versionTime);
        }

        httpClient.SetLogResponse(
            DidUrlMapper.MapToLogUrl(did),
            Encoding.UTF8.GetBytes(logContent));

        using (new CultureScope("ar-SA"))
        {
            var exactResult = await method.ResolveAsync(did, new DidResolutionOptions
            {
                VersionTime = versionTime
            });
            var beforeCreationResult = await method.ResolveAsync(did, new DidResolutionOptions
            {
                VersionTime = "2000-01-01T00:00:00Z"
            });

            exactResult.DidDocument.Should().NotBeNull();
            beforeCreationResult.DidDocument.Should().BeNull();
            beforeCreationResult.ResolutionMetadata.Error.Should().Be("notFound");
        }
    }

    [Fact]
    public async Task Resolve_RejectsFractionalVersionTimeTampering()
    {
        var httpClient = new MockWebVhHttpClient();
        var method = new DidWebVhMethod(httpClient);
        var signer = CreateEd25519Signer();
        var createResult = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = signer
        });
        var did = createResult.Did.Value;
        var logContent = (string)createResult.Artifacts![DidWebVhArtifacts.DidJsonl];

        using var log = JsonDocument.Parse(logContent);
        var originalVersionTime = log.RootElement.GetProperty("versionTime").GetString()!;
        var tamperedVersionTime = WebVhTimestamp.Format(
            WebVhTimestamp.Parse(originalVersionTime).AddTicks(1));
        var tamperedLog = logContent.Replace(
            $"\"versionTime\":\"{originalVersionTime}\"",
            $"\"versionTime\":\"{tamperedVersionTime}\"",
            StringComparison.Ordinal);

        tamperedVersionTime.Should().NotBe(originalVersionTime);
        tamperedLog.Should().NotBe(logContent);
        httpClient.SetLogResponse(
            DidUrlMapper.MapToLogUrl(did),
            Encoding.UTF8.GetBytes(tamperedLog));

        var result = await method.ResolveAsync(did);

        result.DidDocument.Should().BeNull();
        result.ResolutionMetadata.Error.Should().Be("invalidDidLog");
    }

    [Fact]
    public async Task Resolve_RejectsEquivalentVersionTimeWireRewrite()
    {
        var httpClient = new MockWebVhHttpClient();
        var method = new DidWebVhMethod(httpClient);
        var createResult = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = CreateEd25519Signer()
        });
        var did = createResult.Did.Value;
        var logContent = (string)createResult.Artifacts![DidWebVhArtifacts.DidJsonl];

        using var log = JsonDocument.Parse(logContent);
        var original = log.RootElement.GetProperty("versionTime").GetString()!;
        var equivalent = original[..^1] + "+00:00";
        var tamperedLog = logContent.Replace(
            $"\"versionTime\":\"{original}\"",
            $"\"versionTime\":\"{equivalent}\"",
            StringComparison.Ordinal);

        WebVhTimestamp.Parse(equivalent).Should().Be(WebVhTimestamp.Parse(original));
        httpClient.SetLogResponse(
            DidUrlMapper.MapToLogUrl(did),
            Encoding.UTF8.GetBytes(tamperedLog));

        var result = await method.ResolveAsync(did);

        result.DidDocument.Should().BeNull();
        result.ResolutionMetadata.Error.Should().Be("invalidDidLog");
    }

    [Fact]
    public async Task Resolve_NonUtcLogVersionTime_ReturnsInvalidDidLog()
    {
        var httpClient = new MockWebVhHttpClient();
        var method = new DidWebVhMethod(httpClient);
        var createResult = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = CreateEd25519Signer()
        });
        var did = createResult.Did.Value;
        var logContent = (string)createResult.Artifacts![DidWebVhArtifacts.DidJsonl];

        using var log = JsonDocument.Parse(logContent);
        var original = log.RootElement.GetProperty("versionTime").GetString()!;
        var nonUtc = original[..^1] + "+02:00";
        var malformedLog = logContent.Replace(
            $"\"versionTime\":\"{original}\"",
            $"\"versionTime\":\"{nonUtc}\"",
            StringComparison.Ordinal);

        malformedLog.Should().NotBe(logContent);
        httpClient.SetLogResponse(
            DidUrlMapper.MapToLogUrl(did),
            Encoding.UTF8.GetBytes(malformedLog));

        var result = await method.ResolveAsync(did);

        result.DidDocument.Should().BeNull();
        result.ResolutionMetadata.Error.Should().Be("invalidDidLog");
    }

    [Theory]
    [InlineData("null")]
    [InlineData("123")]
    [InlineData("true")]
    [InlineData("{}")]
    [InlineData("[]")]
    public async Task Resolve_NonStringVersionTimeToken_ReturnsInvalidDidLog(string token)
    {
        var httpClient = new MockWebVhHttpClient();
        var method = new DidWebVhMethod(httpClient);
        var createResult = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = CreateEd25519Signer()
        });
        var did = createResult.Did.Value;
        var logContent = (string)createResult.Artifacts![DidWebVhArtifacts.DidJsonl];
        using var log = JsonDocument.Parse(logContent);
        var original = log.RootElement.GetProperty("versionTime").GetRawText();
        var malformedLog = logContent.Replace(original, token, StringComparison.Ordinal);
        httpClient.SetLogResponse(
            DidUrlMapper.MapToLogUrl(did),
            Encoding.UTF8.GetBytes(malformedLog));

        var result = await method.ResolveAsync(did);

        result.DidDocument.Should().BeNull();
        result.ResolutionMetadata.Error.Should().Be("invalidDidLog");
    }

    [Fact]
    public async Task Resolve_MissingVersionTime_ReturnsInvalidDidLog()
    {
        var httpClient = new MockWebVhHttpClient();
        var method = new DidWebVhMethod(httpClient);
        var createResult = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = CreateEd25519Signer()
        });
        var did = createResult.Did.Value;
        var logContent = (string)createResult.Artifacts![DidWebVhArtifacts.DidJsonl];
        using var log = JsonDocument.Parse(logContent);
        var versionTimeProperty =
            $"\"versionTime\":{log.RootElement.GetProperty("versionTime").GetRawText()},";
        var malformedLog = logContent.Replace(
            versionTimeProperty, string.Empty, StringComparison.Ordinal);
        httpClient.SetLogResponse(
            DidUrlMapper.MapToLogUrl(did),
            Encoding.UTF8.GetBytes(malformedLog));

        var result = await method.ResolveAsync(did);

        result.DidDocument.Should().BeNull();
        result.ResolutionMetadata.Error.Should().Be("invalidDidLog");
    }

    [Fact]
    public async Task Resolve_InvalidVersionTimeQuery_DoesNotFallBackToLatest()
    {
        var httpClient = new MockWebVhHttpClient();
        var method = new DidWebVhMethod(httpClient);
        var createResult = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = CreateEd25519Signer()
        });
        var did = createResult.Did.Value;
        httpClient.SetLogResponse(
            DidUrlMapper.MapToLogUrl(did),
            Encoding.UTF8.GetBytes(
                (string)createResult.Artifacts![DidWebVhArtifacts.DidJsonl]));

        var result = await method.ResolveAsync(did, new DidResolutionOptions
        {
            VersionTime = "not-a-timestamp"
        });

        result.DidDocument.Should().BeNull();
        result.ResolutionMetadata.Error.Should().Be("notFound");
    }

    [Theory]
    [InlineData("2026-07-10T12:00:00")]
    [InlineData("2026-07-10 12:00:00Z")]
    [InlineData("2026-07-10T12:00:00+01:00")]
    public void TimestampParser_RejectsNonUtcOrNonCanonicalForms(string value)
    {
        WebVhTimestamp.TryParse(value, out _).Should().BeFalse();
        var act = () => WebVhTimestamp.Parse(value);
        act.Should().Throw<FormatException>();
    }

    [Fact]
    public void FindTargetIndex_UsesAuthenticatedFractionalPrecision()
    {
        var first = new DateTimeOffset(2026, 7, 10, 12, 0, 0, 100, TimeSpan.Zero);
        var second = new DateTimeOffset(2026, 7, 10, 12, 0, 0, 900, TimeSpan.Zero);
        var entries = new[]
        {
            CreateSelectionEntry("1-zFirst", first),
            CreateSelectionEntry("2-zSecond", second)
        };

        var selected = DidWebVhMethod.FindTargetIndex(entries, new DidResolutionOptions
        {
            VersionTime = "2026-07-10T12:00:00.5Z"
        });

        selected.Should().Be(0);
    }

    [Fact]
    public async Task Issue117_ResolvedVersionTime_ReSelectsSameFractionalWebVhVersion()
    {
        // NetDid now authors whole-second versionTimes (issue #127), so the fractional
        // version comes from a hand-built (imported-style) authenticated entry: the
        // fractional-fidelity property this pins is unchanged.
        var httpClient = new MockWebVhHttpClient();
        var method = new DidWebVhMethod(httpClient);
        var (did, entries) = await CreateChainWithFractionalSecondEntryAsync(method);
        var entry = entries[^1];
        entry.VersionTime.Ticks.Should().NotBe(0);
        (entry.VersionTime.Ticks % TimeSpan.TicksPerSecond).Should().NotBe(0,
            "the regression requires a version that whole-second serialization would lose");
        httpClient.SetLogResponse(
            DidUrlMapper.MapToLogUrl(did), LogEntrySerializer.ToJsonLines(entries));

        var latest = await method.ResolveAsync(did);
        var json = JsonSerializer.Serialize(latest.DocumentMetadata,
            new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase });
        using var parsed = JsonDocument.Parse(json);
        var serializedVersionTime = parsed.RootElement.GetProperty("versionTime").GetString();
        var mappedVersionTime = latest.DocumentMetadata!.ToPropertyDictionary()["versionTime"]
            .Should().BeOfType<string>().Subject;

        serializedVersionTime.Should().Be(WebVhTimestamp.Format(entry.VersionTime));
        mappedVersionTime.Should().Be(serializedVersionTime);

        var selected = await method.ResolveAsync(did, new DidResolutionOptions
        {
            VersionTime = mappedVersionTime
        });

        selected.ResolutionMetadata.Error.Should().BeNull();
        selected.DocumentMetadata!.VersionId.Should().Be(latest.DocumentMetadata.VersionId,
            "reusing serialized resolution metadata must select the same authenticated version");
    }

    #region Issue127 — whole-second authored versionTimes

    [Fact]
    public async Task Issue127_Create_EmitsWholeSecondVersionTime_MatchingSerializedCreated()
    {
        var method = new DidWebVhMethod(new MockWebVhHttpClient());

        var createResult = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = CreateEd25519Signer()
        });

        var logContent = (string)createResult.Artifacts![DidWebVhArtifacts.DidJsonl];
        var entry = LogEntrySerializer.ParseJsonLines(Encoding.UTF8.GetBytes(logContent))[0];
        (entry.VersionTime.Ticks % TimeSpan.TicksPerSecond).Should().Be(0,
            "authored versionTimes must survive the DID Core whole-second created/updated projection");

        var json = JsonSerializer.Serialize(createResult.Metadata,
            new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase });
        using var parsed = JsonDocument.Parse(json);
        parsed.RootElement.GetProperty("created").GetString().Should().Be(
            parsed.RootElement.GetProperty("versionTime").GetString(),
            "for a NetDid-authored log the whole-second and fractional-preserving projections coincide");
    }

    [Fact]
    public async Task Issue127_UpdateBurst_EmitsStrictlyIncreasingWholeSecondVersionTimes()
    {
        var (_, _, entries) = await CreateBurstLogAsync(updates: 3);

        entries.Should().HaveCount(4);
        foreach (var entry in entries)
            (entry.VersionTime.Ticks % TimeSpan.TicksPerSecond).Should().Be(0,
                "same-second bursts must advance by whole seconds, not fractional ticks");
        for (var i = 1; i < entries.Count; i++)
            entries[i].VersionTime.Should().BeAfter(entries[i - 1].VersionTime);

        await new LogChainValidator().ValidateChainAsync(entries);
    }

    [Fact]
    public async Task Issue127_SerializedUpdated_RoundTripsAsVersionTimeSelector()
    {
        var (did, httpClient, entries) = await CreateBurstLogAsync(updates: 2);
        httpClient.SetLogResponse(
            DidUrlMapper.MapToLogUrl(did), LogEntrySerializer.ToJsonLines(entries));
        var method = new DidWebVhMethod(httpClient);

        var latest = await method.ResolveAsync(did);
        var json = JsonSerializer.Serialize(latest.DocumentMetadata,
            new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase });
        using var parsed = JsonDocument.Parse(json);
        var serializedUpdated = parsed.RootElement.GetProperty("updated").GetString();
        serializedUpdated.Should().Be(
            parsed.RootElement.GetProperty("versionTime").GetString(),
            "the whole-second and fractional projections of an authored instant must coincide");

        var reselected = await method.ResolveAsync(did, new DidResolutionOptions
        {
            VersionTime = serializedUpdated
        });

        reselected.ResolutionMetadata.Error.Should().BeNull();
        reselected.DocumentMetadata!.VersionId.Should().Be(latest.DocumentMetadata!.VersionId,
            "serialized 'updated' must identify the version it came from for NetDid-authored logs");
    }

    [Fact]
    public async Task Issue127_FractionalImportedLog_PinsLossyCreatedUpdated_AndExactVersionTimeSelector()
    {
        var httpClient = new MockWebVhHttpClient();
        var method = new DidWebVhMethod(httpClient);
        var (did, entries) = await CreateChainWithFractionalSecondEntryAsync(method);
        httpClient.SetLogResponse(
            DidUrlMapper.MapToLogUrl(did), LogEntrySerializer.ToJsonLines(entries));

        var latest = await method.ResolveAsync(did);
        latest.ResolutionMetadata.Error.Should().BeNull();

        var json = JsonSerializer.Serialize(latest.DocumentMetadata,
            new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase });
        using var parsed = JsonDocument.Parse(json);
        var mapped = latest.DocumentMetadata!.ToPropertyDictionary();

        // Documented residual (issue #127 Option A): for imported fractional logs the DID
        // Core-mandated whole-second created/updated CANNOT identify the version; only
        // versionTime/versionId are selectors.
        var expectedLossyUpdated = WebVhTimestamp.Format(
            WebVhTimestamp.TruncateToWholeSecond(entries[^1].VersionTime));
        parsed.RootElement.GetProperty("updated").GetString().Should().Be(expectedLossyUpdated);
        mapped["updated"].Should().Be(expectedLossyUpdated);
        var serializedVersionTime = parsed.RootElement.GetProperty("versionTime").GetString();
        serializedVersionTime.Should().Be(WebVhTimestamp.Format(entries[^1].VersionTime));
        serializedVersionTime.Should().NotBe(expectedLossyUpdated,
            "the fixture must exercise a version the whole-second projection loses");

        var reselected = await method.ResolveAsync(did, new DidResolutionOptions
        {
            VersionTime = serializedVersionTime
        });
        reselected.ResolutionMetadata.Error.Should().BeNull();
        reselected.DocumentMetadata!.VersionId.Should().Be(latest.DocumentMetadata.VersionId,
            "fractional imported logs must keep full-precision selection");
    }

    private static async Task<(string Did, MockWebVhHttpClient HttpClient, IReadOnlyList<LogEntry> Entries)>
        CreateBurstLogAsync(int updates)
    {
        var httpClient = new MockWebVhHttpClient();
        var method = new DidWebVhMethod(httpClient);
        var signer = CreateEd25519Signer();
        var createResult = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = signer
        });
        var did = createResult.Did.Value;
        var logContent = (string)createResult.Artifacts![DidWebVhArtifacts.DidJsonl];

        for (var i = 0; i < updates; i++)
        {
            var updateResult = await method.UpdateAsync(did, new DidWebVhUpdateOptions
            {
                CurrentLogContent = Encoding.UTF8.GetBytes(logContent),
                SigningKey = signer
            });
            logContent = (string)updateResult.Artifacts![DidWebVhArtifacts.DidJsonl];
        }

        var entries = LogEntrySerializer.ParseJsonLines(Encoding.UTF8.GetBytes(logContent));
        return (did, httpClient, entries);
    }

    /// <summary>
    /// Genesis via CreateAsync, then a hand-built authenticated second entry whose
    /// versionTime carries sub-second precision — the shape of a log imported from an
    /// implementation that authors fractional timestamps.
    /// </summary>
    private static async Task<(string Did, IReadOnlyList<LogEntry> Entries)>
        CreateChainWithFractionalSecondEntryAsync(DidWebVhMethod method)
    {
        var signer = CreateEd25519Signer();
        var created = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = signer
        });
        var genesisJson = (string)created.Artifacts![DidWebVhArtifacts.DidJsonl];
        var genesis = LogEntrySerializer.ParseJsonLines(Encoding.UTF8.GetBytes(genesisJson))[0];

        var entryForHashing = new LogEntry
        {
            VersionId = genesis.VersionId,
            VersionTime = genesis.VersionTime.AddMilliseconds(900),
            Parameters = new LogEntryParameters(),
            State = genesis.State
        };
        var entryHash = ScidGenerator.ComputeEntryHash(
            LogEntrySerializer.SerializeWithoutProof(entryForHashing));
        var second = entryForHashing with { VersionId = $"2-{entryHash}" };
        second = second with { Proof = [await SignEntryAsync(second, signer)] };

        return (created.Did.Value, new[] { genesis, second });
    }

    private static async Task<DataIntegrityProofValue> SignEntryAsync(LogEntry entry, ISigner signer)
    {
        var suite = new EddsaJcs2022Cryptosuite();
        var options = new DataIntegrityProof
        {
            Cryptosuite = EddsaJcs2022Cryptosuite.CryptosuiteName,
            VerificationMethod = $"did:key:{signer.MultibasePublicKey}#{signer.MultibasePublicKey}",
            Created = WebVhTimestamp.Format(entry.VersionTime),
            ProofPurpose = "assertionMethod"
        };
        using var document = JsonDocument.Parse(LogEntrySerializer.SerializeWithoutProof(entry));
        var proof = await suite.CreateProofAsync(document.RootElement, options, signer);

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

    #endregion

    [Fact]
    public void FindTargetIndex_StopsBeforeNonMonotonicTailBeyondRequestedTime()
    {
        var first = new DateTimeOffset(2026, 7, 10, 10, 0, 0, TimeSpan.Zero);
        var entries = new[]
        {
            CreateSelectionEntry("1-zFirst", first),
            CreateSelectionEntry("2-zSecond", first.AddHours(10)),
            CreateSelectionEntry("3-zInvalidTail", first.AddHours(5))
        };

        var selected = DidWebVhMethod.FindTargetIndex(entries, new DidResolutionOptions
        {
            VersionTime = "2026-07-10T17:00:00Z"
        });

        selected.Should().Be(0);
    }

    private static LogEntry CreateSelectionEntry(string versionId, DateTimeOffset versionTime)
        => new()
        {
            VersionId = versionId,
            VersionTime = versionTime,
            Parameters = new LogEntryParameters(),
            State = new DidDocument { Id = new Did("did:example:timestamp-selection") }
        };

    private static ISigner CreateEd25519Signer()
    {
        var keyPair = new DefaultKeyGenerator().Generate(KeyType.Ed25519);
        return new KeyPairSigner(keyPair, new DefaultCryptoProvider());
    }

    private sealed class CultureScope : IDisposable
    {
        private readonly CultureInfo _originalCulture = CultureInfo.CurrentCulture;
        private readonly CultureInfo _originalUiCulture = CultureInfo.CurrentUICulture;

        public CultureScope(string name)
        {
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo(name);
            CultureInfo.CurrentUICulture = CultureInfo.GetCultureInfo(name);
        }

        public void Dispose()
        {
            CultureInfo.CurrentCulture = _originalCulture;
            CultureInfo.CurrentUICulture = _originalUiCulture;
        }
    }
}
