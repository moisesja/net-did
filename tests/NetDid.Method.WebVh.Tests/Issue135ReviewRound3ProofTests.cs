using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using DataProofsDotnet.DataIntegrity;
using FluentAssertions;
using NetCrypto;
using NetDid.Core.Model;
using NetDid.Method.WebVh.Model;
using Xunit;

namespace NetDid.Method.WebVh.Tests;

/// <summary>
/// Fail-first regression tests for PR #143 review round 3. A witness proof that carries
/// <c>previousProof</c> must be verified with the complete same-version dependency closure,
/// while the public authoring API must be able to carry the complete proof JSON without
/// exposing a caller-settable raw/modeled dual state.
/// </summary>
public sealed class Issue135ReviewRound3ProofTests
{
    private static readonly DateTimeOffset VersionTime =
        new(2026, 8, 23, 12, 0, 0, TimeSpan.Zero);

    private readonly DefaultCryptoProvider _crypto = new();
    private readonly DefaultKeyGenerator _keyGenerator = new();
    private readonly EddsaJcs2022Cryptosuite _suite = new();

    [Fact]
    public async Task Issue135_R3_GenuinePreviousProofChain_ConfiguredChildCounts()
    {
        var chain = await CreateGenuineChainAsync();

        (await new WitnessValidator(maxProofVerifications: 2)
                .ValidateWitnessesAsync(chain.File, chain.Entry, chain.ChildOnlyPolicy))
            .Should().BeTrue(
                "the configured child is valid only when its unconfigured root proof is " +
                "supplied to the Data Integrity pipeline as its previousProof dependency");
    }

    [Fact]
    public async Task Issue135_R3_PreviousProofChain_InvalidRoot_FailsClosed()
    {
        var chain = await CreateGenuineChainAsync();
        var root = JsonNode.Parse(chain.RootProofJson)!.AsObject();
        root["proofValue"] = "z0";
        var tampered = ParseWitnessFile(
            chain.Entry.VersionId, [root.ToJsonString(), chain.ChildProofJson]);

        (await new WitnessValidator(maxProofVerifications: 2)
                .ValidateWitnessesAsync(tampered, chain.Entry, chain.ChildOnlyPolicy))
            .Should().BeFalse(
                "a child proof is valid only if every proof named by previousProof also verifies");
    }

    [Fact]
    public async Task Issue135_R3_PreviousProofChain_DanglingReference_FailsClosed()
    {
        var chain = await CreateGenuineChainAsync();
        var childOnly = ParseWitnessFile(
            chain.Entry.VersionId, [chain.ChildProofJson]);

        (await new WitnessValidator(maxProofVerifications: 2)
                .ValidateWitnessesAsync(childOnly, chain.Entry, chain.ChildOnlyPolicy))
            .Should().BeFalse("a missing previousProof target must never be ignored");
    }

    [Fact]
    public async Task Issue135_R3_PreviousProofCycle_FailsClosedWithoutHanging()
    {
        var signer = CreateSigner();
        var entry = CreateEntry();
        const string proofId = "urn:proof:self-cycle";
        using var unsigned = JsonDocument.Parse(
            $$"""{"versionId":{{JsonSerializer.Serialize(entry.VersionId)}}}""");
        var cyclicProof = await _suite.CreateProofAsync(unsigned.RootElement,
            new DataIntegrityProof
            {
                Id = proofId,
                Cryptosuite = EddsaJcs2022Cryptosuite.CryptosuiteName,
                VerificationMethod = VerificationMethodFor(signer),
                Created = "2026-08-23T12:00:00Z",
                ProofPurpose = "assertionMethod",
                PreviousProof = PreviousProofReference.FromSingle(proofId)
            }, signer);
        var file = ParseWitnessFile(entry.VersionId, [ProofJson(cyclicProof)]);
        var policy = PolicyFor(signer);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(2));

        (await new WitnessValidator(maxProofVerifications: 2)
                .ValidateWitnessesAsync(file, entry, policy, cts.Token))
            .Should().BeFalse("a cyclic proof dependency cannot establish an approval");
    }

    [Theory]
    [InlineData(1, false)]
    [InlineData(2, true)]
    public async Task Issue135_R3_PreviousProofClosure_ChargesActualVerificationBudget(
        int budget, bool expected)
    {
        var chain = await CreateGenuineChainAsync();

        (await new WitnessValidator(maxProofVerifications: budget)
                .ValidateWitnessesAsync(chain.File, chain.Entry, chain.ChildOnlyPolicy))
            .Should().Be(expected,
                "the configured child requires two actual DI verifications: itself and its root");
    }

    [Fact]
    public async Task Issue135_R3_PublicFullProofFactory_DerivesModeledFieldsFromRawJson()
    {
        var chain = await CreateGenuineChainAsync();

        var parsed = ParseWithPublicFullProofFactory(chain.ChildProofJson);

        parsed.RawJson.Should().Be(chain.ChildProofJson);
        parsed.Type.Should().Be("DataIntegrityProof");
        parsed.Cryptosuite.Should().Be(EddsaJcs2022Cryptosuite.CryptosuiteName);
        parsed.VerificationMethod.Should().Be(VerificationMethodFor(chain.ChildSigner));
        parsed.ProofPurpose.Should().Be("assertionMethod");
        parsed.RawJson.Should().Contain("\"previousProof\":\"urn:proof:root\"");
        parsed.RawJson.Should().Contain("\"domain\":\"witness.example\"");
        parsed.RawJson.Should().Contain("\"expires\":\"2030-01-01T00:00:00Z\"");
        parsed.RawJson.Should().Contain("\"x-witness-ext\":\"preserved\"");

        typeof(DataIntegrityProofValue).GetProperty(nameof(DataIntegrityProofValue.RawJson))!
            .SetMethod!.IsPublic.Should().BeFalse(
                "raw proof JSON must be accepted only through a parser that derives the modeled " +
                "authorization fields from those same bytes");
    }

    [Theory]
    [InlineData("[]")]
    [InlineData("null")]
    [InlineData("\"not-a-proof-object\"")]
    public void Issue135_R3_PublicFullProofFactory_NonObject_FailsClosed(string json)
    {
        var act = () => DataIntegrityProofValue.Parse(json);

        act.Should().Throw<JsonException>(
            "the public raw-proof boundary accepts exactly one JSON proof object");
    }

    [Fact]
    public void Issue135_R3_PublicFullProofFactory_DuplicateTopLevelMember_FailsClosed()
    {
        var json =
            """
            {
              "type":"DataIntegrityProof",
              "type":"SpoofedProof",
              "cryptosuite":"eddsa-jcs-2022",
              "verificationMethod":"did:key:z6MkExample#z6MkExample",
              "proofPurpose":"assertionMethod",
              "proofValue":"zExample"
            }
            """;
        var act = () => DataIntegrityProofValue.Parse(json);

        act.Should().Throw<JsonException>(
            "last-one-wins parsing would let raw and modeled authorization fields diverge");
    }

    [Fact]
    public void Issue135_R3_PublicFullProofFactory_DuplicateNestedMember_FailsClosed()
    {
        var json =
            """
            {
              "type":"DataIntegrityProof",
              "cryptosuite":"eddsa-jcs-2022",
              "verificationMethod":"did:key:z6MkExample#z6MkExample",
              "proofPurpose":"assertionMethod",
              "proofValue":"zExample",
              "x-extension":{"decision":"allow","decision":"deny"}
            }
            """;
        var act = () => DataIntegrityProofValue.Parse(json);

        act.Should().Throw<JsonException>(
            "duplicate rejection must recurse into signature-bound extension objects");
    }

    [Theory]
    [InlineData(
        "{\"type\":\"DataIntegrityProof\",\"verificationMethod\":\"did:key:z6MkExample#z6MkExample\",\"proofPurpose\":\"assertionMethod\",\"proofValue\":\"zExample\"}")]
    [InlineData(
        "{\"type\":\"DataIntegrityProof\",\"cryptosuite\":\"eddsa-jcs-2022\",\"verificationMethod\":42,\"proofPurpose\":\"assertionMethod\",\"proofValue\":\"zExample\"}")]
    [InlineData(
        "{\"type\":\"DataIntegrityProof\",\"cryptosuite\":\"eddsa-jcs-2022\",\"verificationMethod\":\"did:key:z6MkExample#z6MkExample\",\"proofPurpose\":\"assertionMethod\"}")]
    public void Issue135_R3_PublicFullProofFactory_MissingOrWrongRequiredMember_FailsClosed(
        string json)
    {
        var act = () => DataIntegrityProofValue.Parse(json);

        act.Should().Throw<JsonException>(
            "every required modeled member must be derived from a string in the raw object");
    }

    [Fact]
    public void Issue135_R3_PublicFullProofFactory_DefaultJsonElement_ThrowsJsonException()
    {
        var act = () => DataIntegrityProofValue.FromJson(default);

        act.Should().Throw<JsonException>(
            "the public FromJson contract must normalize an undefined element to JsonException");
    }

    [Fact]
    public void Issue135_R3_PublicFullProofFactory_DisposedJsonElement_ThrowsJsonException()
    {
        JsonElement element;
        using (var document = JsonDocument.Parse(StandardProofJson()))
            element = document.RootElement;

        var act = () => DataIntegrityProofValue.FromJson(element);

        act.Should().Throw<JsonException>(
            "the public FromJson contract must not leak JsonElement lifetime exceptions");
    }

    [Fact]
    public async Task Issue135_R3_FailedClosure_DoesNotPoisonDependencyVerdictMemo()
    {
        var rootSigner = CreateSigner();
        var intermediateSigner = CreateSigner();
        var childSigner = CreateSigner();
        var alternateSigner = CreateSigner();
        var oldPolicy = PolicyFor(intermediateSigner);
        var newPolicy = new WitnessConfig
        {
            Threshold = 1,
            Witnesses =
            [
                new WitnessEntry { Id = $"did:key:{childSigner.MultibasePublicKey}" },
                new WitnessEntry { Id = $"did:key:{alternateSigner.MultibasePublicKey}" }
            ]
        };
        var entries = new[]
        {
            CreateEntry(1, oldPolicy),
            CreateEntry(2, newPolicy),
            CreateEntry(3, newPolicy)
        };
        var parameters = entries.Select(entry => entry.Parameters).ToArray();
        var pipeline = new DataIntegrityProofPipeline();
        using var unsigned = JsonDocument.Parse(
            $$"""{"versionId":{{JsonSerializer.Serialize(entries[2].VersionId)}}}""");
        var withRoot = await AddProofAsync(
            pipeline, unsigned.RootElement, rootSigner, "urn:proof:root", previousProof: null);
        var withIntermediate = await AddProofAsync(
            pipeline, withRoot, intermediateSigner, "urn:proof:intermediate", "urn:proof:root");
        var withChild = await AddProofAsync(
            pipeline, withIntermediate, childSigner, "urn:proof:child", "urn:proof:intermediate");
        var withAlternate = await AddProofAsync(
            pipeline, withChild, alternateSigner, "urn:proof:alternate", previousProof: null);
        var proofJson = withAlternate.GetProperty("proof").EnumerateArray()
            .Select(proof => proof.GetRawText())
            .ToArray();
        var invalidRoot = JsonNode.Parse(proofJson[0])!.AsObject();
        invalidRoot["proofValue"] = "z0";
        proofJson[0] = invalidRoot.ToJsonString();
        var file = ParseWitnessFile(entries[2].VersionId, proofJson);

        var valid = await new WitnessValidator(maxProofVerifications: 10)
            .ValidateAllWitnessesAsync(file, entries, upToIndex: 2, parameters);

        valid.Should().BeFalse(
            "the latest policy can be satisfied by the alternate proof, but the older policy's " +
            "intermediate proof still depends on the invalid root and must be rechecked as a " +
            "closure instead of consuming a raw per-proof true memo entry");
    }

    [Fact]
    public async Task Issue135_R3_JcsUnrepresentableProof_TargetResolutionFailsAsWitnessValidation()
    {
        var httpClient = new MockWebVhHttpClient();
        var method = new DidWebVhMethod(httpClient);
        var updateSigner = CreateSigner();
        var witnessSigner = CreateSigner();
        var created = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = updateSigner,
            WitnessDids = [$"did:key:{witnessSigner.MultibasePublicKey}"],
            WitnessThreshold = 1
        });
        var did = created.Did.Value;
        var log = (string)created.Artifacts![DidWebVhArtifacts.DidJsonl];
        var entry = LogEntrySerializer.ParseJsonLines(Encoding.UTF8.GetBytes(log))[0];
        var invalidProof = DataIntegrityProofValue.Parse(OverflowProofJson(witnessSigner));
        httpClient.SetLogResponse(DidUrlMapper.MapToLogUrl(did), Encoding.UTF8.GetBytes(log));
        httpClient.SetWitnessResponse(
            DidUrlMapper.MapToWitnessUrl(did),
            WitnessValidator.SerializeWitnessFile(new WitnessFile
            {
                Entries = [new WitnessProofEntry { VersionId = entry.VersionId, Proofs = [invalidProof] }]
            }));

        var resolved = await method.ResolveAsync(did);

        resolved.DidDocument.Should().BeNull();
        resolved.ResolutionMetadata.Error.Should().Be("witnessValidationFailed",
            "JCS-invalid proof data is an invalid witness, not a generic notFound exception");
    }

    [Fact]
    public async Task Issue135_R3_JcsUnrepresentableTailProof_DoesNotPoisonHistoricalResolution()
    {
        var httpClient = new MockWebVhHttpClient();
        var method = new DidWebVhMethod(httpClient);
        var updateSigner = CreateSigner();
        var witnessSigner = CreateSigner();
        var created = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = updateSigner,
            WitnessDids = [$"did:key:{witnessSigner.MultibasePublicKey}"],
            WitnessThreshold = 1
        });
        var deactivated = await method.DeactivateAsync(created.Did.Value,
            new DidWebVhDeactivateOptions
            {
                CurrentLogContent = Encoding.UTF8.GetBytes(
                    (string)created.Artifacts![DidWebVhArtifacts.DidJsonl]),
                SigningKey = updateSigner
            });
        var did = created.Did.Value;
        var log = (string)deactivated.Artifacts![DidWebVhArtifacts.DidJsonl];
        var entries = LogEntrySerializer.ParseJsonLines(Encoding.UTF8.GetBytes(log));
        var validGenesisProof = await SignVersionAsync(entries[0], witnessSigner);
        var invalidTailProof = DataIntegrityProofValue.Parse(OverflowProofJson(witnessSigner));
        httpClient.SetLogResponse(DidUrlMapper.MapToLogUrl(did), Encoding.UTF8.GetBytes(log));
        httpClient.SetWitnessResponse(
            DidUrlMapper.MapToWitnessUrl(did),
            WitnessValidator.SerializeWitnessFile(new WitnessFile
            {
                Entries =
                [
                    new WitnessProofEntry
                    {
                        VersionId = entries[0].VersionId,
                        Proofs = [validGenesisProof]
                    },
                    new WitnessProofEntry
                    {
                        VersionId = entries[1].VersionId,
                        Proofs = [invalidTailProof]
                    }
                ]
            }));

        var resolved = await method.ResolveAsync(did, new DidResolutionOptions
        {
            VersionId = entries[0].VersionId
        });

        resolved.ResolutionMetadata.Error.Should().BeNull();
        resolved.DidDocument.Should().NotBeNull();
        resolved.DocumentMetadata!.Deactivated.Should().NotBeTrue(
            "an invalid optional tail witness must withhold deactivation metadata, not invalidate " +
            "the independently valid historical prefix");
    }

    [Fact]
    public async Task Issue135_R3_Create_PublicFullProofValues_PreserveCompleteProofJson()
    {
        var chain = await CreateGenuineChainAsync();
        var root = ParseWithPublicFullProofFactory(chain.RootProofJson);
        var child = ParseWithPublicFullProofFactory(chain.ChildProofJson);
        var method = new DidWebVhMethod(new MockWebVhHttpClient());

        var result = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = CreateSigner(),
            WitnessProofs =
            [
                new WitnessProofEntry
                {
                    VersionId = chain.Entry.VersionId,
                    Proofs = [root, child]
                }
            ]
        });

        var artifact = (string)result.Artifacts![DidWebVhArtifacts.DidWitnessJson];
        AssertCompleteChildProof(artifact, chain.ChildProofJson);
    }

    [Fact]
    public async Task Issue135_R3_Update_PublicFullProofValues_PreserveCompleteProofJson()
    {
        var chain = await CreateGenuineChainAsync();
        var (method, did, logContent, signingKey) = await CreateDidAsync();

        var result = await method.UpdateAsync(did, new DidWebVhUpdateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(logContent),
            SigningKey = signingKey,
            WitnessProofs =
            [
                new WitnessProofEntry
                {
                    VersionId = chain.Entry.VersionId,
                    Proofs =
                    [
                        DataIntegrityProofValue.Parse(chain.RootProofJson),
                        DataIntegrityProofValue.Parse(chain.ChildProofJson)
                    ]
                }
            ]
        });

        var artifact = (string)result.Artifacts![DidWebVhArtifacts.DidWitnessJson];
        AssertCompleteChildProof(artifact, chain.ChildProofJson);
    }

    [Fact]
    public async Task Issue135_R3_Deactivate_PublicFullProofValues_PreserveCompleteProofJson()
    {
        var chain = await CreateGenuineChainAsync();
        var (method, did, logContent, signingKey) = await CreateDidAsync();

        var result = await method.DeactivateAsync(did, new DidWebVhDeactivateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(logContent),
            SigningKey = signingKey,
            WitnessProofs =
            [
                new WitnessProofEntry
                {
                    VersionId = chain.Entry.VersionId,
                    Proofs =
                    [
                        DataIntegrityProofValue.Parse(chain.RootProofJson),
                        DataIntegrityProofValue.Parse(chain.ChildProofJson)
                    ]
                }
            ]
        });

        var artifact = (string)result.Artifacts![DidWebVhArtifacts.DidWitnessJson];
        AssertCompleteChildProof(artifact, chain.ChildProofJson);
    }

    private async Task<GenuineChain> CreateGenuineChainAsync()
    {
        var rootSigner = CreateSigner();
        var childSigner = CreateSigner();
        var entry = CreateEntry();
        var pipeline = new DataIntegrityProofPipeline();

        using var unsigned = JsonDocument.Parse(
            $$"""{"versionId":{{JsonSerializer.Serialize(entry.VersionId)}}}""");
        var withRoot = await pipeline.AddProofAsync(unsigned.RootElement,
            new DataIntegrityProof
            {
                Id = "urn:proof:root",
                Cryptosuite = EddsaJcs2022Cryptosuite.CryptosuiteName,
                VerificationMethod = VerificationMethodFor(rootSigner),
                Created = "2026-08-23T12:00:00Z",
                ProofPurpose = "assertionMethod"
            }, rootSigner);

        using var extension = JsonDocument.Parse("\"preserved\"");
        var withChain = await pipeline.AddProofAsync(withRoot,
            new DataIntegrityProof
            {
                Id = "urn:proof:child",
                Cryptosuite = EddsaJcs2022Cryptosuite.CryptosuiteName,
                VerificationMethod = VerificationMethodFor(childSigner),
                Created = "2026-08-23T12:00:01Z",
                Expires = "2030-01-01T00:00:00Z",
                Domain = "witness.example",
                ProofPurpose = "assertionMethod",
                PreviousProof = PreviousProofReference.FromSingle("urn:proof:root"),
                AdditionalProperties = new Dictionary<string, JsonElement>
                {
                    ["x-witness-ext"] = extension.RootElement.Clone()
                }
            }, childSigner);

        var proofElements = withChain.GetProperty("proof").EnumerateArray().ToArray();
        var rootJson = proofElements[0].GetRawText();
        var childJson = proofElements[1].GetRawText();
        return new GenuineChain(
            entry,
            childSigner,
            PolicyFor(childSigner),
            ParseWitnessFile(entry.VersionId, [rootJson, childJson]),
            rootJson,
            childJson);
    }

    private async Task<JsonElement> AddProofAsync(
        DataIntegrityProofPipeline pipeline,
        JsonElement document,
        KeyPairSigner signer,
        string id,
        string? previousProof)
        => await pipeline.AddProofAsync(document,
            new DataIntegrityProof
            {
                Id = id,
                Cryptosuite = EddsaJcs2022Cryptosuite.CryptosuiteName,
                VerificationMethod = VerificationMethodFor(signer),
                Created = "2026-08-23T12:00:00Z",
                ProofPurpose = "assertionMethod",
                PreviousProof = previousProof is null
                    ? null
                    : PreviousProofReference.FromSingle(previousProof)
            }, signer);

    private async Task<DataIntegrityProofValue> SignVersionAsync(
        LogEntry entry,
        KeyPairSigner signer)
    {
        using var document = JsonDocument.Parse(
            $$"""{"versionId":{{JsonSerializer.Serialize(entry.VersionId)}}}""");
        var proof = await _suite.CreateProofAsync(document.RootElement,
            new DataIntegrityProof
            {
                Cryptosuite = EddsaJcs2022Cryptosuite.CryptosuiteName,
                VerificationMethod = VerificationMethodFor(signer),
                Created = entry.VersionTime.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"),
                ProofPurpose = "assertionMethod"
            }, signer);

        return DataIntegrityProofValue.Parse(ProofJson(proof));
    }

    private static string StandardProofJson() =>
        """
        {
          "type":"DataIntegrityProof",
          "cryptosuite":"eddsa-jcs-2022",
          "verificationMethod":"did:key:z6MkExample#z6MkExample",
          "proofPurpose":"assertionMethod",
          "proofValue":"zExample"
        }
        """;

    private static string OverflowProofJson(ISigner signer) =>
        $$"""
        {
          "type":"DataIntegrityProof",
          "cryptosuite":"eddsa-jcs-2022",
          "verificationMethod":{{JsonSerializer.Serialize(VerificationMethodFor(signer))}},
          "created":"2026-08-23T12:00:00Z",
          "proofPurpose":"assertionMethod",
          "proofValue":"zInvalid",
          "x-overflow":1e400
        }
        """;

    private KeyPairSigner CreateSigner()
        => new(_keyGenerator.Generate(KeyType.Ed25519), _crypto);

    private async Task<(DidWebVhMethod Method, string Did, string LogContent, KeyPairSigner SigningKey)>
        CreateDidAsync()
    {
        var method = new DidWebVhMethod(new MockWebVhHttpClient());
        var signingKey = CreateSigner();
        var result = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = signingKey
        });

        return (
            method,
            result.Did.Value,
            (string)result.Artifacts![DidWebVhArtifacts.DidJsonl],
            signingKey);
    }

    private static LogEntry CreateEntry() => new()
    {
        VersionId = "1-zIssue135Round3WitnessChain",
        VersionTime = VersionTime,
        Parameters = new LogEntryParameters(),
        State = new DidDocument { Id = new Did("did:example:issue135-round3") }
    };

    private static LogEntry CreateEntry(int version, WitnessConfig policy) => new()
    {
        VersionId = $"{version}-zIssue135Round3Memo{version}",
        VersionTime = VersionTime.AddMinutes(version - 1),
        Parameters = new LogEntryParameters { Witness = policy },
        State = new DidDocument { Id = new Did("did:example:issue135-round3-memo") }
    };

    private static WitnessConfig PolicyFor(ISigner signer) => new()
    {
        Threshold = 1,
        Witnesses = [new WitnessEntry { Id = $"did:key:{signer.MultibasePublicKey}" }]
    };

    private static string VerificationMethodFor(ISigner signer)
        => $"did:key:{signer.MultibasePublicKey}#{signer.MultibasePublicKey}";

    private static WitnessFile ParseWitnessFile(string versionId, IReadOnlyList<string> proofJson)
    {
        var json = Encoding.UTF8.GetBytes(
            $$"""[{"versionId":{{JsonSerializer.Serialize(versionId)}},"proof":[{{string.Join(',', proofJson)}}]}]""");
        var parsed = WitnessValidator.ParseWitnessFile(json, out var parseError);
        parsed.Should().NotBeNull(parseError);
        return parsed!;
    }

    private static DataIntegrityProofValue ParseWithPublicFullProofFactory(string proofJson)
        => DataIntegrityProofValue.Parse(proofJson);

    private static void AssertCompleteChildProof(string artifact, string expectedRawJson)
    {
        using var document = JsonDocument.Parse(artifact);
        var proofs = document.RootElement[0].GetProperty("proof");
        proofs.GetArrayLength().Should().Be(2);
        var emittedChild = proofs[1];
        emittedChild.GetRawText().Should().Be(expectedRawJson,
            "authoring operations must transport the complete parsed proof object verbatim");
        emittedChild.GetProperty("id").GetString().Should().Be("urn:proof:child");
        emittedChild.GetProperty("previousProof").GetString().Should().Be("urn:proof:root");
        emittedChild.GetProperty("domain").GetString().Should().Be("witness.example");
        emittedChild.GetProperty("expires").GetString().Should().Be("2030-01-01T00:00:00Z");
        emittedChild.GetProperty("x-witness-ext").GetString().Should().Be("preserved");
    }

    private static string ProofJson(DataIntegrityProof proof)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            if (proof.Id is not null)
                writer.WriteString("id", proof.Id);
            writer.WriteString("type", proof.Type);
            writer.WriteString("cryptosuite", proof.Cryptosuite);
            writer.WriteString("verificationMethod", proof.VerificationMethod);
            if (proof.Created is not null)
                writer.WriteString("created", proof.Created);
            writer.WriteString("proofPurpose", proof.ProofPurpose);
            if (proof.PreviousProof is { } previousProof)
            {
                writer.WritePropertyName("previousProof");
                if (previousProof.IsArrayForm)
                {
                    writer.WriteStartArray();
                    foreach (var value in previousProof.Values)
                        writer.WriteStringValue(value);
                    writer.WriteEndArray();
                }
                else
                {
                    writer.WriteStringValue(previousProof.Values[0]);
                }
            }
            writer.WriteString("proofValue", proof.ProofValue);
            writer.WriteEndObject();
        }

        return Encoding.UTF8.GetString(stream.ToArray());
    }

    private sealed record GenuineChain(
        LogEntry Entry,
        KeyPairSigner ChildSigner,
        WitnessConfig ChildOnlyPolicy,
        WitnessFile File,
        string RootProofJson,
        string ChildProofJson);
}
