using System.Text;
using System.Text.Json;
using DataProofsDotnet.DataIntegrity;
using FluentAssertions;
using NetCrypto;
using NetDid.Core.Model;
using NetDid.Method.WebVh.Model;
using Xunit;

namespace NetDid.Method.WebVh.Tests;

/// <summary>
/// Regression tests for issue #135: did-witness.json interoperability.
///
/// Two wire divergences made every witnessed did:webvh DID non-interoperable in both directions:
///
///   • the file's per-version member was written and read as <c>proofs</c>, while did:webvh v1.0
///     and all six DIF-suite reference implementations use <c>proof</c>;
///   • witness proofs were verified against the log entry serialized without its proof, while the
///     spec defines them as Data Integrity proofs "that use the versionId as input data" — the
///     JCS document <c>{"versionId":"..."}</c> (confirmed against ts, rust, java and dart suite
///     vectors). The versionId embeds the entry hash that chain validation independently
///     recomputes, so a versionId proof still binds the whole entry content transitively.
///
/// The known-answer tests replay committed DIF didwebvh-test-suite vectors (suite pinned at
/// f792ce4, ts implementation) so the wire format is checked against an artifact NetDid did not
/// produce — the class of defect self-generated round-trip tests cannot see (#95, #135).
/// </summary>
public class Issue135WitnessInteropTests
{
    private readonly DefaultCryptoProvider _crypto = new();
    private readonly DefaultKeyGenerator _keyGenerator = new();
    private readonly EddsaJcs2022Cryptosuite _suite = new();

    private static string FixturePath(string name)
        => Path.Combine(AppContext.BaseDirectory, "Fixtures", name);

    private static (string Did, byte[] Log, byte[] Witness) SuiteFixture(string prefix)
    {
        var log = File.ReadAllBytes(FixturePath($"{prefix}-did.jsonl"));
        var witness = File.ReadAllBytes(FixturePath($"{prefix}-did-witness.json"));
        var genesisLine = Encoding.UTF8.GetString(log)
            .Split('\n', StringSplitOptions.RemoveEmptyEntries)[0];
        using var doc = JsonDocument.Parse(genesisLine);
        var did = doc.RootElement.GetProperty("state").GetProperty("id").GetString()!;
        return (did, log, witness);
    }

    private static async Task<DidResolutionResult> ResolveFixtureAsync(string prefix)
    {
        var (did, log, witness) = SuiteFixture(prefix);
        var http = new MockWebVhHttpClient();
        http.SetLogResponse(DidUrlMapper.MapToLogUrl(did), log);
        http.SetWitnessResponse(DidUrlMapper.MapToWitnessUrl(did), witness);
        return await new DidWebVhMethod(http).ResolveAsync(did);
    }

    #region Known-answer: happy-path suite vectors must resolve

    [Fact]
    public async Task Issue135_SuiteWitnessThresholdLog_Resolves()
    {
        var result = await ResolveFixtureAsync("issue135-witness-threshold-ts");

        result.ResolutionMetadata.Error.Should().BeNull(
            "a witnessed log and did-witness.json authored by the reference ts implementation " +
            "must validate — rejection means our witness wire format does not interoperate");
        result.DidDocument.Should().NotBeNull();
    }

    [Fact]
    public async Task Issue135_SuiteWitnessUpdateLog_Resolves()
    {
        var result = await ResolveFixtureAsync("issue135-witness-update-ts");

        result.ResolutionMetadata.Error.Should().BeNull(
            "a witnessed multi-version log authored by the reference ts implementation " +
            "must validate across its witness policy transition");
        result.DidDocument.Should().NotBeNull();
    }

    /// <summary>
    /// Fixture-drift guard: the committed suite artifacts really carry the spec's wire shape —
    /// a <c>proof</c> member and never the non-conformant <c>proofs</c> this issue fixed.
    /// </summary>
    [Fact]
    public void Issue135_SuiteWitnessFixtures_UseSpecProofMember()
    {
        foreach (var prefix in new[]
        {
            "issue135-witness-threshold-ts",
            "issue135-witness-update-ts",
            "issue135-negative-threshold-not-met-ts",
            "issue135-negative-cross-did-replay-ts"
        })
        {
            var text = Encoding.UTF8.GetString(
                File.ReadAllBytes(FixturePath($"{prefix}-did-witness.json")));
            text.Should().Contain("\"proof\"", $"{prefix} must carry the spec member");
            text.Should().NotContain("\"proofs\"", $"{prefix} must not carry the legacy member");
        }
    }

    #endregion

    #region Known-answer: negative suite vectors must still be rejected — by witness logic

    /// <summary>
    /// Pre-fix, this vector was rejected vacuously: the witness file failed to parse before any
    /// witness security logic ran. Post-fix the file parses and the rejection must come from the
    /// real defence — the entry that disables the witness policy is itself governed by the prior
    /// threshold-1 policy and carries no witness proof.
    /// </summary>
    [Fact]
    public async Task Issue135_SuiteCrossDidWitnessReplay_IsRejectedByWitnessValidation()
    {
        var result = await ResolveFixtureAsync("issue135-negative-cross-did-replay-ts");

        result.DidDocument.Should().BeNull();
        result.ResolutionMetadata.Error.Should().Be("witnessValidationFailed");
    }

    /// <summary>
    /// Pre-fix this rejection also happened at parse time. Post-fix the witness file parses, its
    /// proofs verify, and the rejection must come from threshold arithmetic: the governed later
    /// version is covered by fewer distinct configured witnesses than the active threshold.
    /// </summary>
    [Fact]
    public async Task Issue135_SuiteWitnessThresholdNotMet_IsRejectedByWitnessValidation()
    {
        var result = await ResolveFixtureAsync("issue135-negative-threshold-not-met-ts");

        result.DidDocument.Should().BeNull();
        result.ResolutionMetadata.Error.Should().Be("witnessValidationFailed");
    }

    #endregion

    #region Wire format: proof member name

    [Fact]
    public async Task Issue135_SerializeWitnessFile_WritesSpecProofMember()
    {
        var signer = CreateSigner();
        var entry = CreateEntry(1, PolicyFor(signer, threshold: 1));
        var witnessFile = new WitnessFile
        {
            Entries =
            [
                new WitnessProofEntry
                {
                    VersionId = entry.VersionId,
                    Proofs = [await SignVersionAsync(entry.VersionId, signer)]
                }
            ]
        };

        var json = Encoding.UTF8.GetString(WitnessValidator.SerializeWitnessFile(witnessFile));

        json.Should().Contain("\"proof\"", "did:webvh v1.0 names the member proof");
        json.Should().NotContain("\"proofs\"", "the legacy member name interoperates with nothing");
    }

    [Fact]
    public void Issue135_ParseWitnessFile_ReadsSpecProofMember()
    {
        var json = """
        [
            {
                "versionId": "1-QmTest",
                "proof": [
                    {
                        "type": "DataIntegrityProof",
                        "cryptosuite": "eddsa-jcs-2022",
                        "verificationMethod": "did:key:z6MkTest#z6MkTest",
                        "created": "2026-01-01T00:00:00Z",
                        "proofPurpose": "assertionMethod",
                        "proofValue": "zTestValue"
                    }
                ]
            }
        ]
        """;

        var witnessFile = WitnessValidator.ParseWitnessFile(Encoding.UTF8.GetBytes(json));

        witnessFile.Should().NotBeNull();
        witnessFile!.Entries.Should().ContainSingle();
        witnessFile.Entries[0].VersionId.Should().Be("1-QmTest");
        witnessFile.Entries[0].Proofs.Should().ContainSingle();
    }

    [Fact]
    public void Issue135_ParseWitnessFile_MalformedFile_ReportsParseReason()
    {
        var parsed = WitnessValidator.ParseWitnessFile(
            Encoding.UTF8.GetBytes("not-valid-json"), out var parseError);

        parsed.Should().BeNull();
        parseError.Should().NotBeNullOrEmpty(
            "a swallowed parse failure surfaces as a bare witnessValidationFailed with no " +
            "diagnostic — exactly how #135 went unnoticed");
        parseError.Should().Contain("Exception", "the reason names the failure type");
    }

    [Fact]
    public void Issue135_ParseWitnessFile_NonArrayRoot_ReportsParseReason()
    {
        var parsed = WitnessValidator.ParseWitnessFile(
            Encoding.UTF8.GetBytes("""{"versionId":"1-QmTest","proof":[]}"""), out var parseError);

        parsed.Should().BeNull();
        parseError.Should().Contain("array");
    }

    [Fact]
    public void Issue135_ParseWitnessFile_RejectsDuplicateMembers()
    {
        // Last-one-wins duplicate parsing would let a decoy member smuggle unvalidated content
        // past validation (same trust-boundary rule as the log-entry parser, issue #101).
        var json = """
        [
            {
                "versionId": "1-QmTest",
                "proof": [],
                "proof": [
                    {
                        "type": "DataIntegrityProof",
                        "cryptosuite": "eddsa-jcs-2022",
                        "verificationMethod": "did:key:z6MkTest#z6MkTest",
                        "created": "2026-01-01T00:00:00Z",
                        "proofPurpose": "assertionMethod",
                        "proofValue": "zTestValue"
                    }
                ]
            }
        ]
        """;

        var parsed = WitnessValidator.ParseWitnessFile(Encoding.UTF8.GetBytes(json), out var parseError);

        parsed.Should().BeNull("duplicate members in untrusted witness JSON must be rejected");
        parseError.Should().NotBeNullOrEmpty();
    }

    #endregion

    #region Signed data: witness proofs cover {"versionId": ...}

    [Fact]
    public async Task Issue135_WitnessProofOverVersionIdDocument_Verifies()
    {
        var signer = CreateSigner();
        var config = PolicyFor(signer, threshold: 1);
        var entry = CreateEntry(1, config);
        var proof = await SignVersionAsync(entry.VersionId, signer);
        var witnessFile = new WitnessFile
        {
            Entries = [new WitnessProofEntry { VersionId = entry.VersionId, Proofs = [proof] }]
        };

        (await new WitnessValidator().ValidateWitnessesAsync(witnessFile, entry, config))
            .Should().BeTrue("the spec's witness input document is {\"versionId\": ...}");
    }

    /// <summary>
    /// The pre-#135 model — signing the entry serialized without proof — must now fail: those
    /// proofs are not what did:webvh v1.0 witnesses produce, and accepting both models would
    /// let a non-conformant proof satisfy a threshold no conformant resolver would count.
    /// </summary>
    [Fact]
    public async Task Issue135_WitnessProofOverEntryWithoutProof_FailsVerification()
    {
        var signer = CreateSigner();
        var config = PolicyFor(signer, threshold: 1);
        var entry = CreateEntry(1, config);
        var legacyProof = await SignJsonAsync(
            LogEntrySerializer.SerializeWithoutProof(entry),
            signer,
            entry.VersionTime);
        var witnessFile = new WitnessFile
        {
            Entries = [new WitnessProofEntry { VersionId = entry.VersionId, Proofs = [legacyProof] }]
        };

        (await new WitnessValidator().ValidateWitnessesAsync(witnessFile, entry, config))
            .Should().BeFalse("a proof over the legacy entry-without-proof document is not a " +
                "conformant witness approval");
    }

    #endregion

    #region Adversarial round: split entries, proof profile, writer contract

    /// <summary>
    /// The ts reference implementation authors ONE array entry PER witness proof, so proofs for
    /// a single version legitimately arrive split across duplicate-versionId entries (the
    /// committed negative fixture carries exactly that shape). The spec's algorithm is
    /// proof-wise ("verify each proof for the relevant versionId"); consulting only the first
    /// matching entry falsely rejects validly witnessed threshold≥2 DIDs.
    /// </summary>
    [Fact]
    public async Task Issue135_SplitWitnessEntries_AggregateAcrossDuplicateVersionIds()
    {
        var signerA = CreateSigner();
        var signerB = CreateSigner();
        var config = new WitnessConfig
        {
            Threshold = 2,
            Witnesses =
            [
                new WitnessEntry { Id = $"did:key:{signerA.MultibasePublicKey}" },
                new WitnessEntry { Id = $"did:key:{signerB.MultibasePublicKey}" }
            ]
        };
        var entry = CreateEntry(1, config);
        var witnessFile = new WitnessFile
        {
            Entries =
            [
                new WitnessProofEntry
                {
                    VersionId = entry.VersionId,
                    Proofs = [await SignVersionAsync(entry.VersionId, signerA)]
                },
                new WitnessProofEntry
                {
                    VersionId = entry.VersionId,
                    Proofs = [await SignVersionAsync(entry.VersionId, signerB)]
                }
            ]
        };

        (await new WitnessValidator().ValidateWitnessesAsync(witnessFile, entry, config))
            .Should().BeTrue("proofs split across duplicate-versionId entries must aggregate");
    }

    /// <summary>
    /// End-to-end known answer for the split-entry shape using committed suite artifacts: the
    /// negative-threshold-not-met vector's GENESIS is fully approved 2-of-2 via two
    /// single-proof entries sharing its versionId (the vector is negative only because a later
    /// version is under-approved). A log truncated to that genesis must resolve.
    /// </summary>
    [Fact]
    public async Task Issue135_SuiteSplitEntryGenesisLog_Resolves()
    {
        var (_, log, witness) = SuiteFixture("issue135-negative-threshold-not-met-ts");
        var genesisLine = Encoding.UTF8.GetString(log)
            .Split('\n', StringSplitOptions.RemoveEmptyEntries)[0];
        using var doc = JsonDocument.Parse(genesisLine);
        var did = doc.RootElement.GetProperty("state").GetProperty("id").GetString()!;

        var http = new MockWebVhHttpClient();
        http.SetLogResponse(DidUrlMapper.MapToLogUrl(did), Encoding.UTF8.GetBytes(genesisLine));
        http.SetWitnessResponse(DidUrlMapper.MapToWitnessUrl(did), witness);
        var result = await new DidWebVhMethod(http).ResolveAsync(did);

        result.ResolutionMetadata.Error.Should().BeNull(
            "a 2-of-2 genesis whose approvals are split across two same-versionId entries " +
            "is validly witnessed");
        result.DidDocument.Should().NotBeNull();
    }

    [Fact]
    public async Task Issue135_MergeWitnessProofs_PreservesSplitEntries()
    {
        var signerA = CreateSigner();
        var signerB = CreateSigner();
        var existing = new WitnessFile
        {
            Entries =
            [
                new WitnessProofEntry
                {
                    VersionId = "1-QmSplit",
                    Proofs = [await SignVersionAsync("1-QmSplit", signerA)]
                },
                new WitnessProofEntry
                {
                    VersionId = "1-QmSplit",
                    Proofs = [await SignVersionAsync("1-QmSplit", signerB)]
                }
            ]
        };
        var newEntries = new List<WitnessProofEntry>
        {
            new()
            {
                VersionId = "2-QmNext",
                Proofs = [await SignVersionAsync("2-QmNext", signerA)]
            }
        };

        var merged = WitnessValidator.MergeWitnessProofs(existing, newEntries);

        merged.Entries.Where(e => e.VersionId == "1-QmSplit").SelectMany(e => e.Proofs)
            .Should().HaveCount(2, "merging must not drop proofs carried by duplicate-versionId entries");
        merged.Entries.Should().Contain(e => e.VersionId == "2-QmNext");
    }

    /// <summary>
    /// The spec says proof-less entries "SHOULD be removed" — they may legitimately appear as
    /// a transient state, so one must not reject the whole file (it simply contributes no
    /// approvals — fail-closed either way).
    /// </summary>
    [Fact]
    public void Issue135_WitnessEntryWithoutProofMember_IsInertNotFatal()
    {
        var json = """
        [
            { "versionId": "9-QmFutureStaged" },
            {
                "versionId": "1-QmTest",
                "proof": []
            }
        ]
        """;

        var parsed = WitnessValidator.ParseWitnessFile(Encoding.UTF8.GetBytes(json), out var parseError);

        parsed.Should().NotBeNull(parseError);
        parsed!.Entries.Should().HaveCount(2);
        parsed.Entries[0].Proofs.Should().BeEmpty();
    }

    /// <summary>
    /// `created` is optional in VC Data Integrity and absent from the spec's minimum witness
    /// proof properties; every reference implementation emits it today, but a proof signed
    /// without it must parse and verify.
    /// </summary>
    [Fact]
    public async Task Issue135_WitnessProofWithoutCreated_ParsesAndVerifies()
    {
        var signer = CreateSigner();
        var config = PolicyFor(signer, threshold: 1);
        var entry = CreateEntry(1, config);
        var proof = await SignVersionWithoutCreatedAsync(entry.VersionId, signer);

        var serialized = WitnessValidator.SerializeWitnessFile(new WitnessFile
        {
            Entries = [new WitnessProofEntry { VersionId = entry.VersionId, Proofs = [proof] }]
        });
        Encoding.UTF8.GetString(serialized).Should().NotContain("\"created\"",
            "a null Created must be omitted, not written as JSON null");

        var reparsed = WitnessValidator.ParseWitnessFile(serialized, out var parseError);
        reparsed.Should().NotBeNull(parseError);

        (await new WitnessValidator().ValidateWitnessesAsync(reparsed!, entry, config))
            .Should().BeTrue("a witness proof without created is conformant and must count");
    }

    /// <summary>
    /// The spec fixes witness proofPurpose to assertionMethod, and the reference resolvers
    /// reject other purposes. Counting them would make NetDid's threshold arithmetic diverge
    /// from conformant resolvers on the same file.
    /// </summary>
    [Fact]
    public async Task Issue135_WitnessProofWithWrongProofPurpose_DoesNotCount()
    {
        var signer = CreateSigner();
        var config = PolicyFor(signer, threshold: 1);
        var entry = CreateEntry(1, config);
        var proof = await SignJsonAsync(
            JsonSerializer.Serialize(new Dictionary<string, string> { ["versionId"] = entry.VersionId }),
            signer,
            new DateTimeOffset(2026, 8, 22, 12, 0, 0, TimeSpan.Zero),
            proofPurpose: "authentication");
        var witnessFile = new WitnessFile
        {
            Entries = [new WitnessProofEntry { VersionId = entry.VersionId, Proofs = [proof] }]
        };

        (await new WitnessValidator().ValidateWitnessesAsync(witnessFile, entry, config))
            .Should().BeFalse("a genuinely signed proof with a non-assertionMethod purpose is " +
                "rejected by conformant resolvers and must not count here either");
    }

    [Fact]
    public void Issue135_ParseWitnessFile_NonStringVersionId_IsRejected()
    {
        var parsed = WitnessValidator.ParseWitnessFile(
            Encoding.UTF8.GetBytes("""[{"versionId":null,"proof":[]}]"""), out var parseError);

        parsed.Should().BeNull(
            "a null versionId would crash the MergeWitnessProofs dictionary in public " +
            "Update/Deactivate");
        parseError.Should().NotBeNullOrEmpty();
    }

    /// <summary>
    /// The parse reason reaches caller logs; System.Text.Json echoes hostile member names
    /// (including U+2028/U+2029 line separators) into exception messages, so the reason must
    /// be bounded by construction: type name plus numeric position only.
    /// </summary>
    [Fact]
    public void Issue135_ParseError_DoesNotEchoHostileMemberNames()
    {
        var hostileName = "evil" + '\u2028' + "injected" + '\u2028' + "name";
        var json = $$"""[{"versionId":"1-QmTest","{{hostileName}}":1,"{{hostileName}}":2,"proof":[]}]""";

        var parsed = WitnessValidator.ParseWitnessFile(Encoding.UTF8.GetBytes(json), out var parseError);

        parsed.Should().BeNull("duplicate members are rejected");
        parseError.Should().NotBeNullOrEmpty();
        parseError.Should().NotContain("\u2028", "U+2028 line separators forge log lines in Unicode-aware viewers");
        parseError.Should().NotContain("evil", "attacker-controlled member names must not reach logs");
    }

    [Fact]
    public async Task Issue135_Update_UnparseableCurrentWitnessContent_Throws()
    {
        var method = new DidWebVhMethod(new MockWebVhHttpClient());
        var signer = CreateSigner();
        var createResult = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = signer
        });
        var logContent = (string)createResult.Artifacts![DidWebVhArtifacts.DidJsonl];
        var newProof = await SignVersionAsync("2-QmNew", signer);

        var act = () => method.UpdateAsync(createResult.Did.Value, new DidWebVhUpdateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(logContent),
            SigningKey = signer,
            CurrentWitnessContent = Encoding.UTF8.GetBytes(
                """[{"versionId":"1-QmLegacy","proofs":[]}]"""),
            WitnessProofs =
            [
                new WitnessProofEntry
                {
                    VersionId = "2-QmNew",
                    Proofs = [newProof]
                }
            ]
        });

        await act.Should().ThrowAsync<ArgumentException>(
            "silently publishing a witness artifact stripped of the caller's existing proofs " +
            "is a dishonest Success");
    }

    [Fact]
    public async Task Issue135_Deactivate_UnparseableCurrentWitnessContent_Throws()
    {
        var method = new DidWebVhMethod(new MockWebVhHttpClient());
        var signer = CreateSigner();
        var createResult = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = signer
        });
        var logContent = (string)createResult.Artifacts![DidWebVhArtifacts.DidJsonl];
        var newProof = await SignVersionAsync("2-QmNew", signer);

        var act = () => method.DeactivateAsync(createResult.Did.Value, new DidWebVhDeactivateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(logContent),
            SigningKey = signer,
            CurrentWitnessContent = Encoding.UTF8.GetBytes("not-a-witness-file"),
            WitnessProofs =
            [
                new WitnessProofEntry
                {
                    VersionId = "2-QmNew",
                    Proofs = [newProof]
                }
            ]
        });

        await act.Should().ThrowAsync<ArgumentException>();
    }

    #endregion

    #region Helpers

    private KeyPairSigner CreateSigner()
        => new(_keyGenerator.Generate(KeyType.Ed25519), _crypto);

    private static WitnessConfig PolicyFor(KeyPairSigner signer, int threshold)
        => new()
        {
            Threshold = threshold,
            Witnesses = [new WitnessEntry { Id = $"did:key:{signer.MultibasePublicKey}" }]
        };

    private static LogEntry CreateEntry(int version, WitnessConfig? witness)
        => new()
        {
            VersionId = $"{version}-QmIssue135Hash{version}",
            VersionTime = new DateTimeOffset(2026, 8, 22, 12, 0, 0, TimeSpan.Zero).AddMinutes(version - 1),
            Parameters = new LogEntryParameters { Witness = witness },
            State = new DidDocument { Id = new Did("did:example:issue135") }
        };

    /// <summary>Mints a conformant witness proof: eddsa-jcs-2022 over {"versionId": ...}.</summary>
    private Task<DataIntegrityProofValue> SignVersionAsync(string versionId, KeyPairSigner signer)
        => SignJsonAsync(
            JsonSerializer.Serialize(new Dictionary<string, string> { ["versionId"] = versionId }),
            signer,
            new DateTimeOffset(2026, 8, 22, 12, 0, 0, TimeSpan.Zero));

    private Task<DataIntegrityProofValue> SignVersionWithoutCreatedAsync(
        string versionId, KeyPairSigner signer)
        => SignJsonAsync(
            JsonSerializer.Serialize(new Dictionary<string, string> { ["versionId"] = versionId }),
            signer,
            created: null);

    private async Task<DataIntegrityProofValue> SignJsonAsync(
        string documentJson,
        KeyPairSigner signer,
        DateTimeOffset? created,
        string proofPurpose = "assertionMethod")
    {
        var proofOptions = new DataIntegrityProof
        {
            Cryptosuite = EddsaJcs2022Cryptosuite.CryptosuiteName,
            VerificationMethod =
                $"did:key:{signer.MultibasePublicKey}#{signer.MultibasePublicKey}",
            Created = created?.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"),
            ProofPurpose = proofPurpose
        };
        using var document = JsonDocument.Parse(documentJson);
        var proof = await _suite.CreateProofAsync(document.RootElement, proofOptions, signer);

        return new DataIntegrityProofValue
        {
            Type = proof.Type,
            Cryptosuite = proof.Cryptosuite!,
            VerificationMethod = proof.VerificationMethod!,
            Created = proof.Created,
            ProofPurpose = proof.ProofPurpose!,
            ProofValue = proof.ProofValue!
        };
    }

    #endregion
}
