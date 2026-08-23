using System.Collections;
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
/// Regression tests for the PR #143 review-round-2 findings on the issue #135 witness
/// trust boundary:
///
///   F1 — witness proofs verify and republish with their COMPLETE proof configuration
///        (signature-bound members like <c>expires</c> are neither dropped before
///        verification nor lost on republish; an unsigned injected member fails);
///   F2 — supplied <c>CurrentWitnessContent</c> is consumed whether or not a new proof
///        batch accompanies it;
///   F3 — caller-supplied <c>WitnessProofs</c> collections are snapshotted exactly once
///        at the public operation boundary;
///   F4 — merging same-version proofs APPENDS (incremental collection), never replaces;
///   F5 — witness verification work is bounded: budgeted, memoized across governed
///        entries, threshold-early-exited, and cancellable;
///   F6 — a witness verificationMethod must use the spec's strict
///        <c>did:key:&lt;mb&gt;#&lt;mb&gt;</c> form; the bare-DID form is not counted.
/// </summary>
public class Issue135ReviewRound2Tests
{
    private static readonly DateTimeOffset SignTime =
        new(2026, 8, 23, 12, 0, 0, TimeSpan.Zero);

    private readonly DefaultCryptoProvider _crypto = new();
    private readonly DefaultKeyGenerator _keyGenerator = new();
    private readonly EddsaJcs2022Cryptosuite _suite = new();

    #region F1 — complete proof configuration

    [Fact]
    public async Task Issue135_R2_ProofWithSignedExpires_VerifiesAndCounts()
    {
        var signer = CreateSigner();
        var config = PolicyFor(signer, threshold: 1);
        var entry = CreateEntry(1, config);
        var proof = await SignVersionAsync(entry.VersionId, signer, expires: "2030-01-01T00:00:00Z");

        var file = ParseFile(WitnessFileJson(entry.VersionId, ProofJson(proof)));

        (await new WitnessValidator().ValidateWitnessesAsync(file, entry, config))
            .Should().BeTrue("expires is signature-bound proof configuration; dropping it " +
                "before verification rejects a conforming proof");
    }

    [Fact]
    public async Task Issue135_R2_UnsignedInjectedProofMember_FailsVerification()
    {
        var signer = CreateSigner();
        var config = PolicyFor(signer, threshold: 1);
        var entry = CreateEntry(1, config);
        var proof = await SignVersionAsync(entry.VersionId, signer);

        var file = ParseFile(WitnessFileJson(
            entry.VersionId, ProofJson(proof, extraMemberJson: "\"nonce\":\"injected\"")));

        (await new WitnessValidator().ValidateWitnessesAsync(file, entry, config))
            .Should().BeFalse("an unsigned member appended to the wire proof changes the " +
                "proof configuration and must fail verification, not be truncated away");
    }

    [Fact]
    public async Task Issue135_R2_Republish_PreservesSignedExtraMembers()
    {
        var signer = CreateSigner();
        var proof = await SignVersionAsync("1-QmR2", signer, expires: "2030-01-01T00:00:00Z");
        var file = ParseFile(WitnessFileJson("1-QmR2", ProofJson(proof)));

        var merged = WitnessValidator.MergeWitnessProofs(file, []);
        var republished = Encoding.UTF8.GetString(WitnessValidator.SerializeWitnessFile(merged));

        republished.Should().Contain("\"expires\":\"2030-01-01T00:00:00Z\"",
            "republishing a proof without a signature-bound member permanently corrupts it");
        republished.Should().Contain($"\"proofValue\":\"{proof.ProofValue}\"");
    }

    #endregion

    #region F2 — CurrentWitnessContent consumed whenever supplied

    [Fact]
    public async Task Issue135_R2_Update_GarbageWitnessContent_NoNewProofs_Throws()
    {
        var (method, did, logContent) = await CreateDidAsync();

        var act = () => method.UpdateAsync(did, new DidWebVhUpdateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(logContent),
            SigningKey = _lastSigner!,
            CurrentWitnessContent = "not-a-witness-file"u8.ToArray()
            // WitnessProofs deliberately absent
        });

        await act.Should().ThrowAsync<ArgumentException>(
            "supplied CurrentWitnessContent must be consumed and validated even when no new " +
            "proof batch accompanies it — silently ignoring supplied input is the same class " +
            "the fix claims to eliminate");
    }

    [Fact]
    public async Task Issue135_R2_Deactivate_GarbageWitnessContent_NoNewProofs_Throws()
    {
        var (method, did, logContent) = await CreateDidAsync();

        var act = () => method.DeactivateAsync(did, new DidWebVhDeactivateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(logContent),
            SigningKey = _lastSigner!,
            CurrentWitnessContent = Encoding.UTF8.GetBytes(
                """[{"versionId":"1-QmLegacy","proofs":[]}]""")
        });

        await act.Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public async Task Issue135_R2_Update_ValidWitnessContent_NoNewProofs_Republishes()
    {
        var (method, did, logContent) = await CreateDidAsync();
        var signer = CreateSigner();
        var proof = await SignVersionAsync("1-QmExisting", signer);
        var existing = WitnessFileJson("1-QmExisting", ProofJson(proof));

        var result = await method.UpdateAsync(did, new DidWebVhUpdateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(logContent),
            SigningKey = _lastSigner!,
            CurrentWitnessContent = existing
        });

        result.Artifacts.Should().ContainKey(DidWebVhArtifacts.DidWitnessJson,
            "supplied witness content round-trips through the operation");
        var republished = (string)result.Artifacts![DidWebVhArtifacts.DidWitnessJson];
        republished.Should().Contain(proof.ProofValue);
    }

    #endregion

    #region F3 — single-enumeration snapshot of caller collections

    [Fact]
    public async Task Issue135_R2_Create_SwitchingWitnessProofList_IsSnapshotOnce()
    {
        var signer = CreateSigner();
        var first = new WitnessProofEntry
        {
            VersionId = "1-QmFirstEnumeration",
            Proofs = [ToProofValue(await SignVersionAsync("1-QmFirstEnumeration", signer))]
        };
        var second = new WitnessProofEntry
        {
            VersionId = "1-QmSecondEnumeration",
            Proofs = [ToProofValue(await SignVersionAsync("1-QmSecondEnumeration", signer))]
        };
        var hostile = new SwitchingList([first], [second]);
        var method = new DidWebVhMethod(new MockWebVhHttpClient());

        var result = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = CreateSigner(),
            WitnessProofs = hostile
        });

        var artifact = (string)result.Artifacts![DidWebVhArtifacts.DidWitnessJson];
        artifact.Should().Contain("1-QmFirstEnumeration",
            "the published artifact must reflect the single snapshot taken at the boundary");
        artifact.Should().NotContain("1-QmSecondEnumeration",
            "a second enumeration observing different contents must never reach the artifact");
        hostile.Enumerations.Should().Be(1,
            "the caller collection is snapshotted exactly once at the trust boundary");
    }

    [Fact]
    public async Task Issue135_R2_Update_SwitchingWitnessProofList_IsSnapshotOnce()
    {
        var (method, did, logContent) = await CreateDidAsync();
        var signer = CreateSigner();
        var first = new WitnessProofEntry
        {
            VersionId = "2-QmFirstEnumeration",
            Proofs = [ToProofValue(await SignVersionAsync("2-QmFirstEnumeration", signer))]
        };
        var second = new WitnessProofEntry
        {
            VersionId = "2-QmSecondEnumeration",
            Proofs = [ToProofValue(await SignVersionAsync("2-QmSecondEnumeration", signer))]
        };
        var hostile = new SwitchingList([first], [second]);

        var result = await method.UpdateAsync(did, new DidWebVhUpdateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(logContent),
            SigningKey = _lastSigner!,
            WitnessProofs = hostile
        });

        var artifact = (string)result.Artifacts![DidWebVhArtifacts.DidWitnessJson];
        artifact.Should().Contain("2-QmFirstEnumeration");
        artifact.Should().NotContain("2-QmSecondEnumeration");
        hostile.Enumerations.Should().Be(1);
    }

    #endregion

    #region F4 — incremental same-version merge

    [Fact]
    public async Task Issue135_R2_Merge_SameVersionProof_AppendsToExisting()
    {
        var signerA = CreateSigner();
        var signerB = CreateSigner();
        var existingProof = await SignVersionAsync("2-QmSame", signerA);
        var newProof = await SignVersionAsync("2-QmSame", signerB);
        var existing = ParseFile(WitnessFileJson("2-QmSame", ProofJson(existingProof)));

        var merged = WitnessValidator.MergeWitnessProofs(existing,
            [new WitnessProofEntry { VersionId = "2-QmSame", Proofs = [ToProofValue(newProof)] }]);

        merged.Entries.Should().ContainSingle();
        merged.Entries[0].Proofs.Should().HaveCount(2,
            "witness collection is incremental — a newly received approval joins the " +
            "existing ones; replacement could sink a satisfied threshold");
    }

    [Fact]
    public async Task Issue135_R2_Merge_ByteIdenticalProof_DedupesAcrossSides()
    {
        var signer = CreateSigner();
        var proof = await SignVersionAsync("1-QmDup", signer);
        var wire = WitnessFileJson("1-QmDup", ProofJson(proof));
        var existing = ParseFile(wire);
        var again = ParseFile(wire);

        var merged = WitnessValidator.MergeWitnessProofs(existing, again.Entries.ToList());

        merged.Entries.Should().ContainSingle();
        merged.Entries[0].Proofs.Should().ContainSingle(
            "the same proof arriving on both sides of a merge is one approval, not two");
    }

    [Fact]
    public async Task Issue135_R2_Update_SameVersionProof_AppendsInArtifact()
    {
        var (method, did, logContent) = await CreateDidAsync();
        var signerA = CreateSigner();
        var signerB = CreateSigner();
        var existingProof = await SignVersionAsync("1-QmV1", signerA);
        var newProof = await SignVersionAsync("1-QmV1", signerB);

        var result = await method.UpdateAsync(did, new DidWebVhUpdateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(logContent),
            SigningKey = _lastSigner!,
            CurrentWitnessContent = WitnessFileJson("1-QmV1", ProofJson(existingProof)),
            WitnessProofs = [new WitnessProofEntry { VersionId = "1-QmV1", Proofs = [ToProofValue(newProof)] }]
        });

        var artifact = (string)result.Artifacts![DidWebVhArtifacts.DidWitnessJson];
        artifact.Should().Contain(existingProof.ProofValue, "prior approvals must survive");
        artifact.Should().Contain(newProof.ProofValue, "the new approval must be added");
    }

    #endregion

    #region F5 — bounded verification work

    [Fact]
    public async Task Issue135_R2_VerificationBudgetExhausted_FailsClosed()
    {
        var signer = CreateSigner();
        var config = PolicyFor(signer, threshold: 1);
        var entry = CreateEntry(1, config);

        // Five distinct structurally-valid proofs from the configured signer whose signatures
        // cannot verify (signed over a different versionId), then the genuine one. With a
        // budget of three, validation must stop and fail closed before reaching it.
        var proofJsons = new List<string>();
        for (var i = 0; i < 5; i++)
            proofJsons.Add(ProofJson(await SignVersionAsync($"9-QmOther{i}", signer)));
        proofJsons.Add(ProofJson(await SignVersionAsync(entry.VersionId, signer)));
        var file = ParseFile(WitnessFileJson(entry.VersionId, [.. proofJsons]));

        (await new WitnessValidator(maxProofVerifications: 3)
                .ValidateWitnessesAsync(file, entry, config))
            .Should().BeFalse("the verification-attempt budget is a hard bound and exhaustion " +
                "fails closed");
    }

    [Fact]
    public async Task Issue135_R2_ThresholdMet_StopsVerifying()
    {
        var signer = CreateSigner();
        var config = PolicyFor(signer, threshold: 1);
        var entry = CreateEntry(1, config);

        // The genuine proof first, then five unverifiable ones. A budget of exactly one
        // passes only if scanning stops the moment the threshold is met.
        var proofJsons = new List<string> { ProofJson(await SignVersionAsync(entry.VersionId, signer)) };
        for (var i = 0; i < 5; i++)
            proofJsons.Add(ProofJson(await SignVersionAsync($"9-QmOther{i}", signer)));
        var file = ParseFile(WitnessFileJson(entry.VersionId, [.. proofJsons]));

        (await new WitnessValidator(maxProofVerifications: 1)
                .ValidateWitnessesAsync(file, entry, config))
            .Should().BeTrue("per-entry scanning must stop once the threshold is met");
    }

    [Fact]
    public async Task Issue135_R2_CumulativeCoverage_MemoizesAcrossGovernedEntries()
    {
        var signer = CreateSigner();
        var config = PolicyFor(signer, threshold: 1);
        var entries = new[] { CreateEntry(1, config), CreateEntry(2, config), CreateEntry(3, config) };
        var perEntryParams = entries
            .Select(_ => new LogEntryParameters { Witness = config })
            .ToList();

        // One proof at version 3 covers all three governed entries. A budget of exactly one
        // passes only if the verdict is memoized instead of re-verified per entry.
        var file = ParseFile(WitnessFileJson(
            entries[2].VersionId, ProofJson(await SignVersionAsync(entries[2].VersionId, signer))));

        (await new WitnessValidator(maxProofVerifications: 1)
                .ValidateAllWitnessesAsync(file, entries, upToIndex: 2, perEntryParams))
            .Should().BeTrue("cumulative coverage must reuse a proof's verdict across entries, " +
                "not re-verify it O(entries × proofs) times");
    }

    [Fact]
    public async Task Issue135_R2_UnconfiguredSigners_ConsumeNoBudget()
    {
        var signer = CreateSigner();
        var stranger = CreateSigner();
        var config = PolicyFor(signer, threshold: 1);
        var entry = CreateEntry(1, config);

        // Five valid proofs from an UNCONFIGURED signer, then the genuine configured one. A
        // budget of one passes only if membership is checked before any cryptography.
        var proofJsons = new List<string>();
        for (var i = 0; i < 5; i++)
            proofJsons.Add(ProofJson(await SignVersionAsync(entry.VersionId, stranger, created: SignTime.AddMinutes(i))));
        proofJsons.Add(ProofJson(await SignVersionAsync(entry.VersionId, signer)));
        var file = ParseFile(WitnessFileJson(entry.VersionId, [.. proofJsons]));

        (await new WitnessValidator(maxProofVerifications: 1)
                .ValidateWitnessesAsync(file, entry, config))
            .Should().BeTrue("a proof whose declared signer is not a configured witness can " +
                "never count and must be skipped before signature verification");
    }

    [Fact]
    public async Task Issue135_R2_Validation_HonorsCancellation()
    {
        var signer = CreateSigner();
        var config = PolicyFor(signer, threshold: 1);
        var entry = CreateEntry(1, config);
        var file = ParseFile(WitnessFileJson(
            entry.VersionId, ProofJson(await SignVersionAsync(entry.VersionId, signer))));
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        var act = () => new WitnessValidator()
            .ValidateAllWitnessesAsync(file, [entry], 0,
                [new LogEntryParameters { Witness = config }], cts.Token);

        await act.Should().ThrowAsync<OperationCanceledException>();
    }

    #endregion

    #region F6 — strict witness verificationMethod form

    [Fact]
    public async Task Issue135_R2_BareDidKeyVerificationMethod_DoesNotCount()
    {
        var signer = CreateSigner();
        var config = PolicyFor(signer, threshold: 1);
        var entry = CreateEntry(1, config);

        // Genuinely signed by the configured witness, but with the bare-DID form the spec
        // does not permit for witness proofs. Conforming resolvers discard it; counting it
        // would diverge in threshold arithmetic on the same file.
        var bareVm = $"did:key:{signer.MultibasePublicKey}";
        var proof = await SignVersionAsync(entry.VersionId, signer, verificationMethod: bareVm);
        var file = ParseFile(WitnessFileJson(entry.VersionId, ProofJson(proof)));

        (await new WitnessValidator().ValidateWitnessesAsync(file, entry, config))
            .Should().BeFalse("did:webvh v1.0 requires the did:key:<mb>#<mb> form for witness " +
                "proof verification methods");
    }

    #endregion

    #region Helpers

    private KeyPairSigner? _lastSigner;

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
            VersionId = $"{version}-QmIssue135R2Hash{version}",
            VersionTime = SignTime.AddMinutes(version - 1),
            Parameters = new LogEntryParameters { Witness = witness },
            State = new DidDocument { Id = new Did("did:example:issue135-r2") }
        };

    private async Task<(DidWebVhMethod Method, string Did, string LogContent)> CreateDidAsync()
    {
        var method = new DidWebVhMethod(new MockWebVhHttpClient());
        _lastSigner = CreateSigner();
        var createResult = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = _lastSigner
        });
        return (method, createResult.Did.Value,
            (string)createResult.Artifacts![DidWebVhArtifacts.DidJsonl]);
    }

    /// <summary>Mints a witness proof over {"versionId": ...} with optional extra options.</summary>
    private async Task<DataIntegrityProof> SignVersionAsync(
        string versionId,
        KeyPairSigner signer,
        string? expires = null,
        string? verificationMethod = null,
        DateTimeOffset? created = null)
    {
        var proofOptions = new DataIntegrityProof
        {
            Cryptosuite = EddsaJcs2022Cryptosuite.CryptosuiteName,
            VerificationMethod = verificationMethod
                ?? $"did:key:{signer.MultibasePublicKey}#{signer.MultibasePublicKey}",
            Created = (created ?? SignTime).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"),
            Expires = expires,
            ProofPurpose = "assertionMethod"
        };
        var documentJson =
            $$"""{"versionId":{{JsonSerializer.Serialize(versionId)}}}""";
        using var document = JsonDocument.Parse(documentJson);
        return await _suite.CreateProofAsync(document.RootElement, proofOptions, signer);
    }

    /// <summary>Wire JSON for one signed proof, optionally with an UNSIGNED injected member.</summary>
    private static string ProofJson(DataIntegrityProof proof, string? extraMemberJson = null)
    {
        var sb = new StringBuilder("{");
        sb.Append($"\"type\":{JsonSerializer.Serialize(proof.Type)},");
        sb.Append($"\"cryptosuite\":{JsonSerializer.Serialize(proof.Cryptosuite)},");
        sb.Append($"\"verificationMethod\":{JsonSerializer.Serialize(proof.VerificationMethod)},");
        if (proof.Created is not null)
            sb.Append($"\"created\":{JsonSerializer.Serialize(proof.Created)},");
        if (proof.Expires is not null)
            sb.Append($"\"expires\":{JsonSerializer.Serialize(proof.Expires)},");
        if (extraMemberJson is not null)
            sb.Append(extraMemberJson).Append(',');
        sb.Append($"\"proofPurpose\":{JsonSerializer.Serialize(proof.ProofPurpose)},");
        sb.Append($"\"proofValue\":{JsonSerializer.Serialize(proof.ProofValue)}");
        sb.Append('}');
        return sb.ToString();
    }

    private static DataIntegrityProofValue ToProofValue(DataIntegrityProof proof) => new()
    {
        Type = proof.Type,
        Cryptosuite = proof.Cryptosuite!,
        VerificationMethod = proof.VerificationMethod!,
        Created = proof.Created,
        ProofPurpose = proof.ProofPurpose!,
        ProofValue = proof.ProofValue!
    };

    private static byte[] WitnessFileJson(string versionId, params string[] proofObjects)
        => Encoding.UTF8.GetBytes(
            $$"""[{"versionId":{{JsonSerializer.Serialize(versionId)}},"proof":[{{string.Join(",", proofObjects)}}]}]""");

    private static WitnessFile ParseFile(byte[] content)
    {
        var parsed = WitnessValidator.ParseWitnessFile(content, out var parseError);
        parsed.Should().NotBeNull(parseError);
        return parsed!;
    }

    /// <summary>
    /// A hostile <see cref="IReadOnlyList{T}"/> that presents different contents on the first
    /// and every subsequent enumeration, and counts enumerations. The increment happens in
    /// <see cref="GetEnumerator"/> itself (not lazily in an iterator) so the count is exact.
    /// </summary>
    private sealed class SwitchingList(
        IReadOnlyList<WitnessProofEntry> first,
        IReadOnlyList<WitnessProofEntry> subsequent) : IReadOnlyList<WitnessProofEntry>
    {
        private int _enumerations;

        public int Enumerations => _enumerations;

        private IReadOnlyList<WitnessProofEntry> Current
            => _enumerations <= 1 ? first : subsequent;

        public WitnessProofEntry this[int index] => Current[index];

        public int Count => Current.Count;

        public IEnumerator<WitnessProofEntry> GetEnumerator()
        {
            var pass = Interlocked.Increment(ref _enumerations);
            return (pass == 1 ? first : subsequent).GetEnumerator();
        }

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }

    #endregion
}
