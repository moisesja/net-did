using System.Collections;
using System.Text.Json;
using DataProofsDotnet.DataIntegrity;
using FluentAssertions;
using NetCrypto;
using NetDid.Core.Model;
using NetDid.Method.WebVh.Model;
using Xunit;

namespace NetDid.Method.WebVh.Tests;

/// <summary>
/// Fail-first regressions for PR #143 review round 3. These tests measure collection work,
/// rather than elapsed time, so the complexity and cancellation contracts are deterministic.
/// </summary>
public sealed class Issue135ReviewRound3BudgetTests
{
    private static readonly DateTimeOffset BaseTime =
        new(2026, 8, 23, 12, 0, 0, TimeSpan.Zero);

    private readonly DefaultCryptoProvider _crypto = new();
    private readonly DefaultKeyGenerator _keyGenerator = new();
    private readonly EddsaJcs2022Cryptosuite _suite = new();

    [Fact]
    public async Task Issue135_R3_CumulativeCoverage_VisitsChainLinearly()
    {
        const int entryCount = 64;
        var signer = CreateSigner();
        var policy = PolicyFor(signer);
        var entries = Enumerable.Range(1, entryCount)
            .Select(version => CreateEntry(version, policy))
            .ToArray();
        var countedEntries = new CountingReadOnlyList<LogEntry>(entries);
        var parameters = Enumerable.Range(0, entryCount)
            .Select(_ => new LogEntryParameters { Witness = policy })
            .ToArray();
        var finalProof = await SignVersionAsync(entries[^1], signer);
        var witnessFile = WitnessFileFor(entries[^1].VersionId, [finalProof]);

        var valid = await new WitnessValidator(maxProofVerifications: 1)
            .ValidateAllWitnessesAsync(
                witnessFile, countedEntries, entryCount - 1, parameters);

        valid.Should().BeTrue();
        countedEntries.IndexerReads.Should().BeLessThanOrEqualTo(entryCount * 8,
            "one final-version proof cumulatively covers every earlier entry, so validation " +
            "must not rescan the same suffix for each governed entry");
    }

    [Fact]
    public async Task Issue135_R3_UnconfiguredProofs_DoConstantConfiguredWitnessMembershipWork()
    {
        const int unconfiguredProofCount = 64;
        var configuredSigner = CreateSigner();
        var stranger = CreateSigner();
        var configuredWitnesses = new CountingReadOnlyList<WitnessEntry>(
            [new WitnessEntry { Id = DidFor(configuredSigner) }]);
        var policy = new WitnessConfig
        {
            Threshold = 1,
            Witnesses = configuredWitnesses
        };
        var entry = CreateEntry(1, policy);
        var proofs = Enumerable.Range(0, unconfiguredProofCount)
            .Select(i => DeclaredProof(stranger, proofValue: $"zInvalid{i}"))
            .ToList();
        proofs.Add(await SignVersionAsync(entry, configuredSigner));

        var valid = await new WitnessValidator(maxProofVerifications: 1)
            .ValidateWitnessesAsync(
                WitnessFileFor(entry.VersionId, proofs), entry, policy);

        valid.Should().BeTrue();
        configuredWitnesses.EnumeratorCreations.Should().BeLessThanOrEqualTo(4,
            "configured witness membership should be indexed once and queried in O(1), " +
            "independent of the number of unconfigured proofs");
    }

    [Fact]
    public async Task Issue135_R3_InheritedPolicy_IsValidatedOncePerDistinctConfiguration()
    {
        const int entryCount = 80;
        const int witnessCount = 40;
        var witnesses = new CountingReadOnlyList<WitnessEntry>(
            Enumerable.Range(0, witnessCount)
                .Select(_ => new WitnessEntry { Id = DidFor(CreateSigner()) })
                .ToArray());
        var policy = new WitnessConfig { Threshold = witnessCount, Witnesses = witnesses };
        var entries = Enumerable.Range(1, entryCount)
            .Select(version => CreateEntry(version, policy))
            .ToArray();
        var parameters = Enumerable.Range(0, entryCount)
            .Select(_ => new LogEntryParameters { Witness = policy })
            .ToArray();

        var valid = await new WitnessValidator().ValidateAllWitnessesAsync(
            new WitnessFile { Entries = [] }, entries, entryCount - 1, parameters);

        valid.Should().BeFalse();
        witnesses.EnumeratorCreations.Should().BeLessThanOrEqualTo(8,
            "an inherited WitnessConfig reference must be validated and indexed once, not once " +
            "for every governed entry");
    }

    [Fact]
    public async Task Issue135_R3_StandaloneClosures_MaterializeOnlySelectedProofs()
    {
        const int proofCount = 64;
        var signer = CreateSigner();
        var policy = PolicyFor(signer);
        var entry = CreateEntry(1, policy);
        var proofs = Enumerable.Range(0, proofCount)
            .Select(i => DeclaredProof(signer, $"zInvalid{i}"))
            .ToArray();
        var validator = new WitnessValidator(maxProofVerifications: proofCount);
        var session = validator.CreateSession(WitnessFileFor(entry.VersionId, proofs));

        var valid = await validator.ValidateAllWitnessesAsync(
            session,
            [entry],
            upToIndex: 0,
            [new LogEntryParameters { Witness = policy }]);

        valid.Should().BeFalse();
        session.DependencyClosureMaterializationVisits.Should().BeLessThanOrEqualTo(proofCount,
            "each standalone candidate closure contains one proof; materialization must not " +
            "rescan the entire same-version bucket for every candidate");
    }

    [Fact]
    public async Task Issue135_R3_OneSession_SharesBudgetAcrossPrefixAndFullTail()
    {
        var signer = CreateSigner();
        var policy = PolicyFor(signer);
        var entries = new[]
        {
            CreateEntry(1, policy),
            CreateEntry(2, policy)
        };
        var parameters = new[]
        {
            new LogEntryParameters { Witness = policy },
            new LogEntryParameters { Witness = policy }
        };
        var proofV1 = await SignVersionAsync(entries[0], signer);
        var proofV2 = await SignVersionAsync(entries[1], signer);
        var witnessFile = new WitnessFile
        {
            Entries =
            [
                new WitnessProofEntry
                {
                    VersionId = entries[0].VersionId,
                    Proofs = [proofV1]
                },
                new WitnessProofEntry
                {
                    VersionId = entries[1].VersionId,
                    Proofs = [proofV2]
                }
            ]
        };
        var validator = new WitnessValidator(maxProofVerifications: 1);
        var session = validator.CreateSession(witnessFile);

        var prefixValid = await validator.ValidateAllWitnessesAsync(
            session, entries, upToIndex: 0, parameters);
        var fullTailValid = await validator.ValidateAllWitnessesAsync(
            session, entries, upToIndex: 1, parameters);

        prefixValid.Should().BeTrue("the genuine V1 proof consumes the one-attempt budget");
        fullTailValid.Should().BeFalse(
            "the same resolution session must not reset its crypto ledger before validating " +
            "a full tail that requires a distinct V2 proof");
    }

    [Fact]
    public async Task Issue135_R3_OneSession_RepeatingExactRangeUsesMemoWithoutSpendingAgain()
    {
        var signer = CreateSigner();
        var policy = PolicyFor(signer);
        var entry = CreateEntry(1, policy);
        var parameters = new[] { new LogEntryParameters { Witness = policy } };
        var proof = await SignVersionAsync(entry, signer);
        var validator = new WitnessValidator(maxProofVerifications: 1);
        var session = validator.CreateSession(
            WitnessFileFor(entry.VersionId, [proof]));

        var firstPass = await validator.ValidateAllWitnessesAsync(
            session, [entry], upToIndex: 0, parameters);
        var repeatedPass = await validator.ValidateAllWitnessesAsync(
            session, [entry], upToIndex: 0, parameters);

        firstPass.Should().BeTrue("the genuine proof consumes the one-attempt budget");
        repeatedPass.Should().BeTrue(
            "the exact version-bound proof verdict must come from the session memo after the " +
            "budget has been exhausted");
    }

    [Fact]
    public async Task Issue135_R3_CancellationDuringSessionIndexing_StopsIndexingPromptly()
    {
        const int witnessEntryCount = 512;
        using var cts = new CancellationTokenSource();
        var witnessEntries = new CancelingReadOnlyList<WitnessProofEntry>(
            Enumerable.Range(0, witnessEntryCount)
                .Select(i => new WitnessProofEntry
                {
                    VersionId = $"{i + 1}-zIrrelevant{i}",
                    Proofs = []
                })
                .ToArray(),
            cts,
            cancelAtRead: 8);
        var signer = CreateSigner();
        var policy = PolicyFor(signer);
        var entry = CreateEntry(1, policy);
        var validator = new WitnessValidator();

        var act = () => validator.ValidateAllWitnessesAsync(
            new WitnessFile { Entries = witnessEntries },
            [entry],
            upToIndex: 0,
            [new LogEntryParameters { Witness = policy }],
            cts.Token);

        await act.Should().ThrowAsync<OperationCanceledException>();
        witnessEntries.Reads.Should().BeLessThan(32,
            "a cancelled validation must not finish indexing the attacker-controlled witness file");
    }

    [Fact]
    public void Issue135_R3_WitnessParser_ObservesCancellationAtItsBoundary()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        var act = () => WitnessValidator.ParseWitnessFile(
            "[]"u8.ToArray(), out _, cts.Token);

        act.Should().Throw<OperationCanceledException>();
    }

    [Fact]
    public async Task Issue135_R3_CancellationDuringProofBucketTraversal_PropagatesImmediately()
    {
        const int wrongPurposeProofCount = 512;
        using var cts = new CancellationTokenSource();
        var signer = CreateSigner();
        var policy = PolicyFor(signer);
        var entry = CreateEntry(1, policy);
        var entries = new CancelOnFirstIndexerReadList<LogEntry>([entry], cts);
        var proofs = Enumerable.Range(0, wrongPurposeProofCount)
            .Select(i => DeclaredProof(
                signer,
                proofValue: $"zWrongPurpose{i}",
                proofPurpose: "authentication"))
            .ToArray();
        var validator = new WitnessValidator();

        var act = () => validator.ValidateAllWitnessesAsync(
            WitnessFileFor(entry.VersionId, proofs),
            entries,
            upToIndex: 0,
            [new LogEntryParameters { Witness = policy }],
            cts.Token);

        await act.Should().ThrowAsync<OperationCanceledException>(
            "the token is cancelled after the outer-loop check, so the proof bucket itself " +
            "must observe cancellation instead of traversing every cheap pre-filter");
    }

    private KeyPairSigner CreateSigner()
        => new(_keyGenerator.Generate(KeyType.Ed25519), _crypto);

    private static string DidFor(ISigner signer)
        => $"did:key:{signer.MultibasePublicKey}";

    private static WitnessConfig PolicyFor(ISigner signer)
        => new()
        {
            Threshold = 1,
            Witnesses = [new WitnessEntry { Id = DidFor(signer) }]
        };

    private static LogEntry CreateEntry(int version, WitnessConfig policy)
        => new()
        {
            VersionId = $"{version}-zIssue135R3Hash{version}",
            VersionTime = BaseTime.AddMinutes(version - 1),
            Parameters = new LogEntryParameters { Witness = policy },
            State = new DidDocument { Id = new Did("did:example:issue135-r3") }
        };

    private async Task<DataIntegrityProofValue> SignVersionAsync(
        LogEntry entry,
        KeyPairSigner signer)
    {
        var proofOptions = new DataIntegrityProof
        {
            Cryptosuite = EddsaJcs2022Cryptosuite.CryptosuiteName,
            VerificationMethod = $"{DidFor(signer)}#{signer.MultibasePublicKey}",
            Created = entry.VersionTime.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"),
            ProofPurpose = "assertionMethod"
        };
        var documentJson =
            $$"""{"versionId":{{JsonSerializer.Serialize(entry.VersionId)}}}""";
        using var document = JsonDocument.Parse(documentJson);
        var proof = await _suite.CreateProofAsync(
            document.RootElement, proofOptions, signer);

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

    private static DataIntegrityProofValue DeclaredProof(
        ISigner signer,
        string proofValue,
        string proofPurpose = "assertionMethod")
        => new()
        {
            Type = DataIntegrityProof.DataIntegrityProofType,
            Cryptosuite = EddsaJcs2022Cryptosuite.CryptosuiteName,
            VerificationMethod = $"{DidFor(signer)}#{signer.MultibasePublicKey}",
            Created = BaseTime.ToString("yyyy-MM-ddTHH:mm:ssZ"),
            ProofPurpose = proofPurpose,
            ProofValue = proofValue
        };

    private static WitnessFile WitnessFileFor(
        string versionId,
        IReadOnlyList<DataIntegrityProofValue> proofs)
        => new()
        {
            Entries = [new WitnessProofEntry { VersionId = versionId, Proofs = proofs }]
        };

    private sealed class CountingReadOnlyList<T>(IReadOnlyList<T> items) : IReadOnlyList<T>
    {
        public int IndexerReads { get; private set; }
        public int EnumeratorCreations { get; private set; }

        public T this[int index]
        {
            get
            {
                IndexerReads++;
                return items[index];
            }
        }

        public int Count => items.Count;

        public IEnumerator<T> GetEnumerator()
        {
            EnumeratorCreations++;
            return items.GetEnumerator();
        }

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }

    private sealed class CancelingReadOnlyList<T>(
        IReadOnlyList<T> items,
        CancellationTokenSource cancellation,
        int cancelAtRead) : IReadOnlyList<T>
    {
        public int Reads { get; private set; }

        public T this[int index]
        {
            get
            {
                ObserveRead();
                return items[index];
            }
        }

        public int Count => items.Count;

        public IEnumerator<T> GetEnumerator()
        {
            foreach (var item in items)
            {
                ObserveRead();
                yield return item;
            }
        }

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

        private void ObserveRead()
        {
            Reads++;
            if (Reads == cancelAtRead)
                cancellation.Cancel();
        }
    }

    private sealed class CancelOnFirstIndexerReadList<T>(
        IReadOnlyList<T> items,
        CancellationTokenSource cancellation) : IReadOnlyList<T>
    {
        private int _reads;

        public T this[int index]
        {
            get
            {
                if (Interlocked.Increment(ref _reads) == 1)
                    cancellation.Cancel();
                return items[index];
            }
        }

        public int Count => items.Count;
        public IEnumerator<T> GetEnumerator() => items.GetEnumerator();
        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }
}
