using System.Text.Json;
using DataProofsDotnet.DataIntegrity;
using FluentAssertions;
using NetCrypto;
using NetDid.Core.Model;
using NetDid.Method.WebVh;
using NetDid.Method.WebVh.Model;

namespace NetDid.Method.WebVh.Tests;

public class WitnessValidatorSecurityTests
{
    private static readonly DateTimeOffset VersionTime =
        new(2026, 7, 10, 12, 0, 0, TimeSpan.Zero);

    private readonly DefaultCryptoProvider _crypto = new();
    private readonly DefaultKeyGenerator _keyGenerator = new();
    private readonly EddsaJcs2022Cryptosuite _suite = new();

    [Fact]
    public async Task ValidateAllWitnesses_PolicyDisablingEntry_UsesPriorEffectivePolicy()
    {
        var witnessSigner = CreateSigner();
        var requiredPolicy = PolicyFor(witnessSigner, threshold: 1);
        var disabledPolicy = new WitnessConfig();
        var entries = new[]
        {
            CreateEntry(1, requiredPolicy),
            CreateEntry(2, disabledPolicy)
        };
        var postMergeParameters = new[]
        {
            new LogEntryParameters { Witness = requiredPolicy },
            new LogEntryParameters { Witness = disabledPolicy }
        };
        var genesisProof = await SignEntryAsync(entries[0], witnessSigner);
        var genesisOnly = WitnessFileFor((entries[0], new[] { genesisProof }));
        var validator = new WitnessValidator(_suite);

        validator.ValidateAllWitnesses(genesisOnly, entries, 1, postMergeParameters)
            .Should().BeFalse("the disabling entry is governed by the preceding witness policy");

        var updateProof = await SignEntryAsync(entries[1], witnessSigner);
        var updateOnly = WitnessFileFor((entries[1], new[] { updateProof }));

        validator.ValidateAllWitnesses(updateOnly, entries, 1, postMergeParameters)
            .Should().BeTrue("a valid proof on the policy transition also covers genesis");
    }

    [Fact]
    public async Task ValidateAllWitnesses_FirstPolicyActivation_IsImmediatelyRequired()
    {
        var signer = CreateSigner();
        var requiredPolicy = PolicyFor(signer, threshold: 1);
        var entries = new[]
        {
            CreateEntry(1, witness: null),
            CreateEntry(2, requiredPolicy)
        };
        var postMergeParameters = new[]
        {
            new LogEntryParameters(),
            new LogEntryParameters { Witness = requiredPolicy }
        };
        var validator = new WitnessValidator(_suite);

        WitnessValidator.RequiresWitness(postMergeParameters, upToIndex: 1).Should().BeTrue(
            "the first positive witness policy is immediately active");
        validator.ValidateAllWitnesses(
                new WitnessFile { Entries = [] }, entries, 1, postMergeParameters)
            .Should().BeFalse("the enabling entry itself must be witnessed");

        var activationProof = await SignEntryAsync(entries[1], signer);
        validator.ValidateAllWitnesses(
                WitnessFileFor((entries[1], new[] { activationProof })),
                entries,
                1,
                postMergeParameters)
            .Should().BeTrue();
    }

    [Fact]
    public async Task ValidateAllWitnesses_LoweredPolicy_IsAuthorizedByOldThreshold()
    {
        var witnessOne = CreateSigner();
        var witnessTwo = CreateSigner();
        var oldPolicy = new WitnessConfig
        {
            Threshold = 2,
            Witnesses = [WitnessFor(witnessOne), WitnessFor(witnessTwo)]
        };
        var loweredPolicy = new WitnessConfig
        {
            Threshold = 1,
            Witnesses = [WitnessFor(witnessOne), WitnessFor(witnessTwo)]
        };
        var entries = new[] { CreateEntry(1, oldPolicy), CreateEntry(2, loweredPolicy) };
        var parameters = new[]
        {
            new LogEntryParameters { Witness = oldPolicy },
            new LogEntryParameters { Witness = loweredPolicy }
        };
        var proofOne = await SignEntryAsync(entries[1], witnessOne);
        var validator = new WitnessValidator(_suite);

        validator.ValidateAllWitnesses(
                WitnessFileFor((entries[1], new[] { proofOne })), entries, 1, parameters)
            .Should().BeFalse("the lowering entry must still meet the old threshold of two");

        var proofTwo = await SignEntryAsync(entries[1], witnessTwo);
        validator.ValidateAllWitnesses(
                WitnessFileFor((entries[1], new[] { proofOne, proofTwo })), entries, 1, parameters)
            .Should().BeTrue();
    }

    [Fact]
    public async Task ValidateAllWitnesses_ReplacementUsesOldPolicyThenNewPolicy()
    {
        var oldSigner = CreateSigner();
        var newSigner = CreateSigner();
        var oldPolicy = PolicyFor(oldSigner, threshold: 1);
        var newPolicy = PolicyFor(newSigner, threshold: 1);
        var entries = new[]
        {
            CreateEntry(1, oldPolicy),
            CreateEntry(2, newPolicy),
            CreateEntry(3, newPolicy)
        };
        var parameters = new[]
        {
            new LogEntryParameters { Witness = oldPolicy },
            new LogEntryParameters { Witness = newPolicy },
            new LogEntryParameters { Witness = newPolicy }
        };
        var oldProofOnReplacement = await SignEntryAsync(entries[1], oldSigner);
        var newProofOnReplacement = await SignEntryAsync(entries[1], newSigner);
        var newProofAfterReplacement = await SignEntryAsync(entries[2], newSigner);
        var validator = new WitnessValidator(_suite);

        validator.ValidateAllWitnesses(
                WitnessFileFor((entries[1], new[] { newProofOnReplacement })),
                entries,
                1,
                parameters)
            .Should().BeFalse("the replacement entry is still governed by the old witness");

        validator.ValidateAllWitnesses(
                WitnessFileFor(
                    (entries[1], new[] { oldProofOnReplacement }),
                    (entries[2], new[] { newProofAfterReplacement })),
                entries,
                2,
                parameters)
            .Should().BeTrue("the replacement governs the following entry");
    }

    [Fact]
    public async Task ValidateAllWitnesses_InvalidProofBeforeValidProof_DoesNotConsumeWitnessVote()
    {
        var witnessOne = CreateSigner();
        var witnessTwo = CreateSigner();
        var policy = new WitnessConfig
        {
            Threshold = 2,
            Witnesses =
            [
                WitnessFor(witnessOne),
                WitnessFor(witnessTwo)
            ]
        };
        var entry = CreateEntry(1, policy);
        var validOne = await SignEntryAsync(entry, witnessOne);
        var validTwo = await SignEntryAsync(entry, witnessTwo);
        var invalidOne = CopyWithProofValue(validOne, "z0");
        var witnessFile = WitnessFileFor((entry, new[] { invalidOne, validOne, validTwo }));
        var validator = new WitnessValidator(_suite);

        validator.ValidateAllWitnesses(
                witnessFile,
                new[] { entry },
                upToIndex: 0,
                new[] { new LogEntryParameters { Witness = policy } })
            .Should().BeTrue("only a successfully verified proof may consume a witness vote");
    }

    [Fact]
    public async Task ValidateAllWitnesses_ConfiguredIdPrefix_DoesNotAuthorizeVerifiedSigner()
    {
        var signer = CreateSigner();
        var signerDid = DidFor(signer);
        var policy = new WitnessConfig
        {
            Threshold = 1,
            Witnesses =
            [
                new WitnessEntry
                {
                    Id = signerDid[..^1],
                    Weight = 1
                }
            ]
        };
        var entry = CreateEntry(1, policy);
        var proof = await SignEntryAsync(entry, signer);
        var validator = new WitnessValidator(_suite);

        validator.ValidateAllWitnesses(
                WitnessFileFor((entry, new[] { proof })),
                new[] { entry },
                upToIndex: 0,
                new[] { new LogEntryParameters { Witness = policy } })
            .Should().BeFalse("configured witness identity must exactly match the verified signer key");
    }

    [Fact]
    public async Task ValidateWitnesses_DuplicateValidProof_CountsSignerOnce()
    {
        var signer = CreateSigner();
        var policy = PolicyFor(signer, threshold: 2);
        var entry = CreateEntry(1, policy);
        var proof = await SignEntryAsync(entry, signer);
        var validator = new WitnessValidator(_suite);

        validator.ValidateWitnesses(
                WitnessFileFor((entry, new[] { proof, proof })),
                entry,
                policy)
            .Should().BeFalse("repeating one valid proof cannot multiply that witness's weight");
    }

    [Fact]
    public async Task ValidateWitnesses_LegacyWeight_DoesNotReplaceDistinctSignerApproval()
    {
        var witnessOne = CreateSigner();
        var witnessTwo = CreateSigner();
        var policy = new WitnessConfig
        {
            Threshold = 2,
            Witnesses =
            [
                new WitnessEntry { Id = DidFor(witnessOne), Weight = 100 },
                WitnessFor(witnessTwo)
            ]
        };
        var entry = CreateEntry(1, policy);
        var proofOne = await SignEntryAsync(entry, witnessOne);
        var proofTwo = await SignEntryAsync(entry, witnessTwo);
        var validator = new WitnessValidator(_suite);

        validator.ValidateWitnesses(
                WitnessFileFor((entry, new[] { proofOne })), entry, policy)
            .Should().BeFalse("one verified witness is one approval regardless of legacy weight");
        validator.ValidateWitnesses(
                WitnessFileFor((entry, new[] { proofOne, proofTwo })), entry, policy)
            .Should().BeTrue("two distinct verified witnesses satisfy threshold two");
    }

    private ISigner CreateSigner()
        => new KeyPairSigner(_keyGenerator.Generate(KeyType.Ed25519), _crypto);

    private static string DidFor(ISigner signer)
        => $"did:key:{signer.MultibasePublicKey}";

    private static WitnessEntry WitnessFor(ISigner signer)
        => new() { Id = DidFor(signer), Weight = 1 };

    private static WitnessConfig PolicyFor(ISigner signer, int threshold)
        => new()
        {
            Threshold = threshold,
            Witnesses = [WitnessFor(signer)]
        };

    private static LogEntry CreateEntry(int version, WitnessConfig? witness)
        => new()
        {
            VersionId = $"{version}-zTestHash{version}",
            VersionTime = VersionTime.AddMinutes(version - 1),
            Parameters = new LogEntryParameters { Witness = witness },
            State = new DidDocument { Id = new Did("did:example:witness-security-test") }
        };

    private async Task<DataIntegrityProofValue> SignEntryAsync(LogEntry entry, ISigner signer)
    {
        var proofOptions = new DataIntegrityProof
        {
            Cryptosuite = EddsaJcs2022Cryptosuite.CryptosuiteName,
            VerificationMethod = $"{DidFor(signer)}#{signer.MultibasePublicKey}",
            Created = entry.VersionTime.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"),
            ProofPurpose = "assertionMethod"
        };
        using var document = JsonDocument.Parse(LogEntrySerializer.SerializeWithoutProof(entry));
        var proof = await _suite.CreateProofAsync(document.RootElement, proofOptions, signer);

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

    private static DataIntegrityProofValue CopyWithProofValue(
        DataIntegrityProofValue proof,
        string proofValue)
        => new()
        {
            Type = proof.Type,
            Cryptosuite = proof.Cryptosuite,
            VerificationMethod = proof.VerificationMethod,
            Created = proof.Created,
            ProofPurpose = proof.ProofPurpose,
            ProofValue = proofValue
        };

    private static WitnessFile WitnessFileFor(
        params (LogEntry Entry, IReadOnlyList<DataIntegrityProofValue> Proofs)[] entries)
        => new()
        {
            Entries = entries.Select(item => new WitnessProofEntry
            {
                VersionId = item.Entry.VersionId,
                Proofs = item.Proofs
            }).ToList()
        };
}
