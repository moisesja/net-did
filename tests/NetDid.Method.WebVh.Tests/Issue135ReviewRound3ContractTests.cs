using System.Text;
using FluentAssertions;
using NetDid.Method.WebVh.Model;

namespace NetDid.Method.WebVh.Tests;

/// <summary>
/// Fail-first contracts from the PR #143 round-three review. Proof identity is semantic over
/// the complete JSON proof object: parser-only wire provenance must not make an otherwise
/// identical caller proof distinct, while signature-bound extension members must.
/// </summary>
public class Issue135ReviewRound3ContractTests
{
    [Fact]
    public void Issue135_R3_Merge_ParsedExistingAndIdenticalProgrammaticProof_Dedupes()
    {
        var programmatic = BaselineProof();
        var existing = ParseWitnessFile(WitnessFileJson(StandardProofJson()));

        var merged = WitnessValidator.MergeWitnessProofs(existing,
        [
            new WitnessProofEntry
            {
                VersionId = VersionId,
                Proofs = [programmatic]
            }
        ]);

        merged.Entries.Should().ContainSingle();
        merged.Entries[0].Proofs.Should().ContainSingle(
            "RawJson is parser provenance, not part of the proof's semantic identity");
    }

    [Fact]
    public void Issue135_R3_Merge_FormattingAndPropertyOrderVariants_DedupeCanonically()
    {
        var existing = ParseWitnessFile(WitnessFileJson(StandardProofJson()));
        var reordered = ParseWitnessFile(WitnessFileJson(ReorderedProofJson()));

        var merged = WitnessValidator.MergeWitnessProofs(existing, reordered.Entries);

        merged.Entries.Should().ContainSingle();
        merged.Entries[0].Proofs.Should().ContainSingle(
            "JSON whitespace and object-member order do not change a Data Integrity proof");
    }

    [Fact]
    public void Issue135_R3_Merge_RawExtraMember_RemainsDistinctFromModeledProof()
    {
        var withSignedExtension = ParseWitnessFile(WitnessFileJson(
            StandardProofJson(extraMember: "\"nonce\":\"signature-bound\",")));

        var merged = WitnessValidator.MergeWitnessProofs(withSignedExtension,
        [
            new WitnessProofEntry
            {
                VersionId = VersionId,
                Proofs = [BaselineProof()]
            }
        ]);

        merged.Entries.Should().ContainSingle();
        merged.Entries[0].Proofs.Should().HaveCount(2,
            "complete proof configuration participates in identity; dropping an extension " +
            "would collapse two different signature inputs");
    }

    private const string VersionId = "1-QmRound3SemanticIdentity";

    private static DataIntegrityProofValue BaselineProof() => new()
    {
        Type = "DataIntegrityProof",
        Cryptosuite = "eddsa-jcs-2022",
        VerificationMethod = "did:key:z6MkRound3#z6MkRound3",
        Created = "2026-08-23T12:00:00Z",
        ProofPurpose = "assertionMethod",
        ProofValue = "zRound3ProofValue"
    };

    private static string StandardProofJson(string extraMember = "") =>
        "{" +
        "\"type\":\"DataIntegrityProof\"," +
        "\"cryptosuite\":\"eddsa-jcs-2022\"," +
        "\"verificationMethod\":\"did:key:z6MkRound3#z6MkRound3\"," +
        "\"created\":\"2026-08-23T12:00:00Z\"," +
        extraMember +
        "\"proofPurpose\":\"assertionMethod\"," +
        "\"proofValue\":\"zRound3ProofValue\"" +
        "}";

    private static string ReorderedProofJson() =>
        "{ \"proofValue\" : \"zRound3ProofValue\", " +
        "\"proofPurpose\" : \"assertionMethod\", " +
        "\"created\" : \"2026-08-23T12:00:00Z\", " +
        "\"verificationMethod\" : \"did:key:z6MkRound3#z6MkRound3\", " +
        "\"cryptosuite\" : \"eddsa-jcs-2022\", " +
        "\"type\" : \"DataIntegrityProof\" }";

    private static byte[] WitnessFileJson(string proofJson) =>
        Encoding.UTF8.GetBytes($"[{{\"versionId\":\"{VersionId}\",\"proof\":[{proofJson}]}}]");

    private static WitnessFile ParseWitnessFile(byte[] content)
    {
        var parsed = WitnessValidator.ParseWitnessFile(content, out var parseError);
        parsed.Should().NotBeNull(parseError);
        return parsed!;
    }
}
