using System.Text;
using System.Text.Json;
using NetDid.Core.Crypto.DataIntegrity;
using NetDid.Method.WebVh.Model;

namespace NetDid.Method.WebVh;

/// <summary>
/// Validates witness proofs against the configured witness threshold.
/// </summary>
internal sealed class WitnessValidator
{
    private readonly DataIntegrityProofEngine _proofEngine;

    public WitnessValidator(DataIntegrityProofEngine proofEngine)
    {
        _proofEngine = proofEngine;
    }

    /// <summary>
    /// Validate witness proofs for a log entry.
    /// Returns true if the total weight of valid witness proofs meets the threshold.
    /// </summary>
    public bool ValidateWitnesses(
        WitnessFile witnessFile,
        LogEntry entry,
        WitnessConfig witnessConfig)
    {
        if (witnessConfig.Threshold <= 0)
            return true; // No witness requirement

        if (witnessFile.VersionId != entry.VersionId)
            return false; // Witness file doesn't match this entry

        // The data that witnesses signed is the log entry without proof
        var entryJsonWithoutProof = LogEntrySerializer.SerializeWithoutProof(entry);

        var totalWeight = 0;

        foreach (var witnessProof in witnessFile.Proofs)
        {
            // Find this witness in the config
            var witness = witnessConfig.Witnesses?.FirstOrDefault(w =>
            {
                // The witness proof's verificationMethod should reference the witness's did:key
                return witnessProof.VerificationMethod.StartsWith(w.Id);
            });

            if (witness is null) continue;

            // Convert to Core proof type for verification
            var proof = new DataIntegrityProof
            {
                Cryptosuite = witnessProof.Cryptosuite,
                VerificationMethod = witnessProof.VerificationMethod,
                Created = DateTimeOffset.Parse(witnessProof.Created),
                ProofPurpose = witnessProof.ProofPurpose,
                ProofValue = witnessProof.ProofValue
            };

            if (_proofEngine.VerifyProof(entryJsonWithoutProof, proof))
            {
                totalWeight += witness.Weight;
            }
        }

        return totalWeight >= witnessConfig.Threshold;
    }

    /// <summary>Parse a did-witness.json file.</summary>
    public static WitnessFile? ParseWitnessFile(byte[] content)
    {
        try
        {
            var json = Encoding.UTF8.GetString(content);
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            var versionId = root.GetProperty("versionId").GetString()!;
            var proofs = root.GetProperty("proofs").EnumerateArray().Select(e => new DataIntegrityProofValue
            {
                Type = e.GetProperty("type").GetString()!,
                Cryptosuite = e.GetProperty("cryptosuite").GetString()!,
                VerificationMethod = e.GetProperty("verificationMethod").GetString()!,
                Created = e.GetProperty("created").GetString()!,
                ProofPurpose = e.GetProperty("proofPurpose").GetString()!,
                ProofValue = e.GetProperty("proofValue").GetString()!
            }).ToList();

            return new WitnessFile
            {
                VersionId = versionId,
                Proofs = proofs
            };
        }
        catch
        {
            return null;
        }
    }
}
