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

        // Find the witness proof entry matching this log version
        var proofEntry = witnessFile.Entries.FirstOrDefault(e => e.VersionId == entry.VersionId);
        if (proofEntry is null)
            return false; // No witness proofs for this version

        // The data that witnesses signed is the log entry without proof
        var entryJsonWithoutProof = LogEntrySerializer.SerializeWithoutProof(entry);

        var totalWeight = 0;

        foreach (var witnessProof in proofEntry.Proofs)
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

    /// <summary>
    /// Parse a did-witness.json file.
    /// The spec defines this as a JSON array of witness proof entries.
    /// </summary>
    public static WitnessFile? ParseWitnessFile(byte[] content)
    {
        try
        {
            var json = Encoding.UTF8.GetString(content);
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            var entries = new List<WitnessProofEntry>();

            if (root.ValueKind == JsonValueKind.Array)
            {
                // Spec-compliant format: array of { versionId, proofs }
                foreach (var element in root.EnumerateArray())
                {
                    entries.Add(ParseProofEntry(element));
                }
            }
            else if (root.ValueKind == JsonValueKind.Object)
            {
                // Legacy single-object format for backwards compatibility
                entries.Add(ParseProofEntry(root));
            }
            else
            {
                return null;
            }

            return new WitnessFile { Entries = entries };
        }
        catch
        {
            return null;
        }
    }

    private static WitnessProofEntry ParseProofEntry(JsonElement element)
    {
        var versionId = element.GetProperty("versionId").GetString()!;
        var proofs = element.GetProperty("proofs").EnumerateArray().Select(e => new DataIntegrityProofValue
        {
            Type = e.GetProperty("type").GetString()!,
            Cryptosuite = e.GetProperty("cryptosuite").GetString()!,
            VerificationMethod = e.GetProperty("verificationMethod").GetString()!,
            Created = e.GetProperty("created").GetString()!,
            ProofPurpose = e.GetProperty("proofPurpose").GetString()!,
            ProofValue = e.GetProperty("proofValue").GetString()!
        }).ToList();

        return new WitnessProofEntry
        {
            VersionId = versionId,
            Proofs = proofs
        };
    }
}
