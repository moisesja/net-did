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
    /// Validate witness proofs for all entries in the log chain up to the target index.
    /// Per spec, a valid witness proof at version j satisfies the witness requirement
    /// for all versions &lt;= j (cumulative coverage).
    /// </summary>
    public bool ValidateAllWitnesses(
        WitnessFile witnessFile,
        IReadOnlyList<LogEntry> entries,
        int upToIndex,
        IReadOnlyList<LogEntryParameters> perEntryParams)
    {
        for (int i = 0; i <= upToIndex; i++)
        {
            var entryParams = perEntryParams[i];
            if (entryParams.Witness is not { Threshold: > 0 })
                continue; // This entry does not require witnessing

            if (!ValidateWitnessesWithCoverage(witnessFile, entries, i, upToIndex, entryParams.Witness))
                return false;
        }

        return true;
    }

    /// <summary>
    /// Validate witness coverage for a specific entry by checking proofs at this version
    /// or any later version up to upToIndex. A later proof implies approval of all
    /// prior entries. Each witness is counted only once (deduplication by witness ID).
    /// </summary>
    private bool ValidateWitnessesWithCoverage(
        WitnessFile witnessFile,
        IReadOnlyList<LogEntry> entries,
        int entryIndex,
        int upToIndex,
        WitnessConfig witnessConfig)
    {
        if (witnessConfig.Threshold <= 0)
            return true;

        var totalWeight = 0;
        var countedWitnessIds = new HashSet<string>();

        // Check proofs from this version through the latest validated version
        for (int j = entryIndex; j <= upToIndex; j++)
        {
            var proofEntry = witnessFile.Entries.FirstOrDefault(e => e.VersionId == entries[j].VersionId);
            if (proofEntry is null)
                continue;

            // Verify proofs against the entry data they actually signed
            var entryJson = LogEntrySerializer.SerializeWithoutProof(entries[j]);

            foreach (var witnessProof in proofEntry.Proofs)
            {
                var witness = witnessConfig.Witnesses?.FirstOrDefault(w =>
                    witnessProof.VerificationMethod.StartsWith(w.Id));

                if (witness is null) continue;
                if (!countedWitnessIds.Add(witness.Id)) continue; // Already counted

                var proof = new DataIntegrityProof
                {
                    Cryptosuite = witnessProof.Cryptosuite,
                    VerificationMethod = witnessProof.VerificationMethod,
                    Created = DateTimeOffset.Parse(witnessProof.Created),
                    ProofPurpose = witnessProof.ProofPurpose,
                    ProofValue = witnessProof.ProofValue
                };

                if (_proofEngine.VerifyProof(entryJson, proof))
                {
                    totalWeight += witness.Weight;
                }
            }
        }

        return totalWeight >= witnessConfig.Threshold;
    }

    /// <summary>
    /// Serialize a WitnessFile to spec-compliant JSON array format.
    /// </summary>
    public static byte[] SerializeWitnessFile(WitnessFile witnessFile)
    {
        using var stream = new MemoryStream();
        using var writer = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = true });

        writer.WriteStartArray();
        foreach (var entry in witnessFile.Entries)
        {
            writer.WriteStartObject();
            writer.WriteString("versionId", entry.VersionId);
            writer.WritePropertyName("proofs");
            writer.WriteStartArray();
            foreach (var proof in entry.Proofs)
            {
                writer.WriteStartObject();
                writer.WriteString("type", proof.Type);
                writer.WriteString("cryptosuite", proof.Cryptosuite);
                writer.WriteString("verificationMethod", proof.VerificationMethod);
                writer.WriteString("created", proof.Created);
                writer.WriteString("proofPurpose", proof.ProofPurpose);
                writer.WriteString("proofValue", proof.ProofValue);
                writer.WriteEndObject();
            }
            writer.WriteEndArray();
            writer.WriteEndObject();
        }
        writer.WriteEndArray();

        writer.Flush();
        return stream.ToArray();
    }

    /// <summary>
    /// Merge new witness proof entries with existing ones.
    /// New entries replace existing ones with the same versionId.
    /// </summary>
    public static WitnessFile MergeWitnessProofs(
        WitnessFile? existing, IReadOnlyList<WitnessProofEntry> newEntries)
    {
        var entriesByVersion = new Dictionary<string, WitnessProofEntry>();

        if (existing is not null)
        {
            foreach (var entry in existing.Entries)
                entriesByVersion[entry.VersionId] = entry;
        }

        foreach (var entry in newEntries)
            entriesByVersion[entry.VersionId] = entry;

        return new WitnessFile { Entries = entriesByVersion.Values.ToList() };
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

            // Spec requires array format
            if (root.ValueKind != JsonValueKind.Array)
                return null;

            var entries = new List<WitnessProofEntry>();
            foreach (var element in root.EnumerateArray())
            {
                entries.Add(ParseProofEntry(element));
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
