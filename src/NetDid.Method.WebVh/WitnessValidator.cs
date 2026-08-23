using System.Text;
using System.Text.Json;
using DataProofsDotnet.DataIntegrity;
using NetDid.Method.WebVh.Model;

namespace NetDid.Method.WebVh;

/// <summary>
/// Validates witness proofs against the configured witness threshold.
/// </summary>
internal sealed class WitnessValidator
{
    private readonly EddsaJcs2022Cryptosuite _suite;

    public WitnessValidator(EddsaJcs2022Cryptosuite suite)
    {
        _suite = suite;
    }

    /// <summary>
    /// Validate witness proofs for a log entry.
    /// Returns true if the count of distinct valid witness proofs meets the threshold.
    /// This entry-local helper is retained for direct validation and focused tests;
    /// production resolution uses <see cref="ValidateAllWitnesses"/> so later proofs
    /// can provide cumulative coverage for earlier governed entries.
    /// </summary>
    public bool ValidateWitnesses(
        WitnessFile witnessFile,
        LogEntry entry,
        WitnessConfig witnessConfig)
    {
        if (WitnessPolicyValidator.GetValidationError(witnessConfig) is not null)
            return false;
        if (witnessConfig.IsDisabled)
            return true;

        // The data that witnesses signed is the {"versionId": ...} document (issue #135)
        var signedDocumentJson = SerializeWitnessSignedDocument(entry.VersionId);

        var approvalCount = 0;
        var countedSignerKeys = new HashSet<string>(StringComparer.Ordinal);

        // Aggregate across ALL entries carrying this versionId: the spec's algorithm is
        // proof-wise, and the ts reference implementation authors one array entry per proof,
        // so a version's approvals legitimately arrive split over duplicate-versionId entries.
        foreach (var witnessProof in ProofsForVersion(witnessFile, entry.VersionId))
        {
            var signerKey = WebVhProofVerifier.VerifyAndExtractSigner(
                _suite, signedDocumentJson, witnessProof);
            if (signerKey is null)
                continue;

            var witness = FindWitnessForSigner(witnessConfig, signerKey);
            if (witness is null || !countedSignerKeys.Add(signerKey))
                continue;

            approvalCount++;
        }

        return approvalCount >= witnessConfig.Threshold;
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
            var witnessConfig = GetAuthorizingWitnessConfig(perEntryParams, i);
            if (witnessConfig is not { Threshold: > 0 })
                continue; // This entry does not require witnessing

            if (!ValidateWitnessesWithCoverage(witnessFile, entries, i, upToIndex, witnessConfig))
                return false;
        }

        return true;
    }

    /// <summary>
    /// Returns whether any entry through <paramref name="upToIndex"/> is governed by a positive
    /// witness threshold. Genesis and the first activation are governed by their declared
    /// configuration; once active, the previous entry's effective configuration governs the
    /// transition that replaces or disables it.
    /// </summary>
    internal static bool RequiresWitness(
        IReadOnlyList<LogEntryParameters> perEntryParams,
        int upToIndex)
    {
        for (int i = 0; i <= upToIndex; i++)
        {
            if (GetAuthorizingWitnessConfig(perEntryParams, i) is { Threshold: > 0 })
                return true;
        }

        return false;
    }

    /// <summary>
    /// Validate witness coverage for a specific entry by checking proofs at this version
    /// or any later version up to upToIndex. A later proof implies approval of all
    /// prior entries. Each verified signer key is counted only once.
    /// </summary>
    private bool ValidateWitnessesWithCoverage(
        WitnessFile witnessFile,
        IReadOnlyList<LogEntry> entries,
        int entryIndex,
        int upToIndex,
        WitnessConfig witnessConfig)
    {
        if (WitnessPolicyValidator.GetValidationError(witnessConfig) is not null)
            return false;
        if (witnessConfig.IsDisabled)
            return true;

        var approvalCount = 0;
        var countedSignerKeys = new HashSet<string>(StringComparer.Ordinal);

        // Check proofs from this version through the latest validated version
        for (int j = entryIndex; j <= upToIndex; j++)
        {
            // Verify proofs against the {"versionId": ...} document witnesses actually sign.
            // The versionId is taken from the chain-validated entry, not the witness file's
            // claimed key, so an approval only ever counts toward a version this log proves.
            // Duplicate-versionId entries aggregate (one-entry-per-proof authoring is valid).
            var signedDocumentJson = SerializeWitnessSignedDocument(entries[j].VersionId);

            foreach (var witnessProof in ProofsForVersion(witnessFile, entries[j].VersionId))
            {
                // A malformed proof must not consume the witness's one counted vote. Derive the
                // signer only from a successfully verified proof, then bind one approval to that
                // exact configured did:key rather than to a verificationMethod string prefix.
                var signerKey = WebVhProofVerifier.VerifyAndExtractSigner(_suite, signedDocumentJson, witnessProof);
                if (signerKey is null)
                    continue;

                var witness = FindWitnessForSigner(witnessConfig, signerKey);
                if (witness is null || !countedSignerKeys.Add(signerKey))
                    continue;

                approvalCount++;
            }
        }

        return approvalCount >= witnessConfig.Threshold;
    }

    private static WitnessConfig? GetAuthorizingWitnessConfig(
        IReadOnlyList<LogEntryParameters> perEntryParams,
        int entryIndex)
    {
        // Genesis declares its own policy. The first transition from no active witnesses to a
        // positive policy is also immediately governed by the newly declared policy. Once a
        // positive policy is active, however, it governs the entry that replaces or disables it;
        // the new policy takes effect only after that entry is published.
        if (entryIndex == 0)
            return perEntryParams[0].Witness;

        var previous = perEntryParams[entryIndex - 1].Witness;
        return previous is { Threshold: > 0 }
            ? previous
            : perEntryParams[entryIndex].Witness;
    }

    /// <summary>
    /// A witness-file structural rule enforced by this parser. Distinct from raw
    /// <see cref="JsonException"/> so the catch above can surface its message verbatim: it is
    /// only ever thrown with fixed library-owned text, never content from the parsed file.
    /// </summary>
    private sealed class WitnessFileFormatException(string message) : JsonException(message);

    /// <summary>
    /// The document a witness signs, per did:webvh v1.0 "DID Witnesses": a Data Integrity proof
    /// that "use[s] the versionId as input data" — the JCS document <c>{"versionId": "..."}</c>.
    /// The versionId embeds the entry hash that chain validation independently recomputes over
    /// the full entry content before witness validation runs, so a witness approval transitively
    /// binds the whole entry. (Issue #135: verifying against the entry serialized without proof
    /// interoperated with no other implementation.)
    /// </summary>
    private static string SerializeWitnessSignedDocument(string versionId)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            writer.WriteString("versionId", versionId);
            writer.WriteEndObject();
        }

        return Encoding.UTF8.GetString(stream.ToArray());
    }

    /// <summary>
    /// All proofs the witness file carries for one chain-validated versionId, across every
    /// array entry that names it. The spec's verification algorithm is per-proof ("verify each
    /// Data Integrity proof for the relevant versionId"), and nothing forbids splitting a
    /// version's proofs over multiple entries — the ts reference implementation writes one
    /// entry per proof.
    /// </summary>
    private static IEnumerable<DataIntegrityProofValue> ProofsForVersion(
        WitnessFile witnessFile, string versionId)
        => witnessFile.Entries
            .Where(e => string.Equals(e.VersionId, versionId, StringComparison.Ordinal))
            .SelectMany(e => e.Proofs);

    private static WitnessEntry? FindWitnessForSigner(WitnessConfig witnessConfig, string signerKey)
    {
        return witnessConfig.Witnesses?.FirstOrDefault(witness =>
            string.Equals(
                WebVhProofVerifier.ExtractDidKeyMultibase(witness.Id),
                signerKey,
                StringComparison.Ordinal));
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
            writer.WritePropertyName("proof");
            writer.WriteStartArray();
            foreach (var proof in entry.Proofs)
            {
                writer.WriteStartObject();
                writer.WriteString("type", proof.Type);
                writer.WriteString("cryptosuite", proof.Cryptosuite);
                writer.WriteString("verificationMethod", proof.VerificationMethod);
                if (proof.Created is not null)
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
    /// Merge new witness proof entries with existing ones. New entries replace existing ones
    /// with the same versionId. Duplicate-versionId entries on either side are aggregated
    /// rather than last-one-wins — a ts-authored file carries one entry per proof, and
    /// dropping its siblings on a republish could sink a version below threshold for every
    /// resolver (issue #135 adversarial round).
    /// </summary>
    public static WitnessFile MergeWitnessProofs(
        WitnessFile? existing, IReadOnlyList<WitnessProofEntry> newEntries)
    {
        var entriesByVersion = new Dictionary<string, List<DataIntegrityProofValue>>();
        var versionOrder = new List<string>();

        void Aggregate(WitnessProofEntry entry)
        {
            if (entriesByVersion.TryGetValue(entry.VersionId, out var proofs))
            {
                proofs.AddRange(entry.Proofs);
            }
            else
            {
                entriesByVersion[entry.VersionId] = [.. entry.Proofs];
                versionOrder.Add(entry.VersionId);
            }
        }

        if (existing is not null)
        {
            foreach (var entry in existing.Entries)
                Aggregate(entry);
        }

        // A new entry replaces the whole aggregated set for its versionId.
        foreach (var versionId in newEntries.Select(e => e.VersionId).Distinct())
        {
            if (entriesByVersion.Remove(versionId))
                versionOrder.Remove(versionId);
        }

        foreach (var entry in newEntries)
            Aggregate(entry);

        return new WitnessFile
        {
            Entries = versionOrder
                .Select(versionId => new WitnessProofEntry
                {
                    VersionId = versionId,
                    Proofs = entriesByVersion[versionId]
                })
                .ToList()
        };
    }

    /// <summary>
    /// Parse a did-witness.json file.
    /// The spec defines this as a JSON array of witness proof entries.
    /// </summary>
    public static WitnessFile? ParseWitnessFile(byte[] content)
        => ParseWitnessFile(content, out _);

    /// <summary>
    /// Parse a did-witness.json file, reporting why parsing failed. A swallowed parse failure
    /// surfaces to callers as a bare <c>witnessValidationFailed</c> with no diagnostic at all —
    /// exactly how the #135 wire-format divergence went unnoticed — so the failure reason must
    /// reach a log. <paramref name="parseError"/> carries only exception-type and library-owned
    /// message text, never raw witness-file content.
    /// </summary>
    public static WitnessFile? ParseWitnessFile(byte[] content, out string? parseError)
    {
        try
        {
            var json = LogEntrySerializer.DecodeUtf8(content);

            // Untrusted remote JSON: reject duplicate members outright (recursive) — with
            // last-one-wins parsing a decoy duplicate could smuggle an unvalidated member
            // past validation (same trust-boundary rule as the log-entry parser, issue #101).
            using var doc = JsonDocument.Parse(
                json, new JsonDocumentOptions { AllowDuplicateProperties = false });
            var root = doc.RootElement;

            // Spec requires array format
            if (root.ValueKind != JsonValueKind.Array)
            {
                parseError = "did-witness.json root must be a JSON array.";
                return null;
            }

            var entries = new List<WitnessProofEntry>();
            foreach (var element in root.EnumerateArray())
            {
                entries.Add(ParseProofEntry(element));
            }

            parseError = null;
            return new WitnessFile { Entries = entries };
        }
        catch (Exception ex) when (ex is JsonException
            or FormatException
            or InvalidOperationException
            or KeyNotFoundException
            or ArgumentException
            or OverflowException)
        {
            // The JSON-access set: Parse raises JsonException, DecodeUtf8 wraps invalid UTF-8
            // in FormatException, and element accessors raise the remainder (e.g. GetString on
            // a non-string, GetProperty on a missing member, unpaired-surrogate decode).
            //
            // The reason is bounded by construction: a BCL type name plus numeric positions.
            // Exception messages are excluded — System.Text.Json echoes hostile member names
            // (including U+2028/U+2029 line separators) into JsonException.Message, and this
            // string reaches caller logs. The one exception is the internal marker type below,
            // whose messages are fixed library-owned text.
            parseError = ex switch
            {
                WitnessFileFormatException => ex.Message,
                JsonException { LineNumber: not null } jsonEx =>
                    $"{ex.GetType().Name} at line {jsonEx.LineNumber}, byte {jsonEx.BytePositionInLine}",
                _ => ex.GetType().Name,
            };
            return null;
        }
    }

    private static WitnessProofEntry ParseProofEntry(JsonElement element)
    {
        // A non-string versionId must fail the parse, not flow onward: a null key crashes
        // the MergeWitnessProofs dictionary inside public Update/Deactivate.
        var versionIdElement = element.GetProperty("versionId");
        if (versionIdElement.ValueKind != JsonValueKind.String)
            throw new WitnessFileFormatException("did-witness.json entry versionId must be a string.");

        var versionId = versionIdElement.GetString()!;

        // Migration tripwire: `proofs` is the pre-#135 NetDid wire format, and with proof-less
        // entries tolerated below it would otherwise parse as an inert empty entry — silently
        // shedding every legacy proof on a republish instead of failing loudly.
        if (element.TryGetProperty("proofs", out _))
            throw new WitnessFileFormatException(
                "did-witness.json entry carries the legacy 'proofs' member (pre-#135 NetDid " +
                "wire format); the did:webvh v1.0 member is 'proof'.");

        // The spec says proof-less entries "SHOULD be removed", so they may legitimately
        // appear as a transient state; an entry without proofs contributes no approvals
        // (fail-closed) rather than invalidating the whole file. `created` is optional in
        // VC Data Integrity and absent from the spec's minimum witness proof properties.
        var proofs = element.TryGetProperty("proof", out var proofElement)
            ? proofElement.EnumerateArray().Select(e => new DataIntegrityProofValue
            {
                Type = e.GetProperty("type").GetString()!,
                Cryptosuite = e.GetProperty("cryptosuite").GetString()!,
                VerificationMethod = e.GetProperty("verificationMethod").GetString()!,
                Created = e.TryGetProperty("created", out var created) ? created.GetString() : null,
                ProofPurpose = e.GetProperty("proofPurpose").GetString()!,
                ProofValue = e.GetProperty("proofValue").GetString()!
            }).ToList()
            : [];

        return new WitnessProofEntry
        {
            VersionId = versionId,
            Proofs = proofs
        };
    }
}
