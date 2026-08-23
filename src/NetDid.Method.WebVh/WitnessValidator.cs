using System.Text;
using System.Text.Json;
using DataProofsDotnet.DataIntegrity;
using NetDid.Method.WebVh.Model;

namespace NetDid.Method.WebVh;

/// <summary>
/// Validates witness proofs against the configured witness threshold.
/// </summary>
/// <remarks>
/// Witness proofs are W3C Data Integrity proofs and are verified by DataProofsDotnet's
/// <see cref="DataIntegrityProofPipeline"/> with their <b>complete</b> proof configuration —
/// the wire JSON captured at parse time (<see cref="DataIntegrityProofValue.RawJson"/>) is the
/// verification input, so signature-bound members outside the modeled set (<c>id</c>,
/// <c>expires</c>, <c>nonce</c>, extensions) are neither dropped before verification nor lost
/// on republish, and an unsigned injected member fails verification instead of being silently
/// truncated away (issue #135 review round 2, finding 1).
/// </remarks>
internal sealed class WitnessValidator
{
    /// <summary>
    /// Default cap on Data Integrity verifications per validation run. This is a resolver
    /// resource policy, not a conformance limit: `created` is signer-chosen, so one witness key
    /// can mint unlimited distinct proofs, and a &lt;=1 MiB witness file can carry thousands —
    /// the byte cap alone is not a CPU cap (issue #135 review round 2, finding 5). Proofs are
    /// deduplicated, memoized, and pre-filtered by configured-signer membership before any
    /// cryptography, and per-entry scanning stops at the threshold, so honest files spend at
    /// most (governed entries × threshold) attempts; the budget bounds the dishonest remainder.
    /// </summary>
    public const int DefaultMaxProofVerifications = 1024;

    private readonly DataIntegrityProofPipeline _pipeline = new();
    private readonly int _maxProofVerifications;

    public WitnessValidator(int maxProofVerifications = DefaultMaxProofVerifications)
    {
        if (maxProofVerifications < 1)
            throw new ArgumentOutOfRangeException(nameof(maxProofVerifications),
                "At least one witness proof verification must be allowed.");
        _maxProofVerifications = maxProofVerifications;
    }

    /// <summary>
    /// Validate witness proofs for a log entry.
    /// Returns true if the count of distinct valid witness proofs meets the threshold.
    /// This entry-local helper is retained for direct validation and focused tests;
    /// production resolution uses <see cref="ValidateAllWitnessesAsync"/> so later proofs
    /// can provide cumulative coverage for earlier governed entries.
    /// </summary>
    public async Task<bool> ValidateWitnessesAsync(
        WitnessFile witnessFile,
        LogEntry entry,
        WitnessConfig witnessConfig,
        CancellationToken ct = default)
    {
        if (WitnessPolicyValidator.GetValidationError(witnessConfig) is not null)
            return false;
        if (witnessConfig.IsDisabled)
            return true;

        var session = new VerificationSession(witnessFile, _maxProofVerifications);
        return await ValidateEntryThresholdAsync(
            session, [entry], entryIndex: 0, upToIndex: 0, witnessConfig, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Validate witness proofs for all entries in the log chain up to the target index.
    /// Per spec, a valid witness proof at version j satisfies the witness requirement
    /// for all versions &lt;= j (cumulative coverage).
    /// </summary>
    public async Task<bool> ValidateAllWitnessesAsync(
        WitnessFile witnessFile,
        IReadOnlyList<LogEntry> entries,
        int upToIndex,
        IReadOnlyList<LogEntryParameters> perEntryParams,
        CancellationToken ct = default)
    {
        // One session per run: the proof index, the per-proof verification memo, and the
        // verification budget are shared across every governed entry, so cumulative coverage
        // re-USES a proof's verdict instead of re-verifying it per entry.
        var session = new VerificationSession(witnessFile, _maxProofVerifications);

        for (int i = 0; i <= upToIndex; i++)
        {
            ct.ThrowIfCancellationRequested();

            var witnessConfig = GetAuthorizingWitnessConfig(perEntryParams, i);
            if (witnessConfig is not { Threshold: > 0 })
                continue; // This entry does not require witnessing

            if (WitnessPolicyValidator.GetValidationError(witnessConfig) is not null)
                return false;
            if (witnessConfig.IsDisabled)
                continue;

            if (!await ValidateEntryThresholdAsync(
                    session, entries, i, upToIndex, witnessConfig, ct).ConfigureAwait(false))
            {
                return false;
            }
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
    /// prior entries. Each verified signer key is counted only once per entry, scanning
    /// stops as soon as the threshold is met, and every skip that needs no cryptography
    /// (unconfigured or already-counted declared signer, wrong declared purpose, memoized
    /// verdict) happens before the budgeted pipeline call.
    /// </summary>
    private async Task<bool> ValidateEntryThresholdAsync(
        VerificationSession session,
        IReadOnlyList<LogEntry> entries,
        int entryIndex,
        int upToIndex,
        WitnessConfig witnessConfig,
        CancellationToken ct)
    {
        var approvalCount = 0;
        var countedSignerKeys = new HashSet<string>(StringComparer.Ordinal);

        // Check proofs from this version through the latest validated version. The signed
        // document is built from the CHAIN-VALIDATED entry's versionId, never the witness
        // file's claimed key, so an approval only ever counts toward a version this log proves.
        for (int j = entryIndex; j <= upToIndex; j++)
        {
            ct.ThrowIfCancellationRequested();

            if (!session.ProofsByVersion.TryGetValue(entries[j].VersionId, out var proofs))
                continue;

            foreach (var witnessProof in proofs)
            {
                // Pre-filters, cheapest first — none of these consume the verification budget.
                // The declared verificationMethod and proofPurpose are part of the signed proof
                // configuration, so a proof can never verify under a different signer or
                // purpose than it declares; filtering on the declared values is sound.
                if (!string.Equals(witnessProof.ProofPurpose, "assertionMethod", StringComparison.Ordinal))
                    continue;

                var declaredSigner =
                    WebVhProofVerifier.ExtractWitnessDidKeyMultibase(witnessProof.VerificationMethod);
                if (declaredSigner is null
                    || countedSignerKeys.Contains(declaredSigner)
                    || FindWitnessForSigner(witnessConfig, declaredSigner) is null)
                {
                    continue;
                }

                if (!session.VerifiedByProof.TryGetValue(witnessProof, out var verified))
                {
                    if (session.RemainingVerifications <= 0)
                        return false; // Budget exhausted with the threshold unmet: fail closed.
                    session.RemainingVerifications--;

                    verified = await VerifyWitnessProofAsync(
                        entries[j].VersionId, entries[j].VersionTime, witnessProof, ct)
                        .ConfigureAwait(false);
                    session.VerifiedByProof[witnessProof] = verified;
                }

                if (!verified || !countedSignerKeys.Add(declaredSigner))
                    continue;

                approvalCount++;
                if (approvalCount >= witnessConfig.Threshold)
                    return true;
            }
        }

        return approvalCount >= witnessConfig.Threshold;
    }

    /// <summary>
    /// Verifies one witness proof — with its complete wire configuration — over the
    /// spec's signed document for the version it is filed under. Fail closed on anything
    /// unexpected; a verification path must never throw for hostile input.
    /// </summary>
    private async Task<bool> VerifyWitnessProofAsync(
        string versionId,
        DateTimeOffset versionTime,
        DataIntegrityProofValue witnessProof,
        CancellationToken ct)
    {
        var options = new ProofVerificationOptions
        {
            ExpectedProofPurpose = "assertionMethod",
            VerificationTime = versionTime
        };

        try
        {
            var securedDocumentJson = SerializeSecuredWitnessDocument(versionId, witnessProof);
            using var document = JsonDocument.Parse(securedDocumentJson);
            var result = await _pipeline.VerifyAsync(
                document.RootElement, WebVhWitnessKeyResolver.Instance, options, ct)
                .ConfigureAwait(false);
            return result.Verified;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return false;
        }
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
    /// Per-validation-run state: the witness file indexed by versionId with byte-identical
    /// duplicates removed, the per-proof verification memo (reference-keyed — the index holds
    /// the canonical instance of each distinct proof), and the remaining verification budget.
    /// A proof is only ever verified against the signed document of the version it is filed
    /// under, so one memoized verdict per proof instance is complete.
    /// </summary>
    private sealed class VerificationSession
    {
        public Dictionary<string, List<DataIntegrityProofValue>> ProofsByVersion { get; }
        public Dictionary<DataIntegrityProofValue, bool> VerifiedByProof { get; } =
            new(ReferenceEqualityComparer.Instance);
        public int RemainingVerifications;

        public VerificationSession(WitnessFile witnessFile, int maxProofVerifications)
        {
            RemainingVerifications = maxProofVerifications;
            ProofsByVersion = new Dictionary<string, List<DataIntegrityProofValue>>(StringComparer.Ordinal);

            // Duplicate-versionId entries aggregate: the spec's algorithm is proof-wise and the
            // ts reference implementation authors one array entry per proof. Byte-identical
            // duplicates within a version are dropped here so they can never consume budget —
            // a value tuple so nullable components compare independently (null != "").
            var seen = new HashSet<(string, string?, string, string, string, string?, string, string)>();
            foreach (var entry in witnessFile.Entries)
            {
                foreach (var proof in entry.Proofs)
                {
                    if (!seen.Add((entry.VersionId, proof.RawJson, proof.Type, proof.Cryptosuite,
                            proof.VerificationMethod, proof.Created, proof.ProofPurpose, proof.ProofValue)))
                    {
                        continue;
                    }

                    if (!ProofsByVersion.TryGetValue(entry.VersionId, out var proofs))
                    {
                        proofs = [];
                        ProofsByVersion[entry.VersionId] = proofs;
                    }

                    proofs.Add(proof);
                }
            }
        }
    }

    /// <summary>
    /// The secured document for one witness proof, per did:webvh v1.0 "DID Witnesses": a Data
    /// Integrity proof that "use[s] the versionId as input data" — the JCS document
    /// <c>{"versionId": "..."}</c> secured by the proof under test. The versionId embeds the
    /// entry hash that chain validation independently recomputes over the full entry content
    /// before witness validation runs, so a witness approval transitively binds the whole
    /// entry. The proof is emitted with full wire fidelity so its complete signed configuration
    /// reaches the pipeline. (Issue #135: verifying against the entry serialized without proof
    /// interoperated with no other implementation.)
    /// </summary>
    private static string SerializeSecuredWitnessDocument(
        string versionId, DataIntegrityProofValue proof)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            writer.WriteString("versionId", versionId);
            writer.WritePropertyName("proof");
            writer.WriteStartArray();
            WriteProofObject(writer, proof);
            writer.WriteEndArray();
            writer.WriteEndObject();
        }

        return Encoding.UTF8.GetString(stream.ToArray());
    }

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
                WriteProofObject(writer, proof);
            writer.WriteEndArray();
            writer.WriteEndObject();
        }
        writer.WriteEndArray();

        writer.Flush();
        return stream.ToArray();
    }

    /// <summary>
    /// A proof parsed from a witness file re-emits verbatim (byte-identical), preserving
    /// signature-bound members outside the modeled set (<c>id</c>, <c>expires</c>, extensions)
    /// so republishing during Update/Deactivate never corrupts another implementation's proof.
    /// A programmatically created proof has no RawJson and is written from the modeled members
    /// (the shape NetDid emits); a null <c>Created</c> is omitted, never written as JSON null.
    /// </summary>
    private static void WriteProofObject(Utf8JsonWriter writer, DataIntegrityProofValue proof)
    {
        if (proof.RawJson is not null)
        {
            writer.WriteRawValue(proof.RawJson);
            return;
        }

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

    /// <summary>
    /// Merge new witness proof entries with existing ones. Proofs APPEND: did:webvh witness
    /// collection is incremental (the file is republished as approvals arrive), so a new proof
    /// for a version must join the existing approvals for that version, never replace them —
    /// replacement could sink an already threshold-satisfying version below its threshold for
    /// every resolver (issue #135 review round 2, finding 4). Byte-identical proofs are
    /// deduplicated; duplicate-versionId entries on either side are aggregated (a ts-authored
    /// file carries one entry per proof).
    /// </summary>
    public static WitnessFile MergeWitnessProofs(
        WitnessFile? existing, IReadOnlyList<WitnessProofEntry> newEntries)
    {
        var proofsByVersion = new Dictionary<string, List<DataIntegrityProofValue>>(StringComparer.Ordinal);
        var versionOrder = new List<string>();
        var seen = new HashSet<(string, string?, string, string, string, string?, string, string)>();

        void Aggregate(WitnessProofEntry entry)
        {
            if (!proofsByVersion.TryGetValue(entry.VersionId, out var proofs))
            {
                proofs = [];
                proofsByVersion[entry.VersionId] = proofs;
                versionOrder.Add(entry.VersionId);
            }

            foreach (var proof in entry.Proofs)
            {
                if (seen.Add((entry.VersionId, proof.RawJson, proof.Type, proof.Cryptosuite,
                        proof.VerificationMethod, proof.Created, proof.ProofPurpose, proof.ProofValue)))
                {
                    proofs.Add(proof);
                }
            }
        }

        if (existing is not null)
        {
            foreach (var entry in existing.Entries)
                Aggregate(entry);
        }

        foreach (var entry in newEntries)
            Aggregate(entry);

        return new WitnessFile
        {
            Entries = versionOrder
                .Select(versionId => new WitnessProofEntry
                {
                    VersionId = versionId,
                    Proofs = proofsByVersion[versionId]
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
        // RawJson captures the complete wire proof (members beyond the modeled set included)
        // as the verification input and the republish source.
        var proofs = element.TryGetProperty("proof", out var proofElement)
            ? proofElement.EnumerateArray().Select(e => new DataIntegrityProofValue
            {
                Type = e.GetProperty("type").GetString()!,
                Cryptosuite = e.GetProperty("cryptosuite").GetString()!,
                VerificationMethod = e.GetProperty("verificationMethod").GetString()!,
                Created = e.TryGetProperty("created", out var created) ? created.GetString() : null,
                ProofPurpose = e.GetProperty("proofPurpose").GetString()!,
                ProofValue = e.GetProperty("proofValue").GetString()!,
                RawJson = e.GetRawText()
            }).ToList()
            : [];

        return new WitnessProofEntry
        {
            VersionId = versionId,
            Proofs = proofs
        };
    }
}
