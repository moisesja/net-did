using System.Text;
using System.Text.Json;
using DataProofsDotnet.DataIntegrity;
using NetCid;
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
    /// Default cap on Data Integrity verifications per resolution. This is a resolver
    /// resource policy, not a conformance limit: `created` is signer-chosen, so one witness key
    /// can mint unlimited distinct proofs, and a &lt;=1 MiB witness file can carry thousands —
    /// the byte cap alone is not a CPU cap (issue #135 review round 2, finding 5). Proofs are
    /// semantically deduplicated, indexed, memoized, and pre-filtered by O(1)
    /// configured-signer membership before any cryptography. Candidate scanning stops as soon as
    /// each policy threshold is met; the shared resolution ledger bounds the dishonest remainder.
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
    /// production resolution uses the all-entry validation overload so later proofs
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

        var session = CreateSession(witnessFile, ct);
        return await ValidateAllWitnessesAsync(
            session,
            [entry],
            upToIndex: 0,
            [new LogEntryParameters { Witness = witnessConfig }],
            ct).ConfigureAwait(false);
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
        var session = CreateSession(witnessFile, ct);
        return await ValidateAllWitnessesAsync(
            session, entries, upToIndex, perEntryParams, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Creates the proof index and crypto ledger for one resolution. The caller keeps this
    /// session across every validation pass performed by that resolution (historical prefix and
    /// deactivation tail), so the advertised budget cannot silently reset between passes.
    /// </summary>
    internal VerificationSession CreateSession(
        WitnessFile witnessFile,
        CancellationToken ct = default)
        => new(witnessFile, _maxProofVerifications, ct);

    /// <summary>
    /// Validates one chain range using a caller-owned resolution session. Coverage state is local
    /// to this range, while proof verdicts and the remaining cryptographic budget are shared.
    /// </summary>
    internal async Task<bool> ValidateAllWitnessesAsync(
        VerificationSession session,
        IReadOnlyList<LogEntry> entries,
        int upToIndex,
        IReadOnlyList<LogEntryParameters> perEntryParams,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(session);

        // Effective parameter merging reuses the same WitnessConfig reference while a policy is
        // inherited. For one policy, its latest governed entry is the hardest requirement: a
        // proof at or after that entry also covers every earlier entry governed by the same
        // object. Grouping those occurrences removes the old entry x suffix rescan.
        var policiesByConfig =
            new Dictionary<WitnessConfig, PolicyRequirement>(ReferenceEqualityComparer.Instance);

        for (int i = 0; i <= upToIndex; i++)
        {
            ct.ThrowIfCancellationRequested();
            var witnessConfig = GetAuthorizingWitnessConfig(perEntryParams, i);
            if (witnessConfig is not { Threshold: > 0 })
                continue;

            if (policiesByConfig.TryGetValue(witnessConfig, out var existing))
            {
                existing.RequiredFromIndex = i;
                continue;
            }

            if (WitnessPolicyValidator.GetValidationError(witnessConfig) is not null)
                return false;
            if (witnessConfig.IsDisabled)
                continue;

            var signerKeys = new List<string>();
            foreach (var witness in witnessConfig.Witnesses!)
            {
                ct.ThrowIfCancellationRequested();
                var signerKey = WebVhProofVerifier.ExtractDidKeyMultibase(witness.Id);
                if (signerKey is null)
                    return false; // Policy validation should already have rejected this.
                signerKeys.Add(signerKey);
            }

            ct.ThrowIfCancellationRequested();
            policiesByConfig[witnessConfig] = new PolicyRequirement(
                i, witnessConfig.Threshold, signerKeys);
        }

        if (policiesByConfig.Count == 0)
            return true;

        var policies = policiesByConfig.Values
            .OrderByDescending(policy => policy.RequiredFromIndex)
            .ToArray();
        var signerStates = policies
            .SelectMany(policy => policy.SignerKeys)
            .Distinct(StringComparer.Ordinal)
            .ToDictionary(key => key, _ => new SignerCoverageState(), StringComparer.Ordinal);

        // Index relevant candidates once in descending version order. A signer's cursor only
        // advances, so every proof is inspected at most once regardless of entry count. The O(1)
        // signerStates lookup replaces the old proof x configured-witness FirstOrDefault scan.
        for (int j = upToIndex; j >= 0; j--)
        {
            ct.ThrowIfCancellationRequested();
            var entry = entries[j];
            ct.ThrowIfCancellationRequested();

            if (!session.TryGetProofs(entry.VersionId, out var proofs))
                continue;

            foreach (var proof in proofs)
            {
                ct.ThrowIfCancellationRequested();
                if (!string.Equals(
                        proof.Value.ProofPurpose, "assertionMethod", StringComparison.Ordinal))
                {
                    continue;
                }

                var declaredSigner = WebVhProofVerifier.ExtractWitnessDidKeyMultibase(
                    proof.Value.VerificationMethod);
                if (declaredSigner is null
                    || !signerStates.TryGetValue(declaredSigner, out var signerState))
                {
                    continue;
                }

                signerState.Candidates.Add(new BoundProof(j, entry.VersionTime, proof));
            }
        }

        foreach (var policy in policies)
        {
            ct.ThrowIfCancellationRequested();
            var approvals = 0;

            foreach (var signerKey in policy.SignerKeys)
            {
                ct.ThrowIfCancellationRequested();
                if (await HasApprovalAtOrAfterAsync(
                        session,
                        signerStates[signerKey],
                        policy.RequiredFromIndex,
                        ct).ConfigureAwait(false))
                {
                    approvals++;
                    if (approvals >= policy.Threshold)
                        break;
                }
            }

            if (approvals < policy.Threshold)
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

    private async Task<bool> HasApprovalAtOrAfterAsync(
        VerificationSession session,
        SignerCoverageState signerState,
        int requiredFromIndex,
        CancellationToken ct)
    {
        if (signerState.LatestValidIndex is { } latestValidIndex)
            return latestValidIndex >= requiredFromIndex;

        while (signerState.Cursor < signerState.Candidates.Count)
        {
            ct.ThrowIfCancellationRequested();
            var candidate = signerState.Candidates[signerState.Cursor];
            if (candidate.VersionIndex < requiredFromIndex)
                return false;

            signerState.Cursor++;
            if (await VerifyWitnessProofAsync(session, candidate, ct).ConfigureAwait(false))
            {
                signerState.LatestValidIndex = candidate.VersionIndex;
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Verifies a candidate with the complete same-version dependency closure required by
    /// <c>previousProof</c>. Dependencies provide Data Integrity context only; threshold counting
    /// still attributes just the configured candidate signer.
    /// </summary>
    private async Task<bool> VerifyWitnessProofAsync(
        VerificationSession session,
        BoundProof candidate,
        CancellationToken ct)
    {
        if (session.TryGetVerdict(candidate.Proof, out var memoized))
            return memoized;

        if (session.IsResourceExhausted)
            return false;

        if (!session.TryGetDependencyClosure(candidate.Proof, ct, out var closure))
        {
            if (session.IsResourceExhausted)
                return false;
            session.SetVerdict(candidate.Proof, false);
            return false;
        }

        // The pipeline verifies every proof supplied. Charge the actual closure size before the
        // call, including dependencies that may already have a memoized standalone verdict,
        // because they are cryptographically processed again as part of this secured document.
        if (!session.TrySpend(closure.Count))
            return false;

        var options = new ProofVerificationOptions
        {
            ExpectedProofPurpose = "assertionMethod",
            VerificationTime = candidate.VersionTime
        };

        try
        {
            var securedDocumentJson = SerializeSecuredWitnessDocument(
                candidate.Proof.VersionId, closure);
            using var document = JsonDocument.Parse(securedDocumentJson);
            var result = await _pipeline.VerifyAsync(
                document.RootElement, WebVhWitnessKeyResolver.Instance, options, ct)
                .ConfigureAwait(false);
            ct.ThrowIfCancellationRequested();

            if (result.ProofResults.Count != closure.Count)
            {
                session.SetVerdict(candidate.Proof, false);
                return false;
            }

            if (!result.Verified || result.ProofResults.Any(proof => !proof.Verified))
            {
                // Individual proof results are not closure-aware: a child can verify its own
                // signature even when an ancestor named by previousProof is invalid. Never memoize
                // those raw true values from a failed aggregate, or a later policy can consume a
                // dependency as a standalone approval without rechecking its failed ancestors.
                session.SetVerdict(candidate.Proof, false);
                return false;
            }

            foreach (var proof in closure)
            {
                ct.ThrowIfCancellationRequested();
                session.SetVerdict(proof, true);
            }

            return true;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            session.SetVerdict(candidate.Proof, false);
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

    private sealed class PolicyRequirement(
        int requiredFromIndex,
        int threshold,
        IReadOnlyList<string> signerKeys)
    {
        public int RequiredFromIndex { get; set; } = requiredFromIndex;
        public int Threshold { get; } = threshold;
        public IReadOnlyList<string> SignerKeys { get; } = signerKeys;
    }

    private sealed class SignerCoverageState
    {
        public List<BoundProof> Candidates { get; } = [];
        public int Cursor { get; set; }
        public int? LatestValidIndex { get; set; }
    }

    private sealed record BoundProof(
        int VersionIndex,
        DateTimeOffset VersionTime,
        IndexedProof Proof);

    internal sealed class IndexedProof(
        string versionId,
        DataIntegrityProofValue value,
        int wireOrdinal,
        string? id,
        IReadOnlyList<string> previousProofIds,
        bool dependencyMetadataMalformed)
    {
        public string VersionId { get; } = versionId;
        public DataIntegrityProofValue Value { get; } = value;
        public int WireOrdinal { get; } = wireOrdinal;
        public string? Id { get; } = id;
        public IReadOnlyList<string> PreviousProofIds { get; } = previousProofIds;
        public bool DependencyMetadataMalformed { get; } = dependencyMetadataMalformed;
    }

    private sealed class ProofBucket
    {
        public List<IndexedProof> Proofs { get; } = [];
        public Dictionary<string, List<IndexedProof>> ProofsById { get; } =
            new(StringComparer.Ordinal);

        public void Add(IndexedProof proof)
        {
            Proofs.Add(proof);
            if (proof.Id is null)
                return;

            if (!ProofsById.TryGetValue(proof.Id, out var matching))
            {
                matching = [];
                ProofsById[proof.Id] = matching;
            }
            matching.Add(proof);
        }
    }

    private sealed class DependencyFrame(IndexedProof proof)
    {
        public IndexedProof Proof { get; } = proof;
        public int NextReferenceIndex { get; set; }
    }

    /// <summary>
    /// Resolution-local witness state. The index is immutable after construction; verdicts and
    /// the remaining budget are deliberately shared across prefix and deactivation-tail passes.
    /// Indexed proofs are bound to exactly one filed versionId, so reference-keyed verdicts cannot
    /// cross signed documents.
    /// </summary>
    internal sealed class VerificationSession
    {
        private readonly Dictionary<string, ProofBucket> _proofsByVersion =
            new(StringComparer.Ordinal);
        private readonly Dictionary<IndexedProof, bool> _verifiedByProof =
            new(ReferenceEqualityComparer.Instance);
        private int _remainingVerifications;
        private long _remainingDependencyTraversalSteps;

        internal bool IsResourceExhausted { get; private set; }
        internal long DependencyClosureMaterializationVisits { get; private set; }

        internal VerificationSession(
            WitnessFile witnessFile,
            int maxProofVerifications,
            CancellationToken ct)
        {
            _remainingVerifications = maxProofVerifications;
            var indexedProofCount = 0L;
            var seen = new HashSet<(string VersionId, string CanonicalProof)>(
                EqualityComparer<(string, string)>.Default);

            foreach (var entry in witnessFile.Entries)
            {
                ct.ThrowIfCancellationRequested();
                foreach (var proof in entry.Proofs)
                {
                    ct.ThrowIfCancellationRequested();
                    try
                    {
                        var canonicalJson = GetCanonicalProofJson(proof, ct);
                        if (!seen.Add((entry.VersionId, canonicalJson)))
                            continue;

                        if (!_proofsByVersion.TryGetValue(entry.VersionId, out var bucket))
                        {
                            bucket = new ProofBucket();
                            _proofsByVersion[entry.VersionId] = bucket;
                        }

                        var indexed = CreateIndexedProof(
                            entry.VersionId, proof, bucket.Proofs.Count, ct);
                        bucket.Add(indexed);
                        indexedProofCount++;
                    }
                    catch (Exception ex) when (ex is JsonException
                        or FormatException
                        or InvalidOperationException
                        or ArgumentException
                        or OverflowException)
                    {
                        // A syntactically valid proof can still be outside the JCS data model
                        // (for example a number that overflows IEEE-754). It is simply an invalid
                        // proof, not an exception that may escape resolution or poison an
                        // otherwise usable witness file.
                    }
                }
            }

            ct.ThrowIfCancellationRequested();
            // Each distinct candidate can be entered once, plus at most one dependency-node visit
            // per cryptographic work unit that could still be accepted. This prevents malformed
            // shared-chain fans from spending O(proofs x chain-length) before the crypto cap is
            // consulted, while every honest closure within the crypto budget fits.
            _remainingDependencyTraversalSteps = indexedProofCount + maxProofVerifications;
        }

        internal bool TryGetProofs(string versionId, out IReadOnlyList<IndexedProof> proofs)
        {
            if (_proofsByVersion.TryGetValue(versionId, out var bucket))
            {
                proofs = bucket.Proofs;
                return true;
            }

            proofs = [];
            return false;
        }

        internal bool TryGetVerdict(IndexedProof proof, out bool verified)
            => _verifiedByProof.TryGetValue(proof, out verified);

        internal void SetVerdict(IndexedProof proof, bool verified)
            => _verifiedByProof[proof] = verified;

        internal bool TrySpend(int count)
        {
            if (count < 1 || count > _remainingVerifications)
            {
                IsResourceExhausted = true;
                _remainingVerifications = 0;
                return false;
            }
            _remainingVerifications -= count;
            return true;
        }

        internal bool TryGetDependencyClosure(
            IndexedProof candidate,
            CancellationToken ct,
            out IReadOnlyList<IndexedProof> closure)
        {
            ct.ThrowIfCancellationRequested();
            if (!_proofsByVersion.TryGetValue(candidate.VersionId, out var bucket)
                || candidate.DependencyMetadataMalformed)
            {
                closure = [];
                return false;
            }

            var selected = new HashSet<IndexedProof>(ReferenceEqualityComparer.Instance);
            var states = new Dictionary<IndexedProof, byte>(ReferenceEqualityComparer.Instance);
            var stack = new Stack<DependencyFrame>();

            if (!TryEnter(candidate))
            {
                closure = [];
                return false;
            }

            while (stack.TryPeek(out var frame))
            {
                ct.ThrowIfCancellationRequested();
                if (frame.NextReferenceIndex < frame.Proof.PreviousProofIds.Count)
                {
                    var previousProofId =
                        frame.Proof.PreviousProofIds[frame.NextReferenceIndex++];
                    if (!bucket.ProofsById.TryGetValue(previousProofId, out var matches)
                        || matches.Count != 1)
                    {
                        closure = [];
                        return false;
                    }

                    var dependency = matches[0];
                    if (states.TryGetValue(dependency, out var state))
                    {
                        if (state == 1) // Visiting: back-edge/cycle.
                        {
                            closure = [];
                            return false;
                        }
                        continue; // Already completed in this closure.
                    }

                    if (!TryEnter(dependency))
                    {
                        closure = [];
                        return false;
                    }
                    continue;
                }

                stack.Pop();
                states[frame.Proof] = 2;
                selected.Add(frame.Proof);
            }

            // Preserve wire order. DataProofsDotnet returns per-proof results in document order,
            // so this also makes the result-to-index mapping deterministic.
            ct.ThrowIfCancellationRequested();
            DependencyClosureMaterializationVisits += selected.Count;
            closure = selected.OrderBy(proof => proof.WireOrdinal).ToArray();
            ct.ThrowIfCancellationRequested();
            return true;

            bool TryEnter(IndexedProof proof)
            {
                if (proof.DependencyMetadataMalformed)
                    return false;
                if (_remainingDependencyTraversalSteps <= 0)
                {
                    IsResourceExhausted = true;
                    return false;
                }

                _remainingDependencyTraversalSteps--;
                states[proof] = 1;
                stack.Push(new DependencyFrame(proof));
                return true;
            }
        }
    }

    /// <summary>
    /// The secured document for one witness proof closure, per did:webvh v1.0 "DID Witnesses": a Data
    /// Integrity proof that "use[s] the versionId as input data" — the JCS document
    /// <c>{"versionId": "..."}</c> secured by the proof under test. The versionId embeds the
    /// entry hash that chain validation independently recomputes over the full entry content
    /// before witness validation runs, so a witness approval transitively binds the whole
    /// entry. The proof is emitted with full wire fidelity so its complete signed configuration
    /// reaches the pipeline. (Issue #135: verifying against the entry serialized without proof
    /// interoperated with no other implementation.)
    /// </summary>
    private static string SerializeSecuredWitnessDocument(
        string versionId, IReadOnlyList<IndexedProof> proofs)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            writer.WriteString("versionId", versionId);
            writer.WritePropertyName("proof");
            writer.WriteStartArray();
            foreach (var proof in proofs)
                WriteProofObject(writer, proof.Value);
            writer.WriteEndArray();
            writer.WriteEndObject();
        }

        return Encoding.UTF8.GetString(stream.ToArray());
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

    private static string GetProofJson(DataIntegrityProofValue proof)
    {
        if (proof.RawJson is not null)
            return proof.RawJson;

        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
            WriteProofObject(writer, proof);
        return Encoding.UTF8.GetString(stream.ToArray());
    }

    private static string GetCanonicalProofJson(
        DataIntegrityProofValue proof,
        CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();
        using var document = JsonDocument.Parse(
            GetProofJson(proof),
            new JsonDocumentOptions { AllowDuplicateProperties = false });
        ct.ThrowIfCancellationRequested();
        if (document.RootElement.ValueKind != JsonValueKind.Object)
            throw new JsonException("A Data Integrity proof must be a JSON object.");
        var canonical = JcsCanonicalizer.Canonicalize(document.RootElement);
        ct.ThrowIfCancellationRequested();
        return Encoding.UTF8.GetString(canonical);
    }

    private static IndexedProof CreateIndexedProof(
        string versionId,
        DataIntegrityProofValue proof,
        int wireOrdinal,
        CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        string? id = null;
        var previousProofIds = new List<string>();
        var malformed = false;

        using var document = JsonDocument.Parse(
            GetProofJson(proof),
            new JsonDocumentOptions { AllowDuplicateProperties = false });
        ct.ThrowIfCancellationRequested();
        var root = document.RootElement;

        if (root.TryGetProperty("id", out var idElement))
        {
            if (idElement.ValueKind == JsonValueKind.String)
                id = idElement.GetString();
            else
                malformed = true;
        }

        if (root.TryGetProperty("previousProof", out var previousProof))
        {
            var distinctReferences = new HashSet<string>(StringComparer.Ordinal);
            if (previousProof.ValueKind == JsonValueKind.String)
            {
                var value = previousProof.GetString();
                if (string.IsNullOrEmpty(value))
                    malformed = true;
                else
                {
                    previousProofIds.Add(value);
                    distinctReferences.Add(value);
                }
            }
            else if (previousProof.ValueKind == JsonValueKind.Array)
            {
                if (previousProof.GetArrayLength() == 0)
                    malformed = true;
                foreach (var reference in previousProof.EnumerateArray())
                {
                    ct.ThrowIfCancellationRequested();
                    if (reference.ValueKind != JsonValueKind.String
                        || string.IsNullOrEmpty(reference.GetString()))
                    {
                        malformed = true;
                        continue;
                    }
                    var value = reference.GetString()!;
                    if (!distinctReferences.Add(value))
                        malformed = true;
                    previousProofIds.Add(value);
                }
            }
            else
            {
                malformed = true;
            }
        }

        ct.ThrowIfCancellationRequested();
        return new IndexedProof(
            versionId, proof, wireOrdinal, id, previousProofIds, malformed);
    }

    /// <summary>
    /// Merge new witness proof entries with existing ones. Proofs APPEND: did:webvh witness
    /// collection is incremental (the file is republished as approvals arrive), so a new proof
    /// for a version must join the existing approvals for that version, never replace them —
    /// replacement could sink an already threshold-satisfying version below its threshold for
    /// every resolver (issue #135 review round 2, finding 4). Complete proof objects are
    /// JCS-canonicalized for identity, so formatting/property-order variants deduplicate while
    /// different signature-bound members remain distinct. Duplicate-versionId entries on either
    /// side are aggregated (a ts-authored file carries one entry per proof).
    /// </summary>
    public static WitnessFile MergeWitnessProofs(
        WitnessFile? existing, IReadOnlyList<WitnessProofEntry> newEntries)
    {
        var proofsByVersion = new Dictionary<string, List<DataIntegrityProofValue>>(StringComparer.Ordinal);
        var versionOrder = new List<string>();
        var seen = new HashSet<(string VersionId, string CanonicalProof)>();

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
                if (seen.Add((entry.VersionId, GetCanonicalProofJson(proof))))
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
        => ParseWitnessFile(content, out _, CancellationToken.None);

    /// <summary>
    /// Parse a did-witness.json file, reporting why parsing failed. A swallowed parse failure
    /// surfaces to callers as a bare <c>witnessValidationFailed</c> with no diagnostic at all —
    /// exactly how the #135 wire-format divergence went unnoticed — so the failure reason must
    /// reach a log. <paramref name="parseError"/> carries only exception-type and library-owned
    /// message text, never raw witness-file content.
    /// </summary>
    public static WitnessFile? ParseWitnessFile(byte[] content, out string? parseError)
        => ParseWitnessFile(content, out parseError, CancellationToken.None);

    /// <summary>
    /// Parse a did-witness.json file with cooperative cancellation between bounded JSON parsing
    /// and per-proof normalization steps.
    /// </summary>
    public static WitnessFile? ParseWitnessFile(
        byte[] content,
        out string? parseError,
        CancellationToken ct)
    {
        try
        {
            ct.ThrowIfCancellationRequested();
            var json = LogEntrySerializer.DecodeUtf8(content);
            ct.ThrowIfCancellationRequested();

            // Untrusted remote JSON: reject duplicate members outright (recursive) — with
            // last-one-wins parsing a decoy duplicate could smuggle an unvalidated member
            // past validation (same trust-boundary rule as the log-entry parser, issue #101).
            using var doc = JsonDocument.Parse(
                json, new JsonDocumentOptions { AllowDuplicateProperties = false });
            ct.ThrowIfCancellationRequested();
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
                ct.ThrowIfCancellationRequested();
                entries.Add(ParseProofEntry(element, ct));
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

    private static WitnessProofEntry ParseProofEntry(
        JsonElement element,
        CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
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
        var proofs = new List<DataIntegrityProofValue>();
        if (element.TryGetProperty("proof", out var proofElement))
        {
            foreach (var proof in proofElement.EnumerateArray())
            {
                ct.ThrowIfCancellationRequested();
                proofs.Add(DataIntegrityProofValue.FromJson(proof));
                ct.ThrowIfCancellationRequested();
            }
        }

        return new WitnessProofEntry
        {
            VersionId = versionId,
            Proofs = proofs
        };
    }
}
