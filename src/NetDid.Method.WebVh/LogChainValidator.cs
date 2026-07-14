using System.Globalization;
using DataProofsDotnet;
using DataProofsDotnet.DataIntegrity;
using NetCrypto;
using NetDid.Core.Exceptions;
using NetDid.Method.WebVh.Model;

namespace NetDid.Method.WebVh;

/// <summary>
/// Validates the integrity and authenticity of a did:webvh log chain.
/// </summary>
internal sealed class LogChainValidator
{
    /// <summary>
    /// Default upper bound on controller proofs verified per entry. Verifying each proof
    /// re-canonicalizes the entry document, so this is an explicit resource policy (not a
    /// conformance rule) that bounds per-entry verification work to
    /// <c>bound × entry-size</c> over an already size-capped log. Real entries carry a single
    /// controller proof; the default is far above any realistic co-signing arrangement.
    /// Configurable via the constructor. An entry exceeding it is rejected as invalidDidLog.
    /// </summary>
    internal const int DefaultMaxControllerProofsPerEntry = 8;

    private readonly DataIntegrityProofPipeline _pipeline;
    private readonly int _maxControllerProofsPerEntry;

    public LogChainValidator(
        int maxControllerProofsPerEntry = DefaultMaxControllerProofsPerEntry)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(maxControllerProofsPerEntry, 1);

        _pipeline = new DataIntegrityProofPipeline();
        _maxControllerProofsPerEntry = maxControllerProofsPerEntry;
    }

    /// <summary>
    /// Validate the entire log chain.
    /// Returns the effective parameters at the final entry on success.
    /// Throws LogChainValidationException on failure.
    /// </summary>
    public Task<LogEntryParameters> ValidateChainAsync(
        IReadOnlyList<LogEntry> entries, CancellationToken ct = default)
    {
        return ValidateChainAsync(entries, entries.Count, ct);
    }

    /// <summary>
    /// Validate the log chain up to the specified entry count.
    /// Returns the effective parameters at the last validated entry.
    /// Throws LogChainValidationException on failure.
    /// </summary>
    public async Task<LogEntryParameters> ValidateChainAsync(
        IReadOnlyList<LogEntry> entries, int upToCount, CancellationToken ct = default)
    {
        var perEntry = await ValidateChainWithPerEntryParamsAsync(entries, upToCount, ct);
        return perEntry[^1];
    }

    /// <summary>
    /// Validate the log chain and return the effective parameters at each entry.
    /// Index 0 = genesis entry's effective params, etc.
    /// Throws LogChainValidationException on failure.
    /// </summary>
    public async Task<IReadOnlyList<LogEntryParameters>> ValidateChainWithPerEntryParamsAsync(
        IReadOnlyList<LogEntry> entries, int upToCount, CancellationToken ct = default)
    {
        if (entries.Count == 0)
            throw new LogChainValidationException(0, "DID log is empty.");

        var count = Math.Min(upToCount, entries.Count);
        var result = new List<LogEntryParameters>(count);

        // Validate genesis entry
        var genesis = entries[0];
        await ValidateGenesisEntryAsync(genesis, ct);

        // did:webvh v1.0: "The SCID segment of state.id MUST be byte-for-byte identical to the
        // scid value in the DID and the first entry's parameters.scid. This check MUST apply to
        // every entry's state.id, not just the first. A mismatch MUST terminate resolution."
        // SCID-level (not full-DID) comparison keeps portable host/path renames valid. Enforced
        // here so resolution, update, and deactivation share one identity gate: the driver can
        // never build on a log its own resolver rejects.
        var scid = genesis.Parameters.Scid!;
        ValidateStateScidConsistency(genesis, scid, 1);

        var effectiveParams = genesis.Parameters;
        result.Add(effectiveParams);

        // Validate subsequent entries
        for (int i = 1; i < count; i++)
        {
            var previous = entries[i - 1];
            var current = entries[i];

            ValidateStateScidConsistency(current, scid, i + 1);
            await ValidateSubsequentEntryAsync(current, previous, effectiveParams, i + 1, ct);

            // Merge parameters for the next iteration
            effectiveParams = current.Parameters.MergeWith(effectiveParams);
            result.Add(effectiveParams);
        }

        return result;
    }

    private async Task ValidateGenesisEntryAsync(LogEntry genesis, CancellationToken ct)
    {
        // Version number must be 1
        if (genesis.VersionNumber != 1)
            throw new LogChainValidationException(1,
                $"Genesis entry version must be 1, got {genesis.VersionNumber}.");

        ValidateWitnessPolicy(genesis.Parameters.Witness, 1);
        if (genesis.Parameters.Watchers is { } genesisWatchers)
            ValidateWatchers(genesisWatchers, 1);

        if (!string.Equals(
                genesis.Parameters.Method,
                DidWebVhMethod.MethodVersion,
                StringComparison.Ordinal))
            throw new LogChainValidationException(1,
                $"Unsupported did:webvh method version '{genesis.Parameters.Method}'.");

        // SCID must be set
        if (string.IsNullOrEmpty(genesis.Parameters.Scid))
            throw new LogChainValidationException(1,
                "Genesis entry must have SCID in parameters.");

        // The SCID and genesis entry hash are separate values. Reconstruct the preliminary
        // post-SCID entry whose versionId is the SCID itself; it is the input to the genesis
        // entry-hash calculation and to reverse-substitution for SCID verification.
        var scid = genesis.Parameters.Scid;
        var entryJsonForHashing = LogEntrySerializer.SerializeWithoutProof(genesis, scid);

        var computedEntryHash = ScidGenerator.ComputeEntryHash(entryJsonForHashing);
        if (computedEntryHash != genesis.EntryHash)
            throw new LogChainValidationException(1,
                "Genesis entry hash does not match computed hash.");

        // Verify SCID by reverse-substituting every SCID occurrence with the spec placeholder.
        var templateJson = entryJsonForHashing.Replace(scid, ScidGenerator.Placeholder);
        var computedScid = ScidGenerator.ComputeScid(templateJson);

        if (computedScid != scid)
            throw new LogChainValidationException(1,
                "Genesis SCID does not match computed hash (SCID verification failed).");

        // Genesis is always authorized by its own explicitly declared update keys.
        var genesisUpdateKeys = genesis.Parameters.UpdateKeys;
        if (genesisUpdateKeys is not { Count: > 0 })
            throw new LogChainValidationException(1,
                "Genesis entry must define at least one updateKey.");

        ValidateUpdateKeys(genesisUpdateKeys, 1);

        await ValidateProofAsync(genesis, genesisUpdateKeys, 1, ct);
    }

    private async Task ValidateSubsequentEntryAsync(
        LogEntry current,
        LogEntry previous,
        LogEntryParameters effectiveParams,
        int expectedVersion,
        CancellationToken ct)
    {
        // Check if previous entry was deactivated
        if (effectiveParams.Deactivated == true)
            throw new LogChainValidationException(expectedVersion,
                $"Cannot append entries after deactivation (version {expectedVersion}).");

        // Version number must increment
        if (current.VersionNumber != expectedVersion)
            throw new LogChainValidationException(expectedVersion,
                $"Expected version {expectedVersion}, got {current.VersionNumber}.");

        ValidateVersionTime(previous.VersionTime, current.VersionTime, expectedVersion);
        ValidateWitnessPolicy(current.Parameters.Witness, expectedVersion);
        if (current.Parameters.Watchers is { } currentWatchers)
            ValidateWatchers(currentWatchers, expectedVersion);

        if (current.Parameters.Method is not null && !string.Equals(
                current.Parameters.Method,
                DidWebVhMethod.MethodVersion,
                StringComparison.Ordinal))
            throw new LogChainValidationException(expectedVersion,
                $"Unsupported did:webvh method version '{current.Parameters.Method}'.");

        // Verify entry hash: the hash input's versionId is exactly the previous entry's
        // full published versionId.
        var entryJsonWithoutProof = LogEntrySerializer.SerializeWithoutProof(
            current,
            previous.VersionId);
        var computedHash = ScidGenerator.ComputeEntryHash(entryJsonWithoutProof);

        if (computedHash != current.EntryHash)
            throw new LogChainValidationException(expectedVersion,
                $"Entry hash mismatch at version {expectedVersion}.");

        if (current.Parameters.UpdateKeys is { } currentUpdateKeys)
            ValidateUpdateKeys(currentUpdateKeys, expectedVersion);

        IReadOnlyList<string> authorizedKeys;
        if (effectiveParams.NextKeyHashes is { Count: > 0 } previousNextKeyHashes)
        {
            // Pre-rotation was activated by the previous effective parameters. The current
            // entry must reveal committed keys explicitly, carry the next commitment array
            // explicitly (including [] to turn pre-rotation off), and be authorized by one of
            // its own revealed keys.
            authorizedKeys = ValidatePreRotation(
                current, previousNextKeyHashes, expectedVersion);
        }
        else
        {
            // Without pre-rotation, the most recent prior updateKeys authorize this entry.
            authorizedKeys = effectiveParams.UpdateKeys is { Count: > 0 } previousUpdateKeys
                ? previousUpdateKeys
                : throw new LogChainValidationException(expectedVersion,
                    $"No updateKeys authorize version {expectedVersion}.");
        }

        await ValidateProofAsync(current, authorizedKeys, expectedVersion, ct);
    }

    /// <summary>
    /// Enforces the per-entry identity rule: every validated entry's <c>state.id</c> must be a
    /// did:webvh DID whose SCID segment equals the genesis <c>parameters.scid</c> byte-for-byte.
    /// The comparison is deliberately SCID-level — under portability only the host/path portion
    /// of <c>state.id</c> may change; the SCID is immutable for the life of the DID.
    /// </summary>
    private static void ValidateStateScidConsistency(LogEntry entry, string scid, int version)
    {
        var stateId = entry.State.Id.Value;
        if (string.IsNullOrEmpty(stateId))
            throw new LogChainValidationException(version,
                $"Entry {version} document has no id; every entry's state.id must carry the log's SCID.");

        string entryScid;
        try
        {
            entryScid = DidUrlMapper.ExtractScid(stateId);
        }
        catch (ArgumentException)
        {
            throw new LogChainValidationException(version,
                $"Entry {version} state.id is not a valid did:webvh DID.");
        }

        if (!stateId.StartsWith("did:webvh:", StringComparison.Ordinal)
            || !string.Equals(entryScid, scid, StringComparison.Ordinal))
        {
            throw new LogChainValidationException(version,
                $"Entry {version} state.id SCID does not match the log's SCID.");
        }
    }

    /// <summary>
    /// Ensures adjacent entries use strictly increasing instants. This compares the already
    /// parsed values only; serialization continues to use each entry's authenticated wire token.
    /// </summary>
    internal static void ValidateVersionTime(
        DateTimeOffset previous, DateTimeOffset current, int version)
    {
        if (current <= previous)
            throw new LogChainValidationException(version,
                $"versionTime at version {version} must be strictly later than version {version - 1}.");
    }

    private static void ValidateWitnessPolicy(WitnessConfig? config, int version)
    {
        var error = WitnessPolicyValidator.GetValidationError(config);
        if (error is not null)
            throw new LogChainValidationException(version, error);
    }

    /// <summary>
    /// Enforces the did:webvh v1.0 controller-proof rule: an entry requires at least one proof,
    /// and <b>every</b> supplied proof must pass the checks implemented by DataProofsDotnet's
    /// <see cref="DataIntegrityProofPipeline"/> plus NetDid's application-boundary checks, and be
    /// authorized by the active <paramref name="authorizedKeys"/>. "Resolvers MUST reject an
    /// entry whose proof fails any check" — existential acceptance would admit logs that
    /// stricter conforming resolvers reject (issue #101). One authorized signer suffices to
    /// authorize the entry; there is no threshold semantics for controller proofs.
    /// </summary>
    /// <remarks>
    /// The pipeline verifies each proof's signature over the entry (with the <c>proof</c>
    /// removed), enforces the required type/cryptosuite/purpose, resolves any
    /// <c>previousProof</c> chain, and rejects a proof whose <c>expires</c> is at or before the
    /// entry's <c>versionTime</c>. Authorization — a <c>did:key</c> verificationMethod (anti-spoof)
    /// whose Ed25519 multibase is verbatim in the active updateKeys, used for
    /// <c>assertionMethod</c> — is supplied by <see cref="WebVhUpdateKeyResolver"/>. Verifying
    /// each proof re-canonicalizes the entry, so the proof count is bounded by
    /// <see cref="_maxControllerProofsPerEntry"/> as an explicit resource policy (see
    /// <see cref="DefaultMaxControllerProofsPerEntry"/>).
    /// </remarks>
    private async Task ValidateProofAsync(
        LogEntry entry, IReadOnlyList<string> authorizedKeys, int version, CancellationToken ct)
    {
        // Snapshot once: an IReadOnlyList implementation could present different contents
        // per enumeration, letting a proof escape validation.
        var proofs = entry.Proof?.ToArray();
        if (proofs is not { Length: > 0 })
            throw new LogChainValidationException(version,
                $"No proof found at version {version}.");

        // Bound verification work before doing any: the pipeline verifies every proof and each
        // verification re-canonicalizes the entry document. `created` is attacker-chosen and
        // part of the signed proof configuration, so one active key can mint arbitrarily many
        // distinct valid proofs — the count, not key diversity, is what must be capped.
        if (proofs.Length > _maxControllerProofsPerEntry)
            throw new LogChainValidationException(version,
                $"Entry at version {version} declares {proofs.Length} controller proofs, " +
                $"exceeding the resolver's limit of {_maxControllerProofsPerEntry}.");

        // Verify against the entry as published (full-fidelity proofs via RawJson): the pipeline
        // removes the proof member, JCS-canonicalizes the rest, and checks every proof. Its
        // resolver authorizes only did:key methods whose Ed25519 multibase is an active update
        // key used for assertionMethod; VerificationTime pins the expires policy to versionTime.
        // Serialization is inside the try so any failure is reported as a chain-validation error
        // (invalidDidLog), never as notFound.
        var resolver = new WebVhUpdateKeyResolver(authorizedKeys);
        var options = new ProofVerificationOptions
        {
            ExpectedProofPurpose = "assertionMethod",
            VerificationTime = entry.VersionTime
        };

        DocumentVerificationResult result;
        try
        {
            var securedDocumentJson = LogEntrySerializer.Serialize(entry);
            using var document = System.Text.Json.JsonDocument.Parse(securedDocumentJson);
            result = await _pipeline.VerifyAsync(document.RootElement, resolver, options, ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // A verification path must never throw for hostile input.
            throw new LogChainValidationException(version,
                $"Proof verification failed at version {version} ({ex.GetType().Name}).");
        }

        if (!result.Verified)
        {
            var reason = result.ProofResults
                .SelectMany(r => r.Problems)
                .Select(p => p.Message)
                .FirstOrDefault(m => m is not null)
                ?? result.Problems.Select(p => p.Message).FirstOrDefault(m => m is not null)
                ?? "a controller proof failed Data Integrity verification or is not from an active update key";
            throw new LogChainValidationException(version,
                $"Proof validation failed at version {version}: {reason}");
        }
    }

    private static IReadOnlyList<string> ValidatePreRotation(
        LogEntry current,
        IReadOnlyList<string> previousNextKeyHashes,
        int version)
    {
        // Omission cannot inherit either field while pre-rotation is active. An explicit empty
        // nextKeyHashes array is valid and deactivates pre-rotation after this entry.
        if (current.Parameters.UpdateKeys is not { Count: > 0 })
            throw new LogChainValidationException(version,
                $"Pre-rotation is active but version {version} does not explicitly define " +
                "at least one updateKey.");

        if (current.Parameters.NextKeyHashes is null)
            throw new LogChainValidationException(version,
                $"Pre-rotation is active but version {version} does not explicitly define " +
                "nextKeyHashes.");

        foreach (var currentKey in current.Parameters.UpdateKeys)
        {
            PreRotationManager.ValidateKeyRotation(currentKey, previousNextKeyHashes, version);
        }

        return current.Parameters.UpdateKeys;
    }

    /// <summary>
    /// Enforces the v1.0 authorization-key algorithm policy for every declared update key, not
    /// only the proof signer. Without this full-set validation, a committed malformed or
    /// unsupported extra value could enter the effective authorization set.
    /// </summary>
    internal static void ValidateUpdateKeys(IReadOnlyList<string> updateKeys, int version)
    {
        foreach (var updateKey in updateKeys)
        {
            var isValidEd25519Multikey = false;
            try
            {
                isValidEd25519Multikey =
                    PublicKeyMaterial.FromMultikey(updateKey).KeyType == KeyType.Ed25519;
            }
            catch
            {
                // Converted to the trust-boundary validation error below.
            }

            if (!isValidEd25519Multikey)
                throw new LogChainValidationException(version,
                    $"updateKeys at version {version} contains a value that is not a valid " +
                    "Ed25519 Multikey.");
        }
    }

    /// <summary>Validates watcher endpoints as absolute HTTP(S) URLs.</summary>
    internal static void ValidateWatchers(IReadOnlyList<string> watchers, int version)
    {
        foreach (var watcher in watchers)
        {
            if (string.IsNullOrWhiteSpace(watcher)
                || !Uri.TryCreate(watcher, UriKind.Absolute, out var uri)
                || (uri.Scheme != Uri.UriSchemeHttps && uri.Scheme != Uri.UriSchemeHttp)
                || string.IsNullOrEmpty(uri.Host)
                || !string.IsNullOrEmpty(uri.UserInfo))
            {
                throw new LogChainValidationException(version,
                    $"watchers at version {version} contains an invalid HTTP(S) URL.");
            }
        }
    }
}
