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
    private readonly EddsaJcs2022Cryptosuite _suite;

    /// <summary>
    /// Upper bound on controller proofs per entry. did:webvh does not define a limit; this is a
    /// resource guard against a fetched entry that packs many proofs to amplify per-proof
    /// verification work. Real entries carry one proof (at most one per active update key), so
    /// this ceiling never rejects a legitimate log.
    /// </summary>
    internal const int MaxProofsPerEntry = 100;

    public LogChainValidator(EddsaJcs2022Cryptosuite suite)
    {
        _suite = suite;
    }

    /// <summary>
    /// Validate the entire log chain.
    /// Returns the effective parameters at the final entry on success.
    /// Throws LogChainValidationException on failure.
    /// </summary>
    public LogEntryParameters ValidateChain(IReadOnlyList<LogEntry> entries)
    {
        return ValidateChain(entries, entries.Count);
    }

    /// <summary>
    /// Validate the log chain up to the specified entry count.
    /// Returns the effective parameters at the last validated entry.
    /// Throws LogChainValidationException on failure.
    /// </summary>
    public LogEntryParameters ValidateChain(IReadOnlyList<LogEntry> entries, int upToCount)
    {
        var perEntry = ValidateChainWithPerEntryParams(entries, upToCount);
        return perEntry[^1];
    }

    /// <summary>
    /// Validate the log chain and return the effective parameters at each entry.
    /// Index 0 = genesis entry's effective params, etc.
    /// Throws LogChainValidationException on failure.
    /// </summary>
    public IReadOnlyList<LogEntryParameters> ValidateChainWithPerEntryParams(
        IReadOnlyList<LogEntry> entries, int upToCount)
    {
        if (entries.Count == 0)
            throw new LogChainValidationException(0, "DID log is empty.");

        var count = Math.Min(upToCount, entries.Count);
        var result = new List<LogEntryParameters>(count);

        // Validate genesis entry
        var genesis = entries[0];
        ValidateGenesisEntry(genesis);

        var effectiveParams = genesis.Parameters;
        result.Add(effectiveParams);

        // Validate subsequent entries
        for (int i = 1; i < count; i++)
        {
            var previous = entries[i - 1];
            var current = entries[i];

            ValidateSubsequentEntry(current, previous, effectiveParams, i + 1);

            // Merge parameters for the next iteration
            effectiveParams = current.Parameters.MergeWith(effectiveParams);
            result.Add(effectiveParams);
        }

        return result;
    }

    private void ValidateGenesisEntry(LogEntry genesis)
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
        var genesisForHashing = genesis with { VersionId = scid };
        var entryJsonForHashing = LogEntrySerializer.SerializeWithoutProof(genesisForHashing);

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

        ValidateProof(genesis, genesisUpdateKeys, 1);
    }

    private void ValidateSubsequentEntry(
        LogEntry current,
        LogEntry previous,
        LogEntryParameters effectiveParams,
        int expectedVersion)
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
        var entryForHashing = current with { VersionId = previous.VersionId };
        var entryJsonWithoutProof = LogEntrySerializer.SerializeWithoutProof(entryForHashing);
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

        ValidateProof(current, authorizedKeys, expectedVersion);
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
    /// Enforces the did:webvh v1.0 controller-proof rule: an entry requires at least one
    /// proof, and <b>every</b> supplied proof must pass the method's checks — type
    /// <c>DataIntegrityProof</c>, cryptosuite <c>eddsa-jcs-2022</c>, purpose
    /// <c>assertionMethod</c>, a valid signature over the entry, and a signer verbatim in
    /// the active <paramref name="authorizedKeys"/>. "Resolvers MUST reject an entry whose
    /// proof fails any check" — existential acceptance would admit logs that stricter
    /// conforming resolvers reject (issue #101). One authorized signer suffices to
    /// authorize the entry; there is no threshold semantics for controller proofs.
    /// </summary>
    private void ValidateProof(LogEntry entry, IReadOnlyList<string> authorizedKeys, int version)
    {
        // Snapshot once: an IReadOnlyList implementation could present different contents
        // per enumeration, letting a proof escape validation.
        var proofs = entry.Proof?.ToArray();
        if (proofs is not { Length: > 0 })
            throw new LogChainValidationException(version,
                $"No proof found at version {version}.");

        // Universal validation verifies every proof (each re-canonicalizes the whole entry),
        // so an unbounded proof array is a resource-amplification vector even though the
        // fetched log is already size-capped. A legitimate entry needs one proof and at most
        // one per active update key; this ceiling is far above any real use.
        if (proofs.Length > MaxProofsPerEntry)
            throw new LogChainValidationException(version,
                $"Entry at version {version} declares {proofs.Length} proofs, exceeding the " +
                $"maximum of {MaxProofsPerEntry}.");

        var entryJsonWithoutProof = LogEntrySerializer.SerializeWithoutProof(entry);

        foreach (var proofValue in proofs)
        {
            // Method-specific policy first, so wrong-type/suite/purpose proofs are reported
            // precisely regardless of signature validity. The cryptosuite independently
            // rejects mismatched type/cryptosuite during verification; proofPurpose is
            // enforced only here — Data Integrity leaves purpose checking to the consumer.
            if (!string.Equals(proofValue.Type, "DataIntegrityProof", StringComparison.Ordinal))
                throw new LogChainValidationException(version,
                    $"Proof at version {version} has unsupported type '{proofValue.Type}'.");

            if (!string.Equals(
                    proofValue.Cryptosuite,
                    EddsaJcs2022Cryptosuite.CryptosuiteName,
                    StringComparison.Ordinal))
                throw new LogChainValidationException(version,
                    $"Proof at version {version} has unsupported cryptosuite " +
                    $"'{proofValue.Cryptosuite}'.");

            if (!string.Equals(proofValue.ProofPurpose, "assertionMethod", StringComparison.Ordinal))
                throw new LogChainValidationException(version,
                    $"Proof at version {version} has proofPurpose '{proofValue.ProofPurpose}'; " +
                    "did:webvh requires 'assertionMethod'.");

            // Verify the signature; the returned multibase is the signer's did:key id with
            // the DID==fragment anti-spoof check already enforced. Null => invalid signature
            // or malformed verificationMethod.
            var signerKey = WebVhProofVerifier.VerifyAndExtractSigner(_suite, entryJsonWithoutProof, proofValue);
            if (signerKey is null)
                throw new LogChainValidationException(version,
                    $"Proof at version {version} has an invalid signature or malformed " +
                    "verificationMethod.");

            // Verify the signer is an authorized update key. Exact equality between the
            // signer's multibase key and an entry in authorizedKeys — substring matching would
            // allow a proof with verificationMethod = "did:key:<attacker>#<authorized>" to be
            // signed by the attacker yet authorized as the legitimate key.
            if (!authorizedKeys.Contains(signerKey, StringComparer.Ordinal))
                throw new LogChainValidationException(version,
                    $"Proof at version {version} is signed by a key that is not an " +
                    "authorized update key.");
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
