using System.Globalization;
using DataProofsDotnet.DataIntegrity;
using NetDid.Core.Exceptions;
using NetDid.Method.WebVh.Model;

namespace NetDid.Method.WebVh;

/// <summary>
/// Validates the integrity and authenticity of a did:webvh log chain.
/// </summary>
internal sealed class LogChainValidator
{
    private readonly EddsaJcs2022Cryptosuite _suite;

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

        // SCID must be set
        if (string.IsNullOrEmpty(genesis.Parameters.Scid))
            throw new LogChainValidationException(1,
                "Genesis entry must have SCID in parameters.");

        // Verify the SCID value in parameters matches the entry hash portion of versionId
        if (genesis.Parameters.Scid != genesis.EntryHash)
            throw new LogChainValidationException(1,
                "SCID parameter does not match the genesis entry hash.");

        // Verify SCID by reverse-substituting the SCID value back to {SCID} placeholders
        // and recomputing the hash (two-pass verification per spec)
        var scid = genesis.Parameters.Scid;
        var entryJsonWithoutProof = LogEntrySerializer.SerializeWithoutProof(genesis);
        var templateJson = entryJsonWithoutProof.Replace(scid, ScidGenerator.Placeholder);
        var computedScid = ScidGenerator.ComputeScid(templateJson);

        if (computedScid != scid)
            throw new LogChainValidationException(1,
                "Genesis entry hash does not match computed hash (SCID verification failed).");

        // Verify proof
        ValidateProof(genesis, genesis.Parameters.UpdateKeys, 1);
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

        // Verify entry hash: recreate the entry with the previous versionId
        // as specified by the spec: versionId = "<versionNumber>-<previousVersionId>"
        var expectedVersionText = expectedVersion.ToString(CultureInfo.InvariantCulture);
        var entryForHashing = current with { VersionId = $"{expectedVersionText}-{previous.VersionId}" };
        var entryJsonWithoutProof = LogEntrySerializer.SerializeWithoutProof(entryForHashing);
        var computedHash = ScidGenerator.ComputeEntryHash(entryJsonWithoutProof);

        if (computedHash != current.EntryHash)
            throw new LogChainValidationException(expectedVersion,
                $"Entry hash mismatch at version {expectedVersion}.");

        // Verify proof is signed by an authorized update key from the PREVIOUS effective params
        var authorizedKeys = effectiveParams.UpdateKeys
            ?? throw new LogChainValidationException(expectedVersion,
                $"No updateKeys defined at version {expectedVersion - 1}.");

        ValidateProof(current, authorizedKeys, expectedVersion);

        // If pre-rotation was active in previous entry, validate key rotation
        if (effectiveParams.Prerotation == true && effectiveParams.NextKeyHashes is { Count: > 0 })
        {
            ValidatePreRotation(current, effectiveParams.NextKeyHashes, expectedVersion);
        }
    }

    private void ValidateProof(LogEntry entry, IReadOnlyList<string>? authorizedKeys, int version)
    {
        if (entry.Proof is null || entry.Proof.Count == 0)
            throw new LogChainValidationException(version,
                $"No proof found at version {version}.");

        var entryJsonWithoutProof = LogEntrySerializer.SerializeWithoutProof(entry);

        // At least one proof must be valid from an authorized update key
        foreach (var proofValue in entry.Proof)
        {
            // Verify the signature; the returned multibase is the signer's did:key id with
            // the DID==fragment anti-spoof check already enforced. Null => invalid signature
            // or malformed verificationMethod.
            var signerKey = WebVhProofVerifier.VerifyAndExtractSigner(_suite, entryJsonWithoutProof, proofValue);
            if (signerKey is null)
                continue;

            // Verify the signer is an authorized update key. Exact equality between the
            // signer's multibase key and an entry in authorizedKeys — substring matching would
            // allow a proof with verificationMethod = "did:key:<attacker>#<authorized>" to be
            // signed by the attacker yet authorized as the legitimate key.
            if (authorizedKeys is null)
                return; // Valid proof, no key restriction

            if (authorizedKeys.Contains(signerKey, StringComparer.Ordinal))
                return; // Valid proof from authorized key
        }

        throw new LogChainValidationException(version,
            $"No valid proof from an authorized update key at version {version}.");
    }

    private static void ValidatePreRotation(
        LogEntry current,
        IReadOnlyList<string> previousNextKeyHashes,
        int version)
    {
        // Pre-rotation requires that this entry introduces new updateKeys
        // that match the previously committed nextKeyHashes.
        // If no new updateKeys are provided, the entry is invalid under pre-rotation.
        if (current.Parameters.UpdateKeys is not { Count: > 0 })
            throw new LogChainValidationException(version,
                $"Pre-rotation is active but version {version} does not introduce new updateKeys. " +
                "When pre-rotation is enabled, every update must rotate keys.");

        foreach (var newKey in current.Parameters.UpdateKeys)
        {
            PreRotationManager.ValidateKeyRotation(newKey, previousNextKeyHashes, version);
        }
    }
}
