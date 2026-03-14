using NetDid.Core.Crypto.DataIntegrity;
using NetDid.Core.Exceptions;
using NetDid.Method.WebVh.Model;

namespace NetDid.Method.WebVh;

/// <summary>
/// Validates the integrity and authenticity of a did:webvh log chain.
/// </summary>
internal sealed class LogChainValidator
{
    private readonly DataIntegrityProofEngine _proofEngine;

    public LogChainValidator(DataIntegrityProofEngine proofEngine)
    {
        _proofEngine = proofEngine;
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
        if (entries.Count == 0)
            throw new LogChainValidationException(0, "DID log is empty.");

        var count = Math.Min(upToCount, entries.Count);

        // Validate genesis entry
        var genesis = entries[0];
        ValidateGenesisEntry(genesis);

        var effectiveParams = genesis.Parameters;

        // Validate subsequent entries
        for (int i = 1; i < count; i++)
        {
            var previous = entries[i - 1];
            var current = entries[i];

            ValidateSubsequentEntry(current, previous, effectiveParams, i + 1);

            // Merge parameters for the next iteration
            effectiveParams = current.Parameters.MergeWith(effectiveParams);
        }

        return effectiveParams;
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
        var savedVersionId = current.VersionId;
        current.VersionId = $"{expectedVersion}-{previous.VersionId}";
        var entryJsonWithoutProof = LogEntrySerializer.SerializeWithoutProof(current);
        var computedHash = ScidGenerator.ComputeEntryHash(entryJsonWithoutProof);
        current.VersionId = savedVersionId; // Restore original

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
            var proof = new DataIntegrityProof
            {
                Cryptosuite = proofValue.Cryptosuite,
                VerificationMethod = proofValue.VerificationMethod,
                Created = DateTimeOffset.Parse(proofValue.Created),
                ProofPurpose = proofValue.ProofPurpose,
                ProofValue = proofValue.ProofValue
            };

            // Verify the proof signature
            if (!_proofEngine.VerifyProof(entryJsonWithoutProof, proof))
                continue;

            // Verify the signer is an authorized update key
            if (authorizedKeys is not null)
            {
                var publicKey = DataIntegrityProofEngine.ExtractPublicKeyFromDidKey(proof.VerificationMethod);
                if (publicKey is null) continue;

                // Check if the proof's key matches any authorized update key
                foreach (var authorizedKey in authorizedKeys)
                {
                    // The verificationMethod is "did:key:{multibase}#{multibase}"
                    // The authorizedKey is just the multibase portion
                    if (proof.VerificationMethod.Contains(authorizedKey))
                        return; // Valid proof from authorized key
                }
            }
            else
            {
                return; // Valid proof, no key restriction
            }
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
