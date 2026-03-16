using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using NetDid.Core;
using NetDid.Core.Crypto;
using NetDid.Core.Crypto.DataIntegrity;
using NetDid.Core.Model;
using NetDid.Method.WebVh.Model;

namespace NetDid.Method.WebVh;

/// <summary>
/// Implementation of the did:webvh DID method (did:web + Verifiable History).
/// Supports full CRUD: Create, Resolve, Update, Deactivate.
/// </summary>
public sealed class DidWebVhMethod : DidMethodBase
{
    private readonly IWebVhHttpClient _httpClient;
    private readonly ICryptoProvider _crypto;
    private readonly DataIntegrityProofEngine _proofEngine;
    private readonly LogChainValidator _chainValidator;
    private readonly WitnessValidator _witnessValidator;
    private readonly ILogger<DidWebVhMethod> _logger;

    internal const string MethodVersion = "did:webvh:1.0";

    public DidWebVhMethod(IWebVhHttpClient httpClient, ICryptoProvider crypto, ILogger<DidWebVhMethod>? logger = null)
    {
        _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        _crypto = crypto ?? throw new ArgumentNullException(nameof(crypto));
        _proofEngine = new DataIntegrityProofEngine(crypto);
        _chainValidator = new LogChainValidator(_proofEngine);
        _witnessValidator = new WitnessValidator(_proofEngine);
        _logger = logger ?? NullLogger<DidWebVhMethod>.Instance;
    }

    public override string MethodName => "webvh";

    public override DidMethodCapabilities Capabilities =>
        DidMethodCapabilities.Create |
        DidMethodCapabilities.Resolve |
        DidMethodCapabilities.Update |
        DidMethodCapabilities.Deactivate |
        DidMethodCapabilities.ServiceEndpoints;

    protected override async Task<DidCreateResult> CreateCoreAsync(
        DidCreateOptions options, CancellationToken ct)
    {
        if (options is not DidWebVhCreateOptions createOptions)
            throw new ArgumentException($"Options must be {nameof(DidWebVhCreateOptions)}.", nameof(options));

        if (createOptions.UpdateKey.KeyType != KeyType.Ed25519)
            throw new ArgumentException("did:webvh requires an Ed25519 update key.");

        // Step 1: Build DID string with safe placeholder (valid DID syntax for object construction)
        var didTemplate = BuildDidTemplate(createOptions.Domain, createOptions.Path,
            ScidGenerator.SafePlaceholder);

        // Step 2: Build the DID Document with safe placeholder
        var docTemplate = BuildDocumentTemplate(didTemplate, createOptions);

        // Step 3: Build the genesis log entry with safe placeholder
        var genesisParams = BuildGenesisParameters(createOptions, ScidGenerator.SafePlaceholder);
        var genesisEntry = new LogEntry
        {
            VersionId = $"1-{ScidGenerator.SafePlaceholder}",
            VersionTime = DateTimeOffset.UtcNow,
            Parameters = genesisParams,
            State = docTemplate
        };

        // Step 4: Serialize, then swap safe placeholder to spec-level {SCID} for SCID computation
        var entryJsonWithSafePlaceholder = LogEntrySerializer.SerializeWithoutProof(genesisEntry);
        var entryJsonWithPlaceholders = entryJsonWithSafePlaceholder.Replace(
            ScidGenerator.SafePlaceholder, ScidGenerator.Placeholder);

        // Step 5: Compute SCID from JSON with {SCID} placeholders (per spec)
        var scid = ScidGenerator.ComputeScid(entryJsonWithPlaceholders);

        // Step 6: Replace all {SCID} placeholders
        var entryJsonWithScid = ScidGenerator.ReplacePlaceholders(entryJsonWithPlaceholders, scid);

        // Step 7: Parse back the entry with real SCID values
        // versionId is now "1-{actualSCID}" — for genesis, the entry hash IS the SCID
        var finalEntry = LogEntrySerializer.DeserializeEntry(entryJsonWithScid);

        // Step 8: Sign with Data Integrity Proof
        var proofJson = LogEntrySerializer.SerializeWithoutProof(finalEntry);
        var proof = await _proofEngine.CreateProofAsync(
            proofJson, createOptions.UpdateKey, "assertionMethod",
            finalEntry.VersionTime, ct);

        finalEntry.Proof =
        [
            new DataIntegrityProofValue
            {
                Type = proof.Type,
                Cryptosuite = proof.Cryptosuite,
                VerificationMethod = proof.VerificationMethod,
                Created = proof.Created.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"),
                ProofPurpose = proof.ProofPurpose,
                ProofValue = proof.ProofValue
            }
        ];

        // Build the final DID string
        var did = didTemplate.Replace(ScidGenerator.SafePlaceholder, scid);
        var didValue = new Did(did);

        // Generate artifacts
        var logContent = LogEntrySerializer.ToJsonLines([finalEntry]);
        var didJsonContent = DidWebCompatibility.GenerateDidJson(did, finalEntry.State);

        var artifacts = new Dictionary<string, object>
        {
            ["did.jsonl"] = logContent,
            ["did.json"] = didJsonContent
        };

        if (createOptions.WitnessProofs is { Count: > 0 })
        {
            var merged = WitnessValidator.MergeWitnessProofs(null, createOptions.WitnessProofs);
            artifacts["did-witness.json"] = WitnessValidator.SerializeWitnessFile(merged);
        }

        return new DidCreateResult
        {
            Did = didValue,
            DidDocument = finalEntry.State,
            Metadata = new DidDocumentMetadata
            {
                Created = finalEntry.VersionTime,
                VersionId = finalEntry.VersionId,
                VersionTime = finalEntry.VersionTime
            },
            Artifacts = artifacts
        };
    }

    protected override async Task<DidResolutionResult> ResolveCoreAsync(
        string did, DidResolutionOptions? options, CancellationToken ct)
    {
        try
        {
            // Map DID to URL
            var logUrl = DidUrlMapper.MapToLogUrl(did);
            _logger.LogDebug("Resolving {Did} from {Url}", did, logUrl);

            // Fetch the log
            var logContent = await _httpClient.FetchDidLogAsync(logUrl, ct);
            if (logContent is null || logContent.Length == 0)
                return DidResolutionResult.NotFound(did);

            // Parse entries
            var entries = LogEntrySerializer.ParseJsonLines(logContent);
            if (entries.Count == 0)
                return DidResolutionResult.NotFound(did);

            // Determine the target entry index before validation
            // This allows versioned queries to succeed even if later entries are invalid
            var targetIndex = FindTargetIndex(entries, options);
            if (targetIndex < 0)
                return DidResolutionResult.NotFound(did);

            // Validate the chain up to the target version
            var perEntryParams = _chainValidator.ValidateChainWithPerEntryParams(entries, targetIndex + 1);
            var effectiveParams = perEntryParams[^1];

            var targetEntry = entries[targetIndex];

            // Verify the resolved document's id matches the requested DID
            if (targetEntry.State.Id.Value != did)
            {
                return new DidResolutionResult
                {
                    DidDocument = null,
                    ResolutionMetadata = new DidResolutionMetadata
                    {
                        Error = "invalidDidLog"
                    }
                };
            }

            // Validate witnesses for ALL entries that require it
            bool anyEntryRequiresWitness = perEntryParams.Any(p => p.Witness is { Threshold: > 0 });
            if (anyEntryRequiresWitness)
            {
                var witnessUrl = DidUrlMapper.MapToWitnessUrl(did);
                var witnessContent = await _httpClient.FetchWitnessFileAsync(witnessUrl, ct);

                // Missing witness file is a validation failure when witnessing is required
                if (witnessContent is null)
                {
                    return new DidResolutionResult
                    {
                        DidDocument = null,
                        ResolutionMetadata = new DidResolutionMetadata
                        {
                            Error = "witnessValidationFailed"
                        }
                    };
                }

                var witnessFile = WitnessValidator.ParseWitnessFile(witnessContent);
                if (witnessFile is null)
                {
                    return new DidResolutionResult
                    {
                        DidDocument = null,
                        ResolutionMetadata = new DidResolutionMetadata
                        {
                            Error = "witnessValidationFailed"
                        }
                    };
                }

                if (!_witnessValidator.ValidateAllWitnesses(witnessFile, entries, targetIndex, perEntryParams.ToList()))
                {
                    return new DidResolutionResult
                    {
                        DidDocument = null,
                        ResolutionMetadata = new DidResolutionMetadata
                        {
                            Error = "witnessValidationFailed"
                        }
                    };
                }
            }

            // Check if deactivated
            var isDeactivated = effectiveParams.Deactivated == true;

            return new DidResolutionResult
            {
                DidDocument = targetEntry.State,
                ResolutionMetadata = new DidResolutionMetadata
                {
                    ContentType = DidContentTypes.JsonLd
                },
                DocumentMetadata = new DidDocumentMetadata
                {
                    Created = entries[0].VersionTime,
                    Updated = entries.Count > 1 ? entries[^1].VersionTime : null,
                    VersionId = targetEntry.VersionId,
                    VersionTime = targetEntry.VersionTime,
                    Deactivated = isDeactivated ? true : null
                }
            };
        }
        catch (Core.Exceptions.LogChainValidationException ex)
        {
            _logger.LogWarning(ex, "Chain validation failed for {Did}", did);
            return new DidResolutionResult
            {
                DidDocument = null,
                ResolutionMetadata = new DidResolutionMetadata
                {
                    Error = "invalidDidLog"
                }
            };
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Resolution failed for {Did}", did);
            return DidResolutionResult.NotFound(did);
        }
    }

    protected override async Task<DidUpdateResult> UpdateCoreAsync(
        string did, DidUpdateOptions options, CancellationToken ct)
    {
        if (options is not DidWebVhUpdateOptions updateOptions)
            throw new ArgumentException($"Options must be {nameof(DidWebVhUpdateOptions)}.", nameof(options));

        if (updateOptions.SigningKey.KeyType != KeyType.Ed25519)
            throw new ArgumentException("did:webvh requires an Ed25519 signing key.");

        // Parse and validate existing log
        var entries = LogEntrySerializer.ParseJsonLines(updateOptions.CurrentLogContent);
        var effectiveParams = _chainValidator.ValidateChain(entries);

        // Verify signing key is authorized
        var signerMultibase = updateOptions.SigningKey.MultibasePublicKey;
        if (effectiveParams.UpdateKeys?.Contains(signerMultibase) != true)
            throw new ArgumentException("SigningKey is not an authorized update key.");

        // If pre-rotation is active, new updateKeys MUST be provided
        if (effectiveParams.Prerotation == true && effectiveParams.NextKeyHashes is { Count: > 0 })
        {
            if (updateOptions.ParameterUpdates?.UpdateKeys is not { Count: > 0 })
                throw new ArgumentException(
                    "Pre-rotation is active — updateKeys must be provided to rotate keys.");

            foreach (var newKey in updateOptions.ParameterUpdates.UpdateKeys)
            {
                PreRotationManager.ValidateKeyRotation(
                    newKey, effectiveParams.NextKeyHashes, entries.Count + 1);
            }
        }

        var previousEntry = entries[^1];

        // Build updated document
        var newDocument = updateOptions.NewDocument ?? previousEntry.State;

        // Build updated parameters (only include changed fields)
        var newParams = BuildUpdateParameters(updateOptions.ParameterUpdates);

        // Build new entry — hash includes previous versionId per spec
        var versionNumber = entries.Count + 1;
        var newEntry = new LogEntry
        {
            VersionId = $"{versionNumber}-{previousEntry.VersionId}",
            VersionTime = DateTimeOffset.UtcNow,
            Parameters = newParams,
            State = newDocument
        };

        // Compute entry hash from the entry with previous versionId
        var entryJsonWithoutProof = LogEntrySerializer.SerializeWithoutProof(newEntry);
        var entryHash = ScidGenerator.ComputeEntryHash(entryJsonWithoutProof);
        newEntry.VersionId = $"{versionNumber}-{entryHash}";

        // Re-serialize with correct versionId
        entryJsonWithoutProof = LogEntrySerializer.SerializeWithoutProof(newEntry);

        // Sign with Data Integrity Proof
        var proof = await _proofEngine.CreateProofAsync(
            entryJsonWithoutProof, updateOptions.SigningKey, "assertionMethod",
            newEntry.VersionTime, ct);

        newEntry.Proof =
        [
            new DataIntegrityProofValue
            {
                Type = proof.Type,
                Cryptosuite = proof.Cryptosuite,
                VerificationMethod = proof.VerificationMethod,
                Created = proof.Created.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"),
                ProofPurpose = proof.ProofPurpose,
                ProofValue = proof.ProofValue
            }
        ];

        // Build updated log
        var allEntries = new List<LogEntry>(entries) { newEntry };
        var logContent = LogEntrySerializer.ToJsonLines(allEntries);

        var updateArtifacts = new Dictionary<string, object>
        {
            ["did.jsonl"] = logContent,
            ["did.json"] = DidWebCompatibility.GenerateDidJson(did, newDocument)
        };

        if (updateOptions.WitnessProofs is { Count: > 0 })
        {
            WitnessFile? existing = null;
            if (updateOptions.CurrentWitnessContent is not null)
                existing = WitnessValidator.ParseWitnessFile(updateOptions.CurrentWitnessContent);
            var merged = WitnessValidator.MergeWitnessProofs(existing, updateOptions.WitnessProofs);
            updateArtifacts["did-witness.json"] = WitnessValidator.SerializeWitnessFile(merged);
        }

        return new DidUpdateResult
        {
            DidDocument = newDocument,
            Artifacts = updateArtifacts
        };
    }

    protected override async Task<DidDeactivateResult> DeactivateCoreAsync(
        string did, DidDeactivateOptions options, CancellationToken ct)
    {
        if (options is not DidWebVhDeactivateOptions deactivateOptions)
            throw new ArgumentException($"Options must be {nameof(DidWebVhDeactivateOptions)}.", nameof(options));

        if (deactivateOptions.SigningKey.KeyType != KeyType.Ed25519)
            throw new ArgumentException("did:webvh requires an Ed25519 signing key.");

        // Parse and validate existing log
        var entries = LogEntrySerializer.ParseJsonLines(deactivateOptions.CurrentLogContent);
        var effectiveParams = _chainValidator.ValidateChain(entries);

        // Verify signing key is authorized
        var signerMultibase = deactivateOptions.SigningKey.MultibasePublicKey;
        if (effectiveParams.UpdateKeys?.Contains(signerMultibase) != true)
            throw new ArgumentException("SigningKey is not an authorized update key.");

        var previousEntry = entries[^1];

        // Build deactivation entry with minimal document
        var versionNumber = entries.Count + 1;
        var minimalDoc = new DidDocument { Id = new Did(did) };

        var deactivationParams = new LogEntryParameters
        {
            Deactivated = true
        };

        var deactivationEntry = new LogEntry
        {
            VersionId = $"{versionNumber}-{previousEntry.VersionId}",
            VersionTime = DateTimeOffset.UtcNow,
            Parameters = deactivationParams,
            State = minimalDoc
        };

        // Compute entry hash
        var entryJsonWithoutProof = LogEntrySerializer.SerializeWithoutProof(deactivationEntry);
        var entryHash = ScidGenerator.ComputeEntryHash(entryJsonWithoutProof);
        deactivationEntry.VersionId = $"{versionNumber}-{entryHash}";

        // Re-serialize with correct versionId
        entryJsonWithoutProof = LogEntrySerializer.SerializeWithoutProof(deactivationEntry);

        // Sign with Data Integrity Proof
        var proof = await _proofEngine.CreateProofAsync(
            entryJsonWithoutProof, deactivateOptions.SigningKey, "assertionMethod",
            deactivationEntry.VersionTime, ct);

        deactivationEntry.Proof =
        [
            new DataIntegrityProofValue
            {
                Type = proof.Type,
                Cryptosuite = proof.Cryptosuite,
                VerificationMethod = proof.VerificationMethod,
                Created = proof.Created.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"),
                ProofPurpose = proof.ProofPurpose,
                ProofValue = proof.ProofValue
            }
        ];

        // Build updated log
        var allEntries = new List<LogEntry>(entries) { deactivationEntry };
        var logContent = LogEntrySerializer.ToJsonLines(allEntries);

        var deactivateArtifacts = new Dictionary<string, object>
        {
            ["did.jsonl"] = logContent
        };

        if (deactivateOptions.WitnessProofs is { Count: > 0 })
        {
            WitnessFile? existing = null;
            if (deactivateOptions.CurrentWitnessContent is not null)
                existing = WitnessValidator.ParseWitnessFile(deactivateOptions.CurrentWitnessContent);
            var merged = WitnessValidator.MergeWitnessProofs(existing, deactivateOptions.WitnessProofs);
            deactivateArtifacts["did-witness.json"] = WitnessValidator.SerializeWitnessFile(merged);
        }

        return new DidDeactivateResult
        {
            Success = true,
            Artifacts = deactivateArtifacts
        };
    }

    // --- Private helpers ---

    private static string BuildDidTemplate(string domain, string? path, string placeholder)
    {
        if (path is not null)
            return $"did:webvh:{placeholder}:{domain}:{path.Replace("/", ":")}";
        return $"did:webvh:{placeholder}:{domain}";
    }

    private static DidDocument BuildDocumentTemplate(string didTemplate, DidWebVhCreateOptions options)
    {
        var didValue = new Did(didTemplate);
        var updateKeyMultibase = options.UpdateKey.MultibasePublicKey;
        var vmId = $"{didTemplate}#{updateKeyMultibase}";

        var verificationMethods = new List<VerificationMethod>
        {
            new()
            {
                Id = vmId,
                Type = "Multikey",
                Controller = didValue,
                PublicKeyMultibase = updateKeyMultibase
            }
        };

        if (options.AdditionalVerificationMethods is not null)
            verificationMethods.AddRange(options.AdditionalVerificationMethods);

        var authentication = new List<VerificationRelationshipEntry>
        {
            VerificationRelationshipEntry.FromReference(vmId)
        };
        var assertionMethod = new List<VerificationRelationshipEntry>
        {
            VerificationRelationshipEntry.FromReference(vmId)
        };
        var capabilityInvocation = new List<VerificationRelationshipEntry>
        {
            VerificationRelationshipEntry.FromReference(vmId)
        };
        var capabilityDelegation = new List<VerificationRelationshipEntry>
        {
            VerificationRelationshipEntry.FromReference(vmId)
        };

        // Build alsoKnownAs with did:web equivalent
        var didWebEquivalent = $"did:web:{options.Domain}";
        if (options.Path is not null)
            didWebEquivalent += $":{options.Path.Replace("/", ":")}";

        return new DidDocument
        {
            Id = didValue,
            AlsoKnownAs = [didWebEquivalent],
            VerificationMethod = verificationMethods,
            Authentication = authentication,
            AssertionMethod = assertionMethod,
            CapabilityInvocation = capabilityInvocation,
            CapabilityDelegation = capabilityDelegation,
            Service = options.Services?.ToList()
        };
    }

    private static LogEntryParameters BuildGenesisParameters(DidWebVhCreateOptions options,
        string scidPlaceholder)
    {
        WitnessConfig? witness = null;
        if (options.WitnessDids is { Count: > 0 })
        {
            witness = new WitnessConfig
            {
                Threshold = options.WitnessThreshold,
                Witnesses = options.WitnessDids.Select(id => new WitnessEntry
                {
                    Id = id,
                    Weight = 1
                }).ToList()
            };
        }

        return new LogEntryParameters
        {
            Method = MethodVersion,
            Scid = scidPlaceholder,
            UpdateKeys = [options.UpdateKey.MultibasePublicKey],
            Prerotation = options.EnablePreRotation ? true : null,
            NextKeyHashes = options.PreRotationCommitments,
            Deactivated = false,
            Witness = witness
        };
    }

    private static LogEntryParameters BuildUpdateParameters(DidWebVhParameterUpdates? updates)
    {
        if (updates is null)
            return new LogEntryParameters();

        return new LogEntryParameters
        {
            UpdateKeys = updates.UpdateKeys,
            Prerotation = updates.Prerotation,
            NextKeyHashes = updates.NextKeyHashes,
            Witness = updates.Witness,
            Ttl = updates.Ttl
        };
    }

    /// <summary>
    /// Find the target entry index based on resolution options.
    /// Returns -1 if a specific version was requested but not found.
    /// </summary>
    private static int FindTargetIndex(
        IReadOnlyList<LogEntry> entries, DidResolutionOptions? options)
    {
        if (options is null)
            return entries.Count - 1; // Latest entry

        // VersionId filtering
        if (options.VersionId is not null)
        {
            for (int i = 0; i < entries.Count; i++)
            {
                if (entries[i].VersionId == options.VersionId)
                    return i;
            }
            return -1; // Requested version not found
        }

        // VersionTime filtering — find latest entry at or before the specified time
        if (options.VersionTime is not null && DateTimeOffset.TryParse(options.VersionTime, out var versionTime))
        {
            int bestIndex = -1;
            for (int i = 0; i < entries.Count; i++)
            {
                if (entries[i].VersionTime <= versionTime)
                    bestIndex = i;
            }
            return bestIndex; // -1 if no entry found before the specified time
        }

        return entries.Count - 1; // Default to latest
    }
}
