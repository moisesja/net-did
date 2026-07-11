using System.Globalization;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using DataProofsDotnet.DataIntegrity;
using NetDid.Core;
using NetCrypto;
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
    private readonly EddsaJcs2022Cryptosuite _suite;
    private readonly LogChainValidator _chainValidator;
    private readonly WitnessValidator _witnessValidator;
    private readonly ILogger<DidWebVhMethod> _logger;

    internal const string MethodVersion = "did:webvh:1.0";

    public DidWebVhMethod(IWebVhHttpClient httpClient, ILogger<DidWebVhMethod>? logger = null)
    {
        _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        _suite = new EddsaJcs2022Cryptosuite();
        _chainValidator = new LogChainValidator(_suite);
        _witnessValidator = new WitnessValidator(_suite);
        _logger = logger ?? NullLogger<DidWebVhMethod>.Instance;
    }

    /// <summary>
    /// Signs the log entry (serialized without its <c>proof</c>) with the conformant
    /// <c>eddsa-jcs-2022</c> cryptosuite from DataProofsDotnet and returns the wire proof.
    /// The verificationMethod is the signer's own <c>did:key</c> (DID==fragment); the
    /// <c>created</c> timestamp is a verbatim string carried through to the wire so the hashed
    /// proof configuration is byte-identical on verification.
    /// </summary>
    private async Task<DataIntegrityProofValue> CreateProofValueAsync(
        string entryJsonWithoutProof, ISigner signer, DateTimeOffset versionTime, CancellationToken ct)
    {
        var verificationMethod = $"did:key:{signer.MultibasePublicKey}#{signer.MultibasePublicKey}";
        var created = WebVhTimestamp.Format(versionTime);

        var proofOptions = new DataIntegrityProof
        {
            Cryptosuite = EddsaJcs2022Cryptosuite.CryptosuiteName,
            VerificationMethod = verificationMethod,
            Created = created,
            ProofPurpose = "assertionMethod",
        };

        using var document = JsonDocument.Parse(entryJsonWithoutProof);
        var proof = await _suite.CreateProofAsync(document.RootElement, proofOptions, signer, ct);

        // Echo the proof config the suite actually signed (it returns the options with the
        // proofValue filled in) so the wire DTO can't drift from the signed bytes.
        return new DataIntegrityProofValue
        {
            Type = proof.Type,
            Cryptosuite = proof.Cryptosuite!,
            VerificationMethod = proof.VerificationMethod!,
            Created = proof.Created!,
            ProofPurpose = proof.ProofPurpose!,
            ProofValue = proof.ProofValue!,
        };
    }

    public override string MethodName => "webvh";

    public override DidMethodCapabilities Capabilities =>
        DidMethodCapabilities.Create |
        DidMethodCapabilities.Resolve |
        DidMethodCapabilities.Update |
        DidMethodCapabilities.Deactivate |
        DidMethodCapabilities.ServiceEndpoints |
        DidMethodCapabilities.History;

    /// <summary>
    /// did:webvh requires an Ed25519 update key (see <see cref="DidWebVhCreateOptions.UpdateKey"/>).
    /// Other key types may appear in the DID Document as additional verification methods,
    /// but only Ed25519 is accepted as the controlling update key.
    /// </summary>
    public override IReadOnlyList<KeyType> SupportedKeyTypes { get; } = [KeyType.Ed25519];

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

        // Validate that the resulting template maps to a safe HTTPS URL. This rejects
        // unsafe domain/path inputs (userinfo, separators, traversal segments, invalid
        // ports) at create time, before any artifacts are produced. Reuses the same
        // validators that resolution applies — see DidUrlMapper.
        _ = DidUrlMapper.MapToLogUrl(didTemplate);

        // Step 2: Build the DID Document with safe placeholder
        var docTemplate = BuildDocumentTemplate(didTemplate, createOptions);

        // Step 3: Build the genesis log entry with safe placeholder
        var genesisParams = BuildGenesisParameters(createOptions, ScidGenerator.SafePlaceholder);
        RequireValidWitnessPolicy(genesisParams.Witness, nameof(options));
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
        var proofValue = await CreateProofValueAsync(
            proofJson, createOptions.UpdateKey, finalEntry.VersionTime, ct);

        finalEntry = finalEntry with { Proof = [proofValue] };

        // Build the final DID string
        var did = didTemplate.Replace(ScidGenerator.SafePlaceholder, scid);
        var didValue = new Did(did);

        // Generate artifacts (as UTF-8 strings for consumer convenience)
        var logContent = Encoding.UTF8.GetString(LogEntrySerializer.ToJsonLines([finalEntry]));
        var didJsonContent = Encoding.UTF8.GetString(DidWebCompatibility.GenerateDidJson(did, finalEntry.State));

        var artifacts = new Dictionary<string, object>
        {
            [DidWebVhArtifacts.DidJsonl] = logContent,
            [DidWebVhArtifacts.DidJson] = didJsonContent
        };

        if (createOptions.WitnessProofs is { Count: > 0 })
        {
            var merged = WitnessValidator.MergeWitnessProofs(null, createOptions.WitnessProofs);
            artifacts[DidWebVhArtifacts.DidWitnessJson] = Encoding.UTF8.GetString(WitnessValidator.SerializeWitnessFile(merged));
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

            // Parse entries. A syntactically valid fetched log with a spec-invalid
            // timestamp is an invalid DID log, not evidence that the DID was absent.
            IReadOnlyList<LogEntry> entries;
            try
            {
                entries = LogEntrySerializer.ParseJsonLines(logContent);
            }
            catch (FormatException ex)
            {
                _logger.LogWarning(ex, "DID log contains an invalid versionTime for {Did}", did);
                return new DidResolutionResult
                {
                    DidDocument = null,
                    ResolutionMetadata = new DidResolutionMetadata
                    {
                        Error = "invalidDidLog"
                    }
                };
            }

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

            // Bind the DID's self-certifying SCID to the genesis entry. State.Id above is an
            // attacker-controllable document field; the SCID in the DID string is the hash of
            // the genesis and is did:webvh's actual root of trust. entries[0].Parameters.Scid
            // has already been proven equal to the recomputed genesis hash by chain validation,
            // so this comparison rejects a self-consistent-but-unrelated genesis served for the
            // requested DID — the impersonation that defeats self-certification. See issue #82.
            if (DidUrlMapper.ExtractScid(did) != entries[0].Parameters.Scid)
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

            // Validate witnesses for every governed entry. Genesis and the first activation
            // use the policy they declare; after activation, the prior effective policy governs
            // the transition. In particular, an entry cannot disable or replace the requirement
            // that authorizes that entry itself.
            bool anyEntryRequiresWitness = WitnessValidator.RequiresWitness(
                perEntryParams, targetIndex);
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

            IReadOnlyDictionary<string, object>? artifacts = null;
            if (options?.IncludeLog == true)
            {
                artifacts = new Dictionary<string, object>
                {
                    [DidWebVhArtifacts.DidJsonl] = Encoding.UTF8.GetString(logContent),
                    [DidWebVhArtifacts.LogEntries] = entries
                };
            }

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
                    Updated = targetIndex > 0 ? targetEntry.VersionTime : null,
                    VersionId = targetEntry.VersionId,
                    VersionTime = targetEntry.VersionTime,
                    Deactivated = isDeactivated ? true : null
                },
                Artifacts = artifacts
            };
        }
        // Caller-initiated cancellation is not a resolution failure — propagate it. The
        // ct.IsCancellationRequested filter keeps an HttpClient.Timeout-driven
        // TaskCanceledException (caller token not cancelled) normalizing to notFound below.
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
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

        // Bind the supplied log and new document to the target DID. Without these checks the
        // driver could emit a log the resolver rejects on identity grounds (resolution enforces
        // State.Id == did and the genesis-SCID binding — see ResolveCoreAsync above), or authorize
        // an update of A entirely with B's log/key. See issue #82. (Other resolution checks, e.g.
        // witness thresholds, are orthogonal — a witness-policy update still needs matching proofs
        // published for the resulting log to resolve.)
        RequireAppendableLogForDid(entries, effectiveParams, did);
        if (updateOptions.NewDocument is not null && updateOptions.NewDocument.Id.Value != did)
            throw new ArgumentException(
                $"NewDocument.Id must equal the DID being updated ('{did}').", nameof(options));

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
        RequireValidWitnessPolicy(newParams.Witness, nameof(options));

        // Determine whether this update touched the method's authorization material, by
        // comparing the effective parameters before and after the merge. Surfaced on the
        // result so a method-agnostic caller can enforce a document-only postcondition — the
        // authority (updateKeys etc.) never appears in the DID Document. This driver always
        // evaluates it, so it reports Changed or Unchanged (never Unknown). See issue #82.
        var newEffectiveParams = newParams.MergeWith(effectiveParams);
        // Key-specific evidence for rotation consumers (issue #91): whether the effective
        // updateKeys set itself changed — a witness/prerotation-only change must not read as
        // a rotation. Computed once and folded into the coarse status so that
        // UpdateKeyChange == Changed structurally implies AuthorizationChange == Changed.
        var updateKeysUnchanged = StringSetEquals(effectiveParams.UpdateKeys, newEffectiveParams.UpdateKeys);
        var updateKeyChange = updateKeysUnchanged
            ? AuthorizationChangeStatus.Unchanged
            : AuthorizationChangeStatus.Changed;
        var authorizationChange = !updateKeysUnchanged || HasAuthorizationChange(effectiveParams, newEffectiveParams)
            ? AuthorizationChangeStatus.Changed
            : AuthorizationChangeStatus.Unchanged;

        // Build new entry — hash includes previous versionId per spec
        var versionNumber = entries.Count + 1;
        var versionNumberText = versionNumber.ToString(CultureInfo.InvariantCulture);
        var newEntry = new LogEntry
        {
            VersionId = $"{versionNumberText}-{previousEntry.VersionId}",
            VersionTime = GetNextVersionTime(previousEntry.VersionTime),
            Parameters = newParams,
            State = newDocument
        };

        // Compute entry hash from the entry with previous versionId
        var entryJsonWithoutProof = LogEntrySerializer.SerializeWithoutProof(newEntry);
        var entryHash = ScidGenerator.ComputeEntryHash(entryJsonWithoutProof);
        newEntry = newEntry with { VersionId = $"{versionNumberText}-{entryHash}" };

        // Re-serialize with correct versionId
        entryJsonWithoutProof = LogEntrySerializer.SerializeWithoutProof(newEntry);

        // Sign with Data Integrity Proof
        var proofValue = await CreateProofValueAsync(
            entryJsonWithoutProof, updateOptions.SigningKey, newEntry.VersionTime, ct);

        newEntry = newEntry with { Proof = [proofValue] };

        // Build updated log (as UTF-8 strings for consumer convenience)
        var allEntries = new List<LogEntry>(entries) { newEntry };
        var logContent = Encoding.UTF8.GetString(LogEntrySerializer.ToJsonLines(allEntries));

        var updateArtifacts = new Dictionary<string, object>
        {
            [DidWebVhArtifacts.DidJsonl] = logContent,
            [DidWebVhArtifacts.DidJson] = Encoding.UTF8.GetString(DidWebCompatibility.GenerateDidJson(did, newDocument))
        };

        if (updateOptions.WitnessProofs is { Count: > 0 })
        {
            WitnessFile? existing = null;
            if (updateOptions.CurrentWitnessContent is not null)
                existing = WitnessValidator.ParseWitnessFile(updateOptions.CurrentWitnessContent);
            var merged = WitnessValidator.MergeWitnessProofs(existing, updateOptions.WitnessProofs);
            updateArtifacts[DidWebVhArtifacts.DidWitnessJson] = Encoding.UTF8.GetString(WitnessValidator.SerializeWitnessFile(merged));
        }

        return new DidUpdateResult
        {
            DidDocument = newDocument,
            Artifacts = updateArtifacts,
            AuthorizationChange = authorizationChange,
            UpdateKeyChange = updateKeyChange,
            // Read-only copy: the merged list may alias the caller's ParameterUpdates.UpdateKeys,
            // and the reported evidence must not drift if the caller mutates it after return (nor
            // be mutable via a downcast by a downstream consumer).
            EffectiveUpdateKeys = newEffectiveParams.UpdateKeys is { } keys ? Array.AsReadOnly(keys.ToArray()) : null
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

        // Bind the supplied log to the target DID (see issue #82 and UpdateCoreAsync).
        RequireAppendableLogForDid(entries, effectiveParams, did);

        // Verify signing key is authorized
        var signerMultibase = deactivateOptions.SigningKey.MultibasePublicKey;
        if (effectiveParams.UpdateKeys?.Contains(signerMultibase) != true)
            throw new ArgumentException("SigningKey is not an authorized update key.");

        var previousEntry = entries[^1];

        // Build deactivation entry with minimal document
        var versionNumber = entries.Count + 1;
        var versionNumberText = versionNumber.ToString(CultureInfo.InvariantCulture);
        var minimalDoc = new DidDocument { Id = new Did(did) };

        var deactivationParams = new LogEntryParameters
        {
            Deactivated = true
        };

        var deactivationEntry = new LogEntry
        {
            VersionId = $"{versionNumberText}-{previousEntry.VersionId}",
            VersionTime = GetNextVersionTime(previousEntry.VersionTime),
            Parameters = deactivationParams,
            State = minimalDoc
        };

        // Compute entry hash
        var entryJsonWithoutProof = LogEntrySerializer.SerializeWithoutProof(deactivationEntry);
        var entryHash = ScidGenerator.ComputeEntryHash(entryJsonWithoutProof);
        deactivationEntry = deactivationEntry with { VersionId = $"{versionNumberText}-{entryHash}" };

        // Re-serialize with correct versionId
        entryJsonWithoutProof = LogEntrySerializer.SerializeWithoutProof(deactivationEntry);

        // Sign with Data Integrity Proof
        var proofValue = await CreateProofValueAsync(
            entryJsonWithoutProof, deactivateOptions.SigningKey, deactivationEntry.VersionTime, ct);

        deactivationEntry = deactivationEntry with { Proof = [proofValue] };

        // Build updated log (as UTF-8 strings for consumer convenience)
        var allEntries = new List<LogEntry>(entries) { deactivationEntry };
        var logContent = Encoding.UTF8.GetString(LogEntrySerializer.ToJsonLines(allEntries));

        var deactivateArtifacts = new Dictionary<string, object>
        {
            [DidWebVhArtifacts.DidJsonl] = logContent
        };

        if (deactivateOptions.WitnessProofs is { Count: > 0 })
        {
            WitnessFile? existing = null;
            if (deactivateOptions.CurrentWitnessContent is not null)
                existing = WitnessValidator.ParseWitnessFile(deactivateOptions.CurrentWitnessContent);
            var merged = WitnessValidator.MergeWitnessProofs(existing, deactivateOptions.WitnessProofs);
            deactivateArtifacts[DidWebVhArtifacts.DidWitnessJson] = Encoding.UTF8.GetString(WitnessValidator.SerializeWitnessFile(merged));
        }

        return new DidDeactivateResult
        {
            Success = true,
            Artifacts = deactivateArtifacts
        };
    }

    // --- Private helpers ---

    private static DateTimeOffset GetNextVersionTime(DateTimeOffset previous)
    {
        var now = DateTimeOffset.UtcNow;
        if (now > previous)
            return now;

        if (previous.UtcTicks == DateTimeOffset.MaxValue.UtcTicks)
            throw new ArgumentException(
                "The supplied DID log's latest versionTime cannot be advanced.");

        return previous.AddTicks(1);
    }

    private static void RequireValidWitnessPolicy(WitnessConfig? config, string parameterName)
    {
        var error = WitnessPolicyValidator.GetValidationError(config);
        if (error is not null)
            throw new ArgumentException(error, parameterName);
    }

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
        if (options.WitnessDids is { Count: > 0 } || options.WitnessThreshold != 0)
        {
            witness = new WitnessConfig
            {
                Threshold = options.WitnessThreshold,
                Witnesses = options.WitnessDids?.Select(id => new WitnessEntry
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
    /// Precondition for appending to a supplied log: it must not already be deactivated, its latest
    /// entry's document must be the DID we were asked to operate on, and its genesis SCID must match
    /// the SCID in that DID. Mirrors the identity invariants resolution enforces (<c>State.Id == did</c>,
    /// the genesis-SCID binding, and "cannot append after deactivation"), so the driver cannot emit a
    /// log that its own resolver rejects <b>on DID/SCID identity grounds</b>. (Other resolution checks,
    /// such as witness thresholds, are orthogonal and can still fail — see <see cref="UpdateCoreAsync"/>.)
    /// See issue #82.
    /// </summary>
    private static void RequireAppendableLogForDid(
        IReadOnlyList<LogEntry> entries, LogEntryParameters effectiveParams, string did)
    {
        if (effectiveParams.Deactivated == true)
            throw new ArgumentException(
                "The supplied DID log is already deactivated and cannot be updated.");

        // entries is non-empty here: ValidateChain has already run and throws on an empty log.
        if (entries[^1].State.Id.Value != did)
            throw new ArgumentException(
                $"The supplied CurrentLogContent does not belong to the DID being operated on ('{did}').");

        // Bind the DID's self-certifying SCID to the supplied log's genesis. State.Id above is
        // an attacker-settable document field, whereas the SCID pins the genesis authority. This
        // stops an update/deactivation of the target DID from being authorized by an unrelated
        // (attacker-owned) log whose latest entry merely claims the target's id. Mirrors the
        // resolution-side binding, so the writer cannot emit a log the resolver rejects on
        // DID/SCID identity grounds. #82.
        if (DidUrlMapper.ExtractScid(did) != entries[0].Parameters.Scid)
            throw new ArgumentException(
                $"The supplied CurrentLogContent's genesis SCID does not match the DID being operated on ('{did}').");
    }

    /// <summary>
    /// True when the effective authorization material differs between two parameter sets —
    /// <c>updateKeys</c>, <c>prerotation</c>, <c>nextKeyHashes</c>, or <c>witness</c> config.
    /// <c>ttl</c> is deliberately excluded (it is a caching hint, not authority). Drives
    /// <see cref="DidUpdateResult.AuthorizationChange"/>.
    /// </summary>
    private static bool HasAuthorizationChange(LogEntryParameters before, LogEntryParameters after)
    {
        if (!StringSetEquals(before.UpdateKeys, after.UpdateKeys))
            return true;
        if ((before.Prerotation ?? false) != (after.Prerotation ?? false))
            return true;
        if (!StringSetEquals(before.NextKeyHashes, after.NextKeyHashes))
            return true;
        if (!WitnessConfigEquals(before.Witness, after.Witness))
            return true;
        return false;
    }

    /// <summary>Order-insensitive, ordinal set equality; a null list is treated as empty.</summary>
    private static bool StringSetEquals(IReadOnlyList<string>? a, IReadOnlyList<string>? b)
    {
        var setA = a is null ? new HashSet<string>(StringComparer.Ordinal) : new HashSet<string>(a, StringComparer.Ordinal);
        var setB = b is null ? new HashSet<string>(StringComparer.Ordinal) : new HashSet<string>(b, StringComparer.Ordinal);
        return setA.SetEquals(setB);
    }

    /// <summary>
    /// Value equality for witness configuration under did:webvh 1.0: same threshold and same set
    /// of witness ids. Ordering and legacy weight values are semantically inert. Null and the empty
    /// disabling configuration are equivalent.
    /// </summary>
    private static bool WitnessConfigEquals(WitnessConfig? a, WitnessConfig? b)
    {
        if (ReferenceEquals(a, b))
            return true;
        if ((a?.Threshold ?? 0) != (b?.Threshold ?? 0))
            return false;

        var idsA = (a?.Witnesses ?? [])
            .Select(entry => entry.Id.Normalize(NormalizationForm.FormC))
            .ToHashSet(StringComparer.Ordinal);
        var idsB = (b?.Witnesses ?? [])
            .Select(entry => entry.Id.Normalize(NormalizationForm.FormC))
            .ToHashSet(StringComparer.Ordinal);
        return idsA.SetEquals(idsB);
    }

    /// <summary>
    /// Find the target entry index based on resolution options.
    /// Returns -1 if a specific version was requested but not found.
    /// </summary>
    internal static int FindTargetIndex(
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

        // VersionTime filtering — find latest entry at or before the specified time. A caller
        // that supplies an invalid timestamp requested a constrained resolution; never weaken
        // that request by silently falling back to the latest entry.
        if (options.VersionTime is not null)
        {
            if (!WebVhTimestamp.TryParse(options.VersionTime, out var versionTime))
                return -1;

            int bestIndex = -1;
            for (int i = 0; i < entries.Count; i++)
            {
                if (entries[i].VersionTime <= versionTime)
                    bestIndex = i;
                else
                    break;
            }
            return bestIndex; // -1 if no entry found before the specified time
        }

        return entries.Count - 1; // Default to latest
    }
}
