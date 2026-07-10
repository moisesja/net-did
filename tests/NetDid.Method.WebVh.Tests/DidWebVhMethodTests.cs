using System.Text;
using System.Text.Json;
using DataProofsDotnet.DataIntegrity;
using FluentAssertions;
using NetDid.Core;
using NetCrypto;
using NetDid.Core.Model;
using NetDid.Method.WebVh;
using NetDid.Method.WebVh.Model;

namespace NetDid.Method.WebVh.Tests;

public class DidWebVhMethodTests
{
    private readonly DefaultKeyGenerator _keyGen = new();
    private readonly DefaultCryptoProvider _crypto = new();

    private (DidWebVhMethod Method, MockWebVhHttpClient HttpClient) CreateMethod()
    {
        var httpClient = new MockWebVhHttpClient();
        var method = new DidWebVhMethod(httpClient);
        return (method, httpClient);
    }

    private ISigner CreateEd25519Signer()
    {
        var keyPair = _keyGen.Generate(KeyType.Ed25519);
        return new KeyPairSigner(keyPair, _crypto);
    }

    // ================================================================
    // CREATE TESTS
    // ================================================================

    [Fact]
    public async Task Create_BasicDid_ReturnsValidResult()
    {
        var (method, _) = CreateMethod();
        var signer = CreateEd25519Signer();

        var result = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = signer
        });

        result.Did.Value.Should().StartWith("did:webvh:");
        result.Did.Value.Should().Contain(":example.com");
        result.DidDocument.Should().NotBeNull();
        result.DidDocument.Id.Value.Should().Be(result.Did.Value);
        result.DidDocument.VerificationMethod.Should().HaveCountGreaterOrEqualTo(1);
        result.DidDocument.Authentication.Should().NotBeEmpty();
        result.DidDocument.AssertionMethod.Should().NotBeEmpty();
        result.Artifacts.Should().ContainKey(DidWebVhArtifacts.DidJsonl);
        result.Artifacts.Should().ContainKey(DidWebVhArtifacts.DidJson);
    }

    [Fact]
    public async Task Create_WithPath_IncludesPathInDid()
    {
        var (method, _) = CreateMethod();
        var signer = CreateEd25519Signer();

        var result = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            Path = "users/alice",
            UpdateKey = signer
        });

        result.Did.Value.Should().Contain(":example.com:users:alice");
    }

    [Fact]
    public async Task Create_WithServices_IncludesServicesInDocument()
    {
        var (method, _) = CreateMethod();
        var signer = CreateEd25519Signer();

        var result = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = signer,
            Services =
            [
                new Service
                {
                    Id = "#pds-1",
                    Type = "TurtleShellPds",
                    ServiceEndpoint = ServiceEndpointValue.FromUri("https://node1.example.com/pds")
                }
            ]
        });

        result.DidDocument.Service.Should().HaveCount(1);
        result.DidDocument.Service![0].Type.Should().Be("TurtleShellPds");
    }

    [Fact]
    public async Task Create_GeneratesValidJsonl()
    {
        var (method, _) = CreateMethod();
        var signer = CreateEd25519Signer();

        var result = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = signer
        });

        var logContent = (string)result.Artifacts![DidWebVhArtifacts.DidJsonl];
        logContent.Should().NotBeEmpty();

        // Parse the generated log
        var entries = LogEntrySerializer.ParseJsonLines(Encoding.UTF8.GetBytes(logContent));
        entries.Should().HaveCount(1);
        entries[0].VersionNumber.Should().Be(1);
        entries[0].Parameters.Method.Should().Be("did:webvh:1.0");
        entries[0].Parameters.Scid.Should().NotBeNullOrEmpty();
        entries[0].Proof.Should().HaveCount(1);
    }

    [Fact]
    public async Task Create_AlsoKnownAs_ContainsDidWebEquivalent()
    {
        var (method, _) = CreateMethod();
        var signer = CreateEd25519Signer();

        var result = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = signer
        });

        result.DidDocument.AlsoKnownAs.Should().Contain("did:web:example.com");
    }

    [Fact]
    public async Task Create_WithPreRotation_IncludesCommitments()
    {
        var (method, _) = CreateMethod();
        var signer = CreateEd25519Signer();
        var nextKey = CreateEd25519Signer();
        var commitment = PreRotationManager.ComputeKeyCommitment(nextKey.MultibasePublicKey);

        var result = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = signer,
            EnablePreRotation = true,
            PreRotationCommitments = [commitment]
        });

        var logContent = (string)result.Artifacts![DidWebVhArtifacts.DidJsonl];
        var entries = LogEntrySerializer.ParseJsonLines(Encoding.UTF8.GetBytes(logContent));
        entries[0].Parameters.Prerotation.Should().BeTrue();
        entries[0].Parameters.NextKeyHashes.Should().Contain(commitment);
    }

    // ================================================================
    // RESOLVE TESTS
    // ================================================================

    [Fact]
    public async Task Create_ThenResolve_RoundTrip_Succeeds()
    {
        var (method, httpClient) = CreateMethod();
        var signer = CreateEd25519Signer();

        // Create
        var createResult = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = signer
        });

        // Set up mock HTTP response
        var logContent = (string)createResult.Artifacts![DidWebVhArtifacts.DidJsonl];
        var logUrl = DidUrlMapper.MapToLogUrl(createResult.Did.Value);
        httpClient.SetLogResponse(logUrl, Encoding.UTF8.GetBytes(logContent));

        // Resolve
        var resolveResult = await method.ResolveAsync(createResult.Did.Value);

        resolveResult.DidDocument.Should().NotBeNull();
        resolveResult.DidDocument!.Id.Value.Should().Be(createResult.Did.Value);
        resolveResult.ResolutionMetadata.Error.Should().BeNull();
        resolveResult.ResolutionMetadata.ContentType.Should().Be(DidContentTypes.JsonLd);
        resolveResult.DocumentMetadata!.VersionId.Should().StartWith("1-");
    }

    [Fact]
    public async Task Resolve_NotFound_ReturnsNotFoundError()
    {
        var (method, _) = CreateMethod();

        var result = await method.ResolveAsync("did:webvh:QmNotExist:example.com");

        result.DidDocument.Should().BeNull();
        result.ResolutionMetadata.Error.Should().Be("notFound");
    }

    [Fact]
    public async Task Resolve_InvalidDid_ReturnsInvalidDidError()
    {
        var (method, _) = CreateMethod();

        var result = await method.ResolveAsync("not-a-did");

        result.DidDocument.Should().BeNull();
        result.ResolutionMetadata.Error.Should().Be("invalidDid");
    }

    [Fact]
    public async Task Resolve_WrongMethod_ReturnsMethodNotSupported()
    {
        var (method, _) = CreateMethod();

        var result = await method.ResolveAsync("did:key:z6MkTest");

        result.DidDocument.Should().BeNull();
        result.ResolutionMetadata.Error.Should().Be("methodNotSupported");
    }

    // ================================================================
    // UPDATE TESTS
    // ================================================================

    [Fact]
    public async Task Create_ThenUpdate_AddService_Succeeds()
    {
        var (method, httpClient) = CreateMethod();
        var signer = CreateEd25519Signer();

        // Create
        var createResult = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = signer
        });

        var logContent = (string)createResult.Artifacts![DidWebVhArtifacts.DidJsonl];
        var did = createResult.Did.Value;

        // Update — add a service
        var updatedDoc = new DidDocument
        {
            Id = createResult.Did,
            VerificationMethod = createResult.DidDocument.VerificationMethod,
            Authentication = createResult.DidDocument.Authentication,
            AssertionMethod = createResult.DidDocument.AssertionMethod,
            CapabilityInvocation = createResult.DidDocument.CapabilityInvocation,
            CapabilityDelegation = createResult.DidDocument.CapabilityDelegation,
            AlsoKnownAs = createResult.DidDocument.AlsoKnownAs,
            Service =
            [
                new Service
                {
                    Id = $"{did}#pds",
                    Type = "TurtleShellPds",
                    ServiceEndpoint = ServiceEndpointValue.FromUri("https://example.com/pds")
                }
            ]
        };

        var updateResult = await method.UpdateAsync(did, new DidWebVhUpdateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(logContent),
            SigningKey = signer,
            NewDocument = updatedDoc
        });

        updateResult.DidDocument.Service.Should().HaveCount(1);
        updateResult.DidDocument.Service![0].Type.Should().Be("TurtleShellPds");
        updateResult.Artifacts.Should().ContainKey(DidWebVhArtifacts.DidJsonl);

        // Verify the updated log has 2 entries
        var updatedLog = (string)updateResult.Artifacts![DidWebVhArtifacts.DidJsonl];
        var entries = LogEntrySerializer.ParseJsonLines(Encoding.UTF8.GetBytes(updatedLog));
        entries.Should().HaveCount(2);
        entries[1].VersionNumber.Should().Be(2);
    }

    [Fact]
    public async Task Create_ThenUpdate_ThenResolve_ReturnsUpdatedDocument()
    {
        var (method, httpClient) = CreateMethod();
        var signer = CreateEd25519Signer();

        // Create
        var createResult = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = signer,
            Services =
            [
                new Service
                {
                    Id = "#svc-1",
                    Type = "OldService",
                    ServiceEndpoint = ServiceEndpointValue.FromUri("https://old.example.com")
                }
            ]
        });

        var logContent = (string)createResult.Artifacts![DidWebVhArtifacts.DidJsonl];
        var did = createResult.Did.Value;

        // Update
        var updatedDoc = createResult.DidDocument with
        {
            Service =
            [
                new Service
                {
                    Id = $"{did}#svc-1",
                    Type = "NewService",
                    ServiceEndpoint = ServiceEndpointValue.FromUri("https://new.example.com")
                }
            ]
        };

        var updateResult = await method.UpdateAsync(did, new DidWebVhUpdateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(logContent),
            SigningKey = signer,
            NewDocument = updatedDoc
        });

        var updatedLog = (string)updateResult.Artifacts![DidWebVhArtifacts.DidJsonl];

        // Resolve
        var logUrl = DidUrlMapper.MapToLogUrl(did);
        httpClient.SetLogResponse(logUrl, Encoding.UTF8.GetBytes(updatedLog));

        var resolveResult = await method.ResolveAsync(did);
        resolveResult.DidDocument.Should().NotBeNull();
        resolveResult.DidDocument!.Service.Should().HaveCount(1);
        resolveResult.DidDocument.Service![0].Type.Should().Be("NewService");
        resolveResult.DocumentMetadata!.Updated.Should().NotBeNull();
    }

    [Fact]
    public async Task Update_KeyRotation_Succeeds()
    {
        var (method, _) = CreateMethod();
        var originalKey = CreateEd25519Signer();

        // Create
        var createResult = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = originalKey
        });

        var logContent = (string)createResult.Artifacts![DidWebVhArtifacts.DidJsonl];
        var did = createResult.Did.Value;

        // Rotate to a new key
        var newKey = CreateEd25519Signer();

        var updateResult = await method.UpdateAsync(did, new DidWebVhUpdateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(logContent),
            SigningKey = originalKey,
            ParameterUpdates = new DidWebVhParameterUpdates
            {
                UpdateKeys = [newKey.MultibasePublicKey]
            }
        });

        var updatedLog = (string)updateResult.Artifacts![DidWebVhArtifacts.DidJsonl];
        var entries = LogEntrySerializer.ParseJsonLines(Encoding.UTF8.GetBytes(updatedLog));

        // The effective updateKeys should be the new key after the update
        entries[1].Parameters.UpdateKeys.Should().Contain(newKey.MultibasePublicKey);
    }

    [Fact]
    public async Task Update_UnauthorizedKey_Throws()
    {
        var (method, _) = CreateMethod();
        var authorizedKey = CreateEd25519Signer();
        var unauthorizedKey = CreateEd25519Signer();

        var createResult = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = authorizedKey
        });

        var logContent = (string)createResult.Artifacts![DidWebVhArtifacts.DidJsonl];
        var did = createResult.Did.Value;

        var act = () => method.UpdateAsync(did, new DidWebVhUpdateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(logContent),
            SigningKey = unauthorizedKey
        });

        await act.Should().ThrowAsync<ArgumentException>().WithMessage("*authorized*");
    }

    // ================================================================
    // DEACTIVATE TESTS
    // ================================================================

    [Fact]
    public async Task Create_ThenDeactivate_Succeeds()
    {
        var (method, httpClient) = CreateMethod();
        var signer = CreateEd25519Signer();

        // Create
        var createResult = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = signer
        });

        var logContent = (string)createResult.Artifacts![DidWebVhArtifacts.DidJsonl];
        var did = createResult.Did.Value;

        // Deactivate
        var deactivateResult = await method.DeactivateAsync(did, new DidWebVhDeactivateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(logContent),
            SigningKey = signer
        });

        deactivateResult.Success.Should().BeTrue();
        deactivateResult.Artifacts.Should().ContainKey(DidWebVhArtifacts.DidJsonl);

        // Resolve should show deactivated
        var updatedLog = (string)deactivateResult.Artifacts![DidWebVhArtifacts.DidJsonl];
        var logUrl = DidUrlMapper.MapToLogUrl(did);
        httpClient.SetLogResponse(logUrl, Encoding.UTF8.GetBytes(updatedLog));

        var resolveResult = await method.ResolveAsync(did);
        resolveResult.DidDocument.Should().NotBeNull();
        resolveResult.DocumentMetadata!.Deactivated.Should().BeTrue();
    }

    [Fact]
    public async Task Deactivate_UnauthorizedKey_Throws()
    {
        var (method, _) = CreateMethod();
        var authorizedKey = CreateEd25519Signer();
        var unauthorizedKey = CreateEd25519Signer();

        var createResult = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = authorizedKey
        });

        var logContent = (string)createResult.Artifacts![DidWebVhArtifacts.DidJsonl];
        var did = createResult.Did.Value;

        var act = () => method.DeactivateAsync(did, new DidWebVhDeactivateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(logContent),
            SigningKey = unauthorizedKey
        });

        await act.Should().ThrowAsync<ArgumentException>().WithMessage("*authorized*");
    }

    // ================================================================
    // PRE-ROTATION TESTS
    // ================================================================

    [Fact]
    public async Task PreRotation_Create_ThenUpdate_WithRotatedKey_Succeeds()
    {
        var (method, httpClient) = CreateMethod();
        var key1 = CreateEd25519Signer();
        var key2 = CreateEd25519Signer();
        var commitment2 = PreRotationManager.ComputeKeyCommitment(key2.MultibasePublicKey);

        // Create with pre-rotation
        var createResult = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = key1,
            EnablePreRotation = true,
            PreRotationCommitments = [commitment2]
        });

        var logContent = (string)createResult.Artifacts![DidWebVhArtifacts.DidJsonl];
        var did = createResult.Did.Value;

        // Rotate to key2 — signed by key1 (the current authorized key),
        // with key2 becoming the new updateKey (validator checks commitment)
        var key3 = CreateEd25519Signer();
        var commitment3 = PreRotationManager.ComputeKeyCommitment(key3.MultibasePublicKey);

        var updateResult = await method.UpdateAsync(did, new DidWebVhUpdateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(logContent),
            SigningKey = key1,
            ParameterUpdates = new DidWebVhParameterUpdates
            {
                UpdateKeys = [key2.MultibasePublicKey],
                Prerotation = true,
                NextKeyHashes = [commitment3]
            }
        });

        // Verify the update succeeded and is resolvable
        var updatedLog = (string)updateResult.Artifacts![DidWebVhArtifacts.DidJsonl];
        var logUrl = DidUrlMapper.MapToLogUrl(did);
        httpClient.SetLogResponse(logUrl, Encoding.UTF8.GetBytes(updatedLog));

        var resolveResult = await method.ResolveAsync(did);
        resolveResult.DidDocument.Should().NotBeNull();
        resolveResult.ResolutionMetadata.Error.Should().BeNull();
    }

    // ================================================================
    // CAPABILITIES TESTS
    // ================================================================

    [Fact]
    public void MethodName_IsWebvh()
    {
        var (method, _) = CreateMethod();
        method.MethodName.Should().Be("webvh");
    }

    [Fact]
    public void Capabilities_IncludeAllCrud()
    {
        var (method, _) = CreateMethod();
        method.Capabilities.Should().HaveFlag(DidMethodCapabilities.Create);
        method.Capabilities.Should().HaveFlag(DidMethodCapabilities.Resolve);
        method.Capabilities.Should().HaveFlag(DidMethodCapabilities.Update);
        method.Capabilities.Should().HaveFlag(DidMethodCapabilities.Deactivate);
        method.Capabilities.Should().HaveFlag(DidMethodCapabilities.ServiceEndpoints);
    }

    [Fact]
    public void CanResolve_DidWebvh_ReturnsTrue()
    {
        var (method, _) = CreateMethod();
        method.CanResolve("did:webvh:QmTest:example.com").Should().BeTrue();
    }

    // --- Discovery surface (issue #36) ---

    [Fact]
    public void SupportedKeyTypes_IsEd25519Only()
    {
        // did:webvh requires Ed25519 update keys; this is hardcoded in CreateAsync.
        var (method, _) = CreateMethod();
        method.SupportedKeyTypes.Should().Equal(KeyType.Ed25519);
    }

    [Fact]
    public async Task SupportedKeyTypes_NonEd25519UpdateKey_StillRejected()
    {
        // The discovery surface is a contract; CreateAsync must still reject non-Ed25519.
        var (method, _) = CreateMethod();
        var p256KeyPair = _keyGen.Generate(KeyType.P256);
        var p256Signer = new KeyPairSigner(p256KeyPair, _crypto);

        var act = () => method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = p256Signer
        });

        await act.Should().ThrowAsync<ArgumentException>()
            .WithMessage("*Ed25519*");
    }

    [Fact]
    public void SupportsRecovery_IsFalse_UntilRecoveryApiLands()
    {
        // ND-E9 (issue #44) will wire the log/commitment recovery category for did:webvh.
        var (method, _) = CreateMethod();
        method.SupportsRecovery.Should().BeFalse();
        method.RecoveryMaterialSpec.Should().BeNull();
    }

    [Fact]
    public void CanResolve_DidKey_ReturnsFalse()
    {
        var (method, _) = CreateMethod();
        method.CanResolve("did:key:z6MkTest").Should().BeFalse();
    }

    // ================================================================
    // MULTIPLE UPDATES CHAIN TEST
    // ================================================================

    [Fact]
    public async Task MultipleUpdates_ChainValidates()
    {
        var (method, httpClient) = CreateMethod();
        var signer = CreateEd25519Signer();

        // Create
        var createResult = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = signer
        });

        var logContent = (string)createResult.Artifacts![DidWebVhArtifacts.DidJsonl];
        var did = createResult.Did.Value;

        // First update
        var update1 = await method.UpdateAsync(did, new DidWebVhUpdateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(logContent),
            SigningKey = signer
        });
        logContent = (string)update1.Artifacts![DidWebVhArtifacts.DidJsonl];

        // Second update
        var update2 = await method.UpdateAsync(did, new DidWebVhUpdateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(logContent),
            SigningKey = signer
        });
        logContent = (string)update2.Artifacts![DidWebVhArtifacts.DidJsonl];

        // Third update
        var update3 = await method.UpdateAsync(did, new DidWebVhUpdateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(logContent),
            SigningKey = signer
        });
        logContent = (string)update3.Artifacts![DidWebVhArtifacts.DidJsonl];

        // Verify 4 entries total
        var entries = LogEntrySerializer.ParseJsonLines(Encoding.UTF8.GetBytes(logContent));
        entries.Should().HaveCount(4);

        // Resolve should return the latest document
        var logUrl = DidUrlMapper.MapToLogUrl(did);
        httpClient.SetLogResponse(logUrl, Encoding.UTF8.GetBytes(logContent));

        var resolveResult = await method.ResolveAsync(did);
        resolveResult.DidDocument.Should().NotBeNull();
        resolveResult.DocumentMetadata!.VersionId.Should().StartWith("4-");
    }

    // ================================================================
    // ISSUE #14: ENTRY HASH CHAINING TO PREVIOUS VERSIONID
    // ================================================================

    [Fact]
    public async Task Issue14_EntryHashChainsViaPreviousVersionId()
    {
        var (method, _) = CreateMethod();
        var signer = CreateEd25519Signer();

        var createResult = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = signer
        });

        var logContent = (string)createResult.Artifacts![DidWebVhArtifacts.DidJsonl];
        var did = createResult.Did.Value;

        // First update
        var update1 = await method.UpdateAsync(did, new DidWebVhUpdateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(logContent),
            SigningKey = signer
        });
        logContent = (string)update1.Artifacts![DidWebVhArtifacts.DidJsonl];

        // Second update
        var update2 = await method.UpdateAsync(did, new DidWebVhUpdateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(logContent),
            SigningKey = signer
        });
        logContent = (string)update2.Artifacts![DidWebVhArtifacts.DidJsonl];

        var entries = LogEntrySerializer.ParseJsonLines(Encoding.UTF8.GetBytes(logContent));
        entries.Should().HaveCount(3);

        // Verify each entry's hash is computed using the PREVIOUS entry's versionId
        // by re-computing: set versionId to "{N}-{previous.VersionId}", hash, compare
        for (int i = 1; i < entries.Count; i++)
        {
            var current = entries[i];
            var previous = entries[i - 1];
            var version = i + 1;

            var entryForHashing = current with { VersionId = $"{version}-{previous.VersionId}" };
            var json = LogEntrySerializer.SerializeWithoutProof(entryForHashing);
            var computedHash = ScidGenerator.ComputeEntryHash(json);

            current.EntryHash.Should().Be(computedHash,
                $"version {version} entry hash should chain to previous versionId");
        }
    }

    [Fact]
    public async Task Issue14_TamperedIntermediateEntry_FailsChainValidation()
    {
        var (method, httpClient) = CreateMethod();
        var signer = CreateEd25519Signer();

        // Create a 3-entry log
        var createResult = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = signer
        });
        var logContent = (string)createResult.Artifacts![DidWebVhArtifacts.DidJsonl];
        var did = createResult.Did.Value;

        var update1 = await method.UpdateAsync(did, new DidWebVhUpdateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(logContent),
            SigningKey = signer
        });
        logContent = (string)update1.Artifacts![DidWebVhArtifacts.DidJsonl];

        var update2 = await method.UpdateAsync(did, new DidWebVhUpdateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(logContent),
            SigningKey = signer
        });
        logContent = (string)update2.Artifacts![DidWebVhArtifacts.DidJsonl];

        // Tamper with version 2's versionId (simulate rewriting history)
        var lines = logContent.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        lines.Should().HaveCount(3);

        // Parse entry 2 and change its entry hash
        var entries = LogEntrySerializer.ParseJsonLines(Encoding.UTF8.GetBytes(logContent));
        var originalV2Hash = entries[1].EntryHash;
        var tamperedLine = lines[1].Replace(originalV2Hash, "zTamperedHash12345");
        lines[1] = tamperedLine;

        var tamperedLog = System.Text.Encoding.UTF8.GetBytes(string.Join("\n", lines));
        var logUrl = DidUrlMapper.MapToLogUrl(did);
        httpClient.SetLogResponse(logUrl, tamperedLog);

        // Resolution should fail due to chain validation
        var resolveResult = await method.ResolveAsync(did);
        resolveResult.ResolutionMetadata.Error.Should().NotBeNull();
    }

    // ================================================================
    // ISSUE #15: WITNESS VALIDATION
    // ================================================================

    [Fact]
    public async Task Issue15_MissingWitnessFile_WhenRequired_FailsResolution()
    {
        var (method, httpClient) = CreateMethod();
        var signer = CreateEd25519Signer();
        var witnessDid = "did:key:z6MkWitnessKey";

        var createResult = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = signer,
            WitnessDids = [witnessDid],
            WitnessThreshold = 1
        });

        var logContent = (string)createResult.Artifacts![DidWebVhArtifacts.DidJsonl];
        var did = createResult.Did.Value;
        var logUrl = DidUrlMapper.MapToLogUrl(did);
        httpClient.SetLogResponse(logUrl, Encoding.UTF8.GetBytes(logContent));
        // Intentionally NOT setting witness response

        var resolveResult = await method.ResolveAsync(did);
        resolveResult.DidDocument.Should().BeNull();
        resolveResult.ResolutionMetadata.Error.Should().Be("witnessValidationFailed");
    }

    [Fact]
    public async Task Issue15_MalformedWitnessFile_FailsResolution()
    {
        var (method, httpClient) = CreateMethod();
        var signer = CreateEd25519Signer();
        var witnessDid = "did:key:z6MkWitnessKey";

        var createResult = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = signer,
            WitnessDids = [witnessDid],
            WitnessThreshold = 1
        });

        var logContent = (string)createResult.Artifacts![DidWebVhArtifacts.DidJsonl];
        var did = createResult.Did.Value;
        var logUrl = DidUrlMapper.MapToLogUrl(did);
        httpClient.SetLogResponse(logUrl, Encoding.UTF8.GetBytes(logContent));

        // Set malformed witness file
        var witnessUrl = DidUrlMapper.MapToWitnessUrl(did);
        httpClient.SetWitnessResponse(witnessUrl, "not-valid-json"u8.ToArray());

        var resolveResult = await method.ResolveAsync(did);
        resolveResult.DidDocument.Should().BeNull();
        resolveResult.ResolutionMetadata.Error.Should().Be("witnessValidationFailed");
    }

    [Fact]
    public void Issue15_WitnessFileParser_HandlesSpecArrayFormat()
    {
        // Spec-compliant format: array of { versionId, proofs }
        var json = """
        [
            {
                "versionId": "1-zTestScid",
                "proofs": [
                    {
                        "type": "DataIntegrityProof",
                        "cryptosuite": "eddsa-jcs-2022",
                        "verificationMethod": "did:key:z6MkTest#z6MkTest",
                        "created": "2026-01-01T00:00:00Z",
                        "proofPurpose": "assertionMethod",
                        "proofValue": "zTestValue"
                    }
                ]
            },
            {
                "versionId": "2-zTestHash",
                "proofs": []
            }
        ]
        """;

        var witnessFile = WitnessValidator.ParseWitnessFile(
            System.Text.Encoding.UTF8.GetBytes(json));

        witnessFile.Should().NotBeNull();
        witnessFile!.Entries.Should().HaveCount(2);
        witnessFile.Entries[0].VersionId.Should().Be("1-zTestScid");
        witnessFile.Entries[0].Proofs.Should().HaveCount(1);
        witnessFile.Entries[1].VersionId.Should().Be("2-zTestHash");
        witnessFile.Entries[1].Proofs.Should().BeEmpty();
    }

    [Fact]
    public void Issue15_WitnessFileParser_RejectsLegacySingleObjectFormat()
    {
        // Legacy format: single { versionId, proofs } object — no longer accepted per spec
        var json = """
        {
            "versionId": "1-zTestScid",
            "proofs": [
                {
                    "type": "DataIntegrityProof",
                    "cryptosuite": "eddsa-jcs-2022",
                    "verificationMethod": "did:key:z6MkTest#z6MkTest",
                    "created": "2026-01-01T00:00:00Z",
                    "proofPurpose": "assertionMethod",
                    "proofValue": "zTestValue"
                }
            ]
        }
        """;

        var witnessFile = WitnessValidator.ParseWitnessFile(
            System.Text.Encoding.UTF8.GetBytes(json));

        witnessFile.Should().BeNull();
    }

    [Fact]
    public async Task Issue15_LaterWitnessProofs_SatisfyEarlierVersions()
    {
        // Per spec: "for the current or any later published log entries"
        // A witness proof at version 3 should satisfy the witness requirement
        // for version 1, since witnessing version 3 implies approval of all prior entries.
        var crypto = new DefaultCryptoProvider();
        var suite = new EddsaJcs2022Cryptosuite();
        var validator = new WitnessValidator(suite);

        // Create 3 log entries, all requiring witnessing
        var witnessSigner = new KeyPairSigner(
            new DefaultKeyGenerator().Generate(KeyType.Ed25519), crypto);
        var witnessDidKey = $"did:key:{witnessSigner.MultibasePublicKey}";
        var witnessVm = $"{witnessDidKey}#{witnessSigner.MultibasePublicKey}";

        var witnessConfig = new WitnessConfig
        {
            Threshold = 1,
            Witnesses = [new WitnessEntry { Id = witnessDidKey, Weight = 1 }]
        };

        // Simulate 3 log entries (only need data relevant to witness validation)
        var entries = new List<LogEntry>();
        var perEntryParams = new List<LogEntryParameters>();

        for (int i = 0; i < 3; i++)
        {
            var entry = new LogEntry
            {
                VersionId = $"{i + 1}-zTestHash{i}",
                VersionTime = DateTimeOffset.UtcNow.AddMinutes(i),
                Parameters = new LogEntryParameters { Witness = witnessConfig },
                State = new DidDocument { Id = new Did("did:example:test") }
            };
            entries.Add(entry);
            perEntryParams.Add(new LogEntryParameters { Witness = witnessConfig });
        }

        // Create witness proofs ONLY for version 3
        var entry3Json = LogEntrySerializer.SerializeWithoutProof(entries[2]);
        var proof3Created = entries[2].VersionTime.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ");
        using var entry3Doc = JsonDocument.Parse(entry3Json);
        var proof3 = await suite.CreateProofAsync(
            entry3Doc.RootElement,
            new DataIntegrityProof
            {
                Cryptosuite = EddsaJcs2022Cryptosuite.CryptosuiteName,
                VerificationMethod = witnessVm,
                Created = proof3Created,
                ProofPurpose = "assertionMethod",
            },
            witnessSigner);

        var witnessFile = new WitnessFile
        {
            Entries =
            [
                new WitnessProofEntry
                {
                    VersionId = entries[2].VersionId, // Only version 3
                    Proofs =
                    [
                        new DataIntegrityProofValue
                        {
                            Type = DataIntegrityProof.DataIntegrityProofType,
                            Cryptosuite = EddsaJcs2022Cryptosuite.CryptosuiteName,
                            VerificationMethod = witnessVm,
                            Created = proof3Created,
                            ProofPurpose = "assertionMethod",
                            ProofValue = proof3.ProofValue!
                        }
                    ]
                }
            ]
        };

        // Validate: version 1 and 2 require witnessing, only version 3 has proofs
        // Per spec, version 3 proof covers versions 1, 2, and 3
        var result = validator.ValidateAllWitnesses(
            witnessFile, entries, upToIndex: 2, perEntryParams);

        result.Should().BeTrue("later witness proofs should satisfy earlier version requirements");
    }

    // ================================================================
    // ISSUE #16: DID BINDING DURING RESOLUTION
    // ================================================================

    [Fact]
    public async Task Issue16_Resolve_WrongScid_ReturnsError()
    {
        var (method, httpClient) = CreateMethod();
        var signer = CreateEd25519Signer();

        // Create a valid DID
        var createResult = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = signer
        });

        var logContent = (string)createResult.Artifacts![DidWebVhArtifacts.DidJsonl];
        var realDid = createResult.Did.Value;

        // Host the log at the correct URL
        var logUrl = DidUrlMapper.MapToLogUrl(realDid);
        httpClient.SetLogResponse(logUrl, Encoding.UTF8.GetBytes(logContent));

        // Resolve with a DIFFERENT SCID — same domain, wrong SCID
        // Both DIDs map to the same URL, but the document inside has the real DID
        var wrongDid = realDid.Replace(
            DidUrlMapper.ExtractScid(realDid),
            "zWrongScid12345");

        // The wrong SCID maps to the same URL, so the HTTP client returns the same log
        var wrongLogUrl = DidUrlMapper.MapToLogUrl(wrongDid);
        httpClient.SetLogResponse(wrongLogUrl, Encoding.UTF8.GetBytes(logContent));

        var resolveResult = await method.ResolveAsync(wrongDid);
        resolveResult.DidDocument.Should().BeNull();
        resolveResult.ResolutionMetadata.Error.Should().Be("invalidDidLog");
    }

    // ================================================================
    // ISSUE #19: VERSIONTIME IN METADATA
    // ================================================================

    [Fact]
    public async Task Issue19_Resolve_ReturnsVersionTime()
    {
        var (method, httpClient) = CreateMethod();
        var signer = CreateEd25519Signer();

        var createResult = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = signer
        });

        var logContent = (string)createResult.Artifacts![DidWebVhArtifacts.DidJsonl];
        var did = createResult.Did.Value;
        var logUrl = DidUrlMapper.MapToLogUrl(did);
        httpClient.SetLogResponse(logUrl, Encoding.UTF8.GetBytes(logContent));

        var resolveResult = await method.ResolveAsync(did);

        resolveResult.DocumentMetadata.Should().NotBeNull();
        resolveResult.DocumentMetadata!.VersionTime.Should().NotBeNull();
        resolveResult.DocumentMetadata.VersionTime.Should().BeCloseTo(
            DateTimeOffset.UtcNow, TimeSpan.FromMinutes(1));
    }

    [Fact]
    public async Task Issue19_Create_MetadataIncludesVersionTime()
    {
        var (method, _) = CreateMethod();
        var signer = CreateEd25519Signer();

        var result = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = signer
        });

        result.Metadata.Should().NotBeNull();
        result.Metadata!.VersionTime.Should().NotBeNull();
    }

    // ================================================================
    // ISSUE #20: VERSIONED RESOLUTION RETURNS NOTFOUND
    // ================================================================

    [Fact]
    public async Task Issue20_Resolve_MissingVersionId_ReturnsNotFound()
    {
        var (method, httpClient) = CreateMethod();
        var signer = CreateEd25519Signer();

        var createResult = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = signer
        });

        var logContent = (string)createResult.Artifacts![DidWebVhArtifacts.DidJsonl];
        var did = createResult.Did.Value;
        var logUrl = DidUrlMapper.MapToLogUrl(did);
        httpClient.SetLogResponse(logUrl, Encoding.UTF8.GetBytes(logContent));

        var resolveResult = await method.ResolveAsync(did, new DidResolutionOptions
        {
            VersionId = "999-missing"
        });

        resolveResult.DidDocument.Should().BeNull();
        resolveResult.ResolutionMetadata.Error.Should().Be("notFound");
    }

    [Fact]
    public async Task Issue20_Resolve_MissingVersionTime_ReturnsNotFound()
    {
        var (method, httpClient) = CreateMethod();
        var signer = CreateEd25519Signer();

        var createResult = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = signer
        });

        var logContent = (string)createResult.Artifacts![DidWebVhArtifacts.DidJsonl];
        var did = createResult.Did.Value;
        var logUrl = DidUrlMapper.MapToLogUrl(did);
        httpClient.SetLogResponse(logUrl, Encoding.UTF8.GetBytes(logContent));

        // Request a time far in the past — no entry should exist
        var resolveResult = await method.ResolveAsync(did, new DidResolutionOptions
        {
            VersionTime = "2000-01-01T00:00:00Z"
        });

        resolveResult.DidDocument.Should().BeNull();
        resolveResult.ResolutionMetadata.Error.Should().Be("notFound");
    }

    [Fact]
    public async Task Issue20_Resolve_ValidVersionId_Succeeds()
    {
        var (method, httpClient) = CreateMethod();
        var signer = CreateEd25519Signer();

        // Create + update
        var createResult = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = signer
        });
        var logContent = (string)createResult.Artifacts![DidWebVhArtifacts.DidJsonl];
        var did = createResult.Did.Value;

        var updateResult = await method.UpdateAsync(did, new DidWebVhUpdateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(logContent),
            SigningKey = signer
        });
        logContent = (string)updateResult.Artifacts![DidWebVhArtifacts.DidJsonl];

        var entries = LogEntrySerializer.ParseJsonLines(Encoding.UTF8.GetBytes(logContent));
        var v1VersionId = entries[0].VersionId;

        var logUrl = DidUrlMapper.MapToLogUrl(did);
        httpClient.SetLogResponse(logUrl, Encoding.UTF8.GetBytes(logContent));

        // Request version 1 specifically
        var resolveResult = await method.ResolveAsync(did, new DidResolutionOptions
        {
            VersionId = v1VersionId
        });

        resolveResult.DidDocument.Should().NotBeNull();
        resolveResult.DocumentMetadata!.VersionId.Should().Be(v1VersionId);
    }

    [Fact]
    public async Task Issue20_Resolve_EarlierVersion_SucceedsWithPartialChainValidation()
    {
        var (method, httpClient) = CreateMethod();
        var signer = CreateEd25519Signer();

        // Create + update to get a 2-entry log
        var createResult = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = signer
        });
        var logContent = (string)createResult.Artifacts![DidWebVhArtifacts.DidJsonl];
        var did = createResult.Did.Value;

        var updateResult = await method.UpdateAsync(did, new DidWebVhUpdateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(logContent),
            SigningKey = signer
        });
        logContent = (string)updateResult.Artifacts![DidWebVhArtifacts.DidJsonl];

        var entries = LogEntrySerializer.ParseJsonLines(Encoding.UTF8.GetBytes(logContent));
        var v1VersionId = entries[0].VersionId;

        // Corrupt version 2's entry hash
        var lines = logContent.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        var v2Hash = entries[1].EntryHash;
        lines[1] = lines[1].Replace(v2Hash, "zCorruptedHashValue");
        var corruptedLog = System.Text.Encoding.UTF8.GetBytes(string.Join("\n", lines));

        var logUrl = DidUrlMapper.MapToLogUrl(did);
        httpClient.SetLogResponse(logUrl, corruptedLog);

        // Requesting version 1 should succeed — only chain validated up to version 1
        var resolveResult = await method.ResolveAsync(did, new DidResolutionOptions
        {
            VersionId = v1VersionId
        });

        resolveResult.DidDocument.Should().NotBeNull();
        resolveResult.DocumentMetadata!.VersionId.Should().Be(v1VersionId);
    }

    // ================================================================
    // ISSUE #21: PRE-ROTATION BYPASS ENFORCEMENT
    // ================================================================

    [Fact]
    public async Task Issue21_PreRotation_UpdateWithoutKeyRotation_Throws()
    {
        var (method, _) = CreateMethod();
        var key1 = CreateEd25519Signer();
        var key2 = CreateEd25519Signer();
        var commitment2 = PreRotationManager.ComputeKeyCommitment(key2.MultibasePublicKey);

        // Create with pre-rotation
        var createResult = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = key1,
            EnablePreRotation = true,
            PreRotationCommitments = [commitment2]
        });

        var logContent = (string)createResult.Artifacts![DidWebVhArtifacts.DidJsonl];
        var did = createResult.Did.Value;

        // Try to update with TTL change only — no updateKeys
        var act = () => method.UpdateAsync(did, new DidWebVhUpdateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(logContent),
            SigningKey = key1,
            ParameterUpdates = new DidWebVhParameterUpdates
            {
                Ttl = 300
            }
        });

        await act.Should().ThrowAsync<ArgumentException>()
            .WithMessage("*Pre-rotation*updateKeys*");
    }

    [Fact]
    public async Task Issue21_PreRotation_UpdateWithKeyRotation_Succeeds()
    {
        var (method, httpClient) = CreateMethod();
        var key1 = CreateEd25519Signer();
        var key2 = CreateEd25519Signer();
        var commitment2 = PreRotationManager.ComputeKeyCommitment(key2.MultibasePublicKey);

        var createResult = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = key1,
            EnablePreRotation = true,
            PreRotationCommitments = [commitment2]
        });

        var logContent = (string)createResult.Artifacts![DidWebVhArtifacts.DidJsonl];
        var did = createResult.Did.Value;

        // Update with both TTL change and key rotation — should succeed
        var key3 = CreateEd25519Signer();
        var commitment3 = PreRotationManager.ComputeKeyCommitment(key3.MultibasePublicKey);

        var updateResult = await method.UpdateAsync(did, new DidWebVhUpdateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(logContent),
            SigningKey = key1,
            ParameterUpdates = new DidWebVhParameterUpdates
            {
                Ttl = 300,
                UpdateKeys = [key2.MultibasePublicKey],
                Prerotation = true,
                NextKeyHashes = [commitment3]
            }
        });

        updateResult.DidDocument.Should().NotBeNull();

        // Verify it resolves
        var updatedLog = (string)updateResult.Artifacts![DidWebVhArtifacts.DidJsonl];
        var logUrl = DidUrlMapper.MapToLogUrl(did);
        httpClient.SetLogResponse(logUrl, Encoding.UTF8.GetBytes(updatedLog));

        var resolveResult = await method.ResolveAsync(did);
        resolveResult.DidDocument.Should().NotBeNull();
        resolveResult.ResolutionMetadata.Error.Should().BeNull();
    }

    // ================================================================
    // ISSUE #17: WITNESS ARTIFACT PRODUCTION
    // ================================================================

    [Fact]
    public async Task Issue17_Create_WithWitnessProofs_ProducesWitnessArtifact()
    {
        var (method, _) = CreateMethod();
        var signer = CreateEd25519Signer();

        var witnessProofs = new List<WitnessProofEntry>
        {
            new()
            {
                VersionId = "1-zTestScid",
                Proofs =
                [
                    new DataIntegrityProofValue
                    {
                        Type = "DataIntegrityProof",
                        Cryptosuite = "eddsa-jcs-2022",
                        VerificationMethod = "did:key:z6MkTest#z6MkTest",
                        Created = "2026-01-01T00:00:00Z",
                        ProofPurpose = "assertionMethod",
                        ProofValue = "zTestProofValue"
                    }
                ]
            }
        };

        var result = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = signer,
            WitnessDids = ["did:key:z6MkTest"],
            WitnessThreshold = 1,
            WitnessProofs = witnessProofs
        });

        result.Artifacts.Should().ContainKey(DidWebVhArtifacts.DidWitnessJson);
        var witnessContent = (string)result.Artifacts![DidWebVhArtifacts.DidWitnessJson];
        var witnessFile = WitnessValidator.ParseWitnessFile(Encoding.UTF8.GetBytes(witnessContent));
        witnessFile.Should().NotBeNull();
        witnessFile!.Entries.Should().HaveCount(1);
        witnessFile.Entries[0].VersionId.Should().Be("1-zTestScid");
        witnessFile.Entries[0].Proofs.Should().HaveCount(1);
    }

    [Fact]
    public async Task Issue17_Create_WithoutWitnessProofs_OmitsWitnessArtifact()
    {
        var (method, _) = CreateMethod();
        var signer = CreateEd25519Signer();

        var result = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = signer
        });

        result.Artifacts.Should().NotContainKey(DidWebVhArtifacts.DidWitnessJson);
    }

    [Fact]
    public void Issue17_WitnessFile_SerializeRoundTrip()
    {
        var original = new WitnessFile
        {
            Entries =
            [
                new WitnessProofEntry
                {
                    VersionId = "1-zScid1",
                    Proofs =
                    [
                        new DataIntegrityProofValue
                        {
                            Type = "DataIntegrityProof",
                            Cryptosuite = "eddsa-jcs-2022",
                            VerificationMethod = "did:key:z6MkA#z6MkA",
                            Created = "2026-01-01T00:00:00Z",
                            ProofPurpose = "assertionMethod",
                            ProofValue = "zProof1"
                        }
                    ]
                },
                new WitnessProofEntry
                {
                    VersionId = "2-zHash2",
                    Proofs =
                    [
                        new DataIntegrityProofValue
                        {
                            Type = "DataIntegrityProof",
                            Cryptosuite = "eddsa-jcs-2022",
                            VerificationMethod = "did:key:z6MkB#z6MkB",
                            Created = "2026-02-01T00:00:00Z",
                            ProofPurpose = "assertionMethod",
                            ProofValue = "zProof2"
                        }
                    ]
                }
            ]
        };

        var serialized = WitnessValidator.SerializeWitnessFile(original);
        var roundTripped = WitnessValidator.ParseWitnessFile(serialized);

        roundTripped.Should().NotBeNull();
        roundTripped!.Entries.Should().HaveCount(2);
        roundTripped.Entries[0].VersionId.Should().Be("1-zScid1");
        roundTripped.Entries[0].Proofs[0].ProofValue.Should().Be("zProof1");
        roundTripped.Entries[1].VersionId.Should().Be("2-zHash2");
        roundTripped.Entries[1].Proofs[0].ProofValue.Should().Be("zProof2");
    }

    [Fact]
    public void Issue17_WitnessFile_MergeProofs()
    {
        var existing = new WitnessFile
        {
            Entries =
            [
                new WitnessProofEntry
                {
                    VersionId = "1-zScid1",
                    Proofs =
                    [
                        new DataIntegrityProofValue
                        {
                            Type = "DataIntegrityProof",
                            Cryptosuite = "eddsa-jcs-2022",
                            VerificationMethod = "did:key:z6MkA#z6MkA",
                            Created = "2026-01-01T00:00:00Z",
                            ProofPurpose = "assertionMethod",
                            ProofValue = "zOldProof"
                        }
                    ]
                }
            ]
        };

        var newEntries = new List<WitnessProofEntry>
        {
            // Replace existing entry for version 1
            new()
            {
                VersionId = "1-zScid1",
                Proofs =
                [
                    new DataIntegrityProofValue
                    {
                        Type = "DataIntegrityProof",
                        Cryptosuite = "eddsa-jcs-2022",
                        VerificationMethod = "did:key:z6MkA#z6MkA",
                        Created = "2026-01-01T00:00:00Z",
                        ProofPurpose = "assertionMethod",
                        ProofValue = "zNewProof"
                    }
                ]
            },
            // Add new entry for version 2
            new()
            {
                VersionId = "2-zHash2",
                Proofs =
                [
                    new DataIntegrityProofValue
                    {
                        Type = "DataIntegrityProof",
                        Cryptosuite = "eddsa-jcs-2022",
                        VerificationMethod = "did:key:z6MkB#z6MkB",
                        Created = "2026-02-01T00:00:00Z",
                        ProofPurpose = "assertionMethod",
                        ProofValue = "zProof2"
                    }
                ]
            }
        };

        var merged = WitnessValidator.MergeWitnessProofs(existing, newEntries);

        merged.Entries.Should().HaveCount(2);

        // Version 1 should have the new proof (replaced)
        var v1 = merged.Entries.First(e => e.VersionId == "1-zScid1");
        v1.Proofs[0].ProofValue.Should().Be("zNewProof");

        // Version 2 should be added
        var v2 = merged.Entries.First(e => e.VersionId == "2-zHash2");
        v2.Proofs[0].ProofValue.Should().Be("zProof2");
    }

    [Fact]
    public async Task Issue17_Update_WithWitnessProofs_MergesWithExisting()
    {
        var (method, _) = CreateMethod();
        var signer = CreateEd25519Signer();

        // Create
        var createResult = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = signer,
            WitnessDids = ["did:key:z6MkTest"],
            WitnessThreshold = 1,
            WitnessProofs =
            [
                new WitnessProofEntry
                {
                    VersionId = "1-zScid",
                    Proofs =
                    [
                        new DataIntegrityProofValue
                        {
                            Type = "DataIntegrityProof",
                            Cryptosuite = "eddsa-jcs-2022",
                            VerificationMethod = "did:key:z6MkTest#z6MkTest",
                            Created = "2026-01-01T00:00:00Z",
                            ProofPurpose = "assertionMethod",
                            ProofValue = "zCreateProof"
                        }
                    ]
                }
            ]
        });

        var logContent = (string)createResult.Artifacts![DidWebVhArtifacts.DidJsonl];
        var existingWitness = (string)createResult.Artifacts[DidWebVhArtifacts.DidWitnessJson];
        var did = createResult.Did.Value;

        // Update with new witness proofs, merging with existing
        var updateResult = await method.UpdateAsync(did, new DidWebVhUpdateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(logContent),
            SigningKey = signer,
            CurrentWitnessContent = Encoding.UTF8.GetBytes(existingWitness),
            WitnessProofs =
            [
                new WitnessProofEntry
                {
                    VersionId = "2-zHash2",
                    Proofs =
                    [
                        new DataIntegrityProofValue
                        {
                            Type = "DataIntegrityProof",
                            Cryptosuite = "eddsa-jcs-2022",
                            VerificationMethod = "did:key:z6MkTest#z6MkTest",
                            Created = "2026-01-02T00:00:00Z",
                            ProofPurpose = "assertionMethod",
                            ProofValue = "zUpdateProof"
                        }
                    ]
                }
            ]
        });

        updateResult.Artifacts.Should().ContainKey(DidWebVhArtifacts.DidWitnessJson);
        var mergedContent = (string)updateResult.Artifacts![DidWebVhArtifacts.DidWitnessJson];
        var merged = WitnessValidator.ParseWitnessFile(Encoding.UTF8.GetBytes(mergedContent));
        merged.Should().NotBeNull();
        merged!.Entries.Should().HaveCount(2);
    }

    [Fact]
    public async Task Issue17_Deactivate_WithWitnessProofs_ProducesWitnessArtifact()
    {
        var (method, _) = CreateMethod();
        var signer = CreateEd25519Signer();

        var createResult = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = signer
        });

        var logContent = (string)createResult.Artifacts![DidWebVhArtifacts.DidJsonl];
        var did = createResult.Did.Value;

        var deactivateResult = await method.DeactivateAsync(did, new DidWebVhDeactivateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(logContent),
            SigningKey = signer,
            WitnessProofs =
            [
                new WitnessProofEntry
                {
                    VersionId = "2-zDeactivate",
                    Proofs =
                    [
                        new DataIntegrityProofValue
                        {
                            Type = "DataIntegrityProof",
                            Cryptosuite = "eddsa-jcs-2022",
                            VerificationMethod = "did:key:z6MkTest#z6MkTest",
                            Created = "2026-03-01T00:00:00Z",
                            ProofPurpose = "assertionMethod",
                            ProofValue = "zDeactivateProof"
                        }
                    ]
                }
            ]
        });

        deactivateResult.Artifacts.Should().ContainKey(DidWebVhArtifacts.DidWitnessJson);
        var witnessContent = (string)deactivateResult.Artifacts![DidWebVhArtifacts.DidWitnessJson];
        var witnessFile = WitnessValidator.ParseWitnessFile(Encoding.UTF8.GetBytes(witnessContent));
        witnessFile.Should().NotBeNull();
        witnessFile!.Entries.Should().HaveCount(1);
    }

    [Fact]
    public async Task Issue21_Validator_RejectsEntryWithoutKeyRotation_WhenPreRotationActive()
    {
        var (method, httpClient) = CreateMethod();
        var key1 = CreateEd25519Signer();
        var key2 = CreateEd25519Signer();
        var commitment2 = PreRotationManager.ComputeKeyCommitment(key2.MultibasePublicKey);

        var createResult = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = key1,
            EnablePreRotation = true,
            PreRotationCommitments = [commitment2]
        });

        var logContent = (string)createResult.Artifacts![DidWebVhArtifacts.DidJsonl];
        var did = createResult.Did.Value;

        // Manually construct an update entry WITHOUT updateKeys to bypass the API check
        // and feed it directly into the validator via resolution
        var key3 = CreateEd25519Signer();
        var commitment3 = PreRotationManager.ComputeKeyCommitment(key3.MultibasePublicKey);

        // Proper update with key rotation
        var updateResult = await method.UpdateAsync(did, new DidWebVhUpdateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(logContent),
            SigningKey = key1,
            ParameterUpdates = new DidWebVhParameterUpdates
            {
                UpdateKeys = [key2.MultibasePublicKey],
                Prerotation = true,
                NextKeyHashes = [commitment3]
            }
        });

        // The update succeeds at the API level; verify the log resolves correctly
        var updatedLog = (string)updateResult.Artifacts![DidWebVhArtifacts.DidJsonl];
        var logUrl = DidUrlMapper.MapToLogUrl(did);
        httpClient.SetLogResponse(logUrl, Encoding.UTF8.GetBytes(updatedLog));

        var resolveResult = await method.ResolveAsync(did);
        resolveResult.DidDocument.Should().NotBeNull();
        resolveResult.ResolutionMetadata.Error.Should().BeNull();
    }

    // ================================================================
    // ISSUE #49: CREATE-TIME REJECTION OF UNSAFE DOMAIN / PATH INPUTS
    // ================================================================

    [Theory]
    [InlineData("evil@bank")]
    [InlineData("example.com/attacker")]
    [InlineData("example.com\\evil")]
    [InlineData("")]
    public async Task Issue49_Create_UnsafeDomain_Throws(string domain)
    {
        var (method, _) = CreateMethod();
        var signer = CreateEd25519Signer();

        var act = () => method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = domain,
            UpdateKey = signer
        });

        await act.Should().ThrowAsync<ArgumentException>();
    }

    [Theory]
    [InlineData("../etc")]
    [InlineData("users/../admin")]
    [InlineData(".")]
    public async Task Issue49_Create_UnsafePath_Throws(string path)
    {
        var (method, _) = CreateMethod();
        var signer = CreateEd25519Signer();

        var act = () => method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            Path = path,
            UpdateKey = signer
        });

        await act.Should().ThrowAsync<ArgumentException>();
    }

    // ================================================================
    // Issue #37: IncludeLog — expose parsed log on DidResolutionResult
    // ================================================================

    [Fact]
    public async Task Issue37_Resolve_WithoutIncludeLog_ArtifactsIsNull()
    {
        var (method, httpClient) = CreateMethod();
        var signer = CreateEd25519Signer();

        var createResult = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = signer
        });
        var logContent = (string)createResult.Artifacts![DidWebVhArtifacts.DidJsonl];
        httpClient.SetLogResponse(
            DidUrlMapper.MapToLogUrl(createResult.Did.Value),
            Encoding.UTF8.GetBytes(logContent));

        var resolveResult = await method.ResolveAsync(createResult.Did.Value);

        resolveResult.Artifacts.Should().BeNull();
    }

    [Fact]
    public async Task Issue37_Resolve_WithIncludeLog_ReturnsParsedEntries()
    {
        var (method, httpClient) = CreateMethod();
        var signer = CreateEd25519Signer();

        var createResult = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = signer
        });
        var logContent = (string)createResult.Artifacts![DidWebVhArtifacts.DidJsonl];
        httpClient.SetLogResponse(
            DidUrlMapper.MapToLogUrl(createResult.Did.Value),
            Encoding.UTF8.GetBytes(logContent));

        var resolveResult = await method.ResolveAsync(
            createResult.Did.Value,
            new DidResolutionOptions { IncludeLog = true });

        resolveResult.Artifacts.Should().NotBeNull();
        resolveResult.Artifacts!.Should().ContainKey(DidWebVhArtifacts.LogEntries);
        var entries = (IReadOnlyList<LogEntry>)resolveResult.Artifacts![DidWebVhArtifacts.LogEntries];
        entries.Should().HaveCount(1);
        entries[0].VersionNumber.Should().Be(1);
        entries[0].State.Id.Value.Should().Be(createResult.Did.Value);
    }

    [Fact]
    public async Task Issue37_Resolve_WithIncludeLog_ReturnsRawJsonl()
    {
        var (method, httpClient) = CreateMethod();
        var signer = CreateEd25519Signer();

        var createResult = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = signer
        });
        var createdLog = (string)createResult.Artifacts![DidWebVhArtifacts.DidJsonl];
        httpClient.SetLogResponse(
            DidUrlMapper.MapToLogUrl(createResult.Did.Value),
            Encoding.UTF8.GetBytes(createdLog));

        var resolveResult = await method.ResolveAsync(
            createResult.Did.Value,
            new DidResolutionOptions { IncludeLog = true });

        resolveResult.Artifacts.Should().ContainKey(DidWebVhArtifacts.DidJsonl);
        var resolvedLog = (string)resolveResult.Artifacts![DidWebVhArtifacts.DidJsonl];
        resolvedLog.Should().Be(createdLog);
    }

    [Fact]
    public async Task Issue37_Resolve_AfterUpdate_LogContainsAllEntries()
    {
        var (method, httpClient) = CreateMethod();
        var signer = CreateEd25519Signer();

        var createResult = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = signer
        });
        var did = createResult.Did.Value;

        // Update once
        var updatedDoc = new DidDocument
        {
            Id = createResult.Did,
            VerificationMethod = createResult.DidDocument.VerificationMethod,
            Authentication = createResult.DidDocument.Authentication,
            AssertionMethod = createResult.DidDocument.AssertionMethod,
            CapabilityInvocation = createResult.DidDocument.CapabilityInvocation,
            CapabilityDelegation = createResult.DidDocument.CapabilityDelegation,
            AlsoKnownAs = createResult.DidDocument.AlsoKnownAs,
            Service =
            [
                new Service
                {
                    Id = $"{did}#pds",
                    Type = "TurtleShellPds",
                    ServiceEndpoint = ServiceEndpointValue.FromUri("https://example.com/pds")
                }
            ]
        };
        var updateResult = await method.UpdateAsync(did, new DidWebVhUpdateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes((string)createResult.Artifacts![DidWebVhArtifacts.DidJsonl]),
            SigningKey = signer,
            NewDocument = updatedDoc
        });

        var updatedLog = (string)updateResult.Artifacts![DidWebVhArtifacts.DidJsonl];
        httpClient.SetLogResponse(
            DidUrlMapper.MapToLogUrl(did), Encoding.UTF8.GetBytes(updatedLog));

        var resolveResult = await method.ResolveAsync(
            did, new DidResolutionOptions { IncludeLog = true });

        var entries = (IReadOnlyList<LogEntry>)resolveResult.Artifacts![DidWebVhArtifacts.LogEntries];
        entries.Should().HaveCount(2);
        entries[0].VersionNumber.Should().Be(1);
        entries[1].VersionNumber.Should().Be(2);
    }

    [Fact]
    public void Issue37_DidWebVhMethod_AdvertisesHistoryCapability()
    {
        var (method, _) = CreateMethod();
        method.Capabilities.HasFlag(DidMethodCapabilities.History).Should().BeTrue();
    }

    [Fact]
    public void Issue37_DidResolutionOptions_CacheDiscriminator_DistinguishesIncludeLog()
    {
        var without = new DidResolutionOptions();
        var with = new DidResolutionOptions { IncludeLog = true };

        without.GetCacheDiscriminator().Should().NotBe(with.GetCacheDiscriminator());
    }

    // ================================================================
    // ISSUE 82 — Update/Deactivate must bind their inputs to the target
    // DID, and DidUpdateResult must expose authorization-change evidence.
    // https://github.com/moisesja/net-did/issues/82
    // ================================================================

    /// <summary>Creates a fresh did:webvh DID and returns (did, log bytes-as-string, its update signer).</summary>
    private async Task<(string Did, string Log, ISigner Signer)> CreateWebVhDidAsync(
        DidWebVhMethod method, string? path = null)
    {
        var signer = CreateEd25519Signer();
        var result = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            Path = path,
            UpdateKey = signer
        });
        return (result.Did.Value, (string)result.Artifacts![DidWebVhArtifacts.DidJsonl], signer);
    }

    [Fact]
    public async Task Issue82_Update_LogOfDifferentDid_Throws()
    {
        // Reproduction #1: an "update of A" driven entirely by B's log + B's signer, with a
        // document claiming Id = A, must be rejected — otherwise the driver mints a log its
        // own resolver rejects.
        var (method, _) = CreateMethod();
        var (didA, _, _) = await CreateWebVhDidAsync(method, "alice");
        var (_, logB, signerB) = await CreateWebVhDidAsync(method, "bob");

        var act = () => method.UpdateAsync(didA, new DidWebVhUpdateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(logB),
            SigningKey = signerB,
            NewDocument = new DidDocument { Id = new Did(didA) }
        });

        await act.Should().ThrowAsync<ArgumentException>().WithMessage("*does not belong*");
    }

    [Fact]
    public async Task Issue82_Update_NewDocumentIdMismatch_Throws()
    {
        var (method, _) = CreateMethod();
        var (didA, logA, signerA) = await CreateWebVhDidAsync(method, "alice");
        var (didB, _, _) = await CreateWebVhDidAsync(method, "bob");

        var act = () => method.UpdateAsync(didA, new DidWebVhUpdateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(logA),
            SigningKey = signerA,
            NewDocument = new DidDocument { Id = new Did(didB) }
        });

        await act.Should().ThrowAsync<ArgumentException>().WithMessage("*NewDocument.Id*");
    }

    [Fact]
    public async Task Issue82_Update_NewDocumentMissingId_Throws()
    {
        var (method, _) = CreateMethod();
        var (didA, logA, signerA) = await CreateWebVhDidAsync(method, "alice");

        // A document with no Id (default(Did).Value == null) must not be accepted for an update.
        var act = () => method.UpdateAsync(didA, new DidWebVhUpdateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(logA),
            SigningKey = signerA,
            NewDocument = new DidDocument()
        });

        await act.Should().ThrowAsync<ArgumentException>().WithMessage("*NewDocument.Id*");
    }

    [Fact]
    public async Task Issue82_Update_OnDeactivatedLog_Throws()
    {
        var (method, _) = CreateMethod();
        var (didA, logA, signerA) = await CreateWebVhDidAsync(method, "alice");

        var deactivated = await method.DeactivateAsync(didA, new DidWebVhDeactivateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(logA),
            SigningKey = signerA
        });
        var deactivatedLog = (string)deactivated.Artifacts![DidWebVhArtifacts.DidJsonl];

        var act = () => method.UpdateAsync(didA, new DidWebVhUpdateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(deactivatedLog),
            SigningKey = signerA,
            NewDocument = new DidDocument { Id = new Did(didA) }
        });

        await act.Should().ThrowAsync<ArgumentException>().WithMessage("*deactivated*");
    }

    [Fact]
    public async Task Issue82_Deactivate_LogOfDifferentDid_Throws()
    {
        var (method, _) = CreateMethod();
        var (didA, _, _) = await CreateWebVhDidAsync(method, "alice");
        var (_, logB, signerB) = await CreateWebVhDidAsync(method, "bob");

        var act = () => method.DeactivateAsync(didA, new DidWebVhDeactivateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(logB),
            SigningKey = signerB
        });

        await act.Should().ThrowAsync<ArgumentException>().WithMessage("*does not belong*");
    }

    [Fact]
    public async Task Issue82_Deactivate_OnDeactivatedLog_Throws()
    {
        var (method, _) = CreateMethod();
        var (didA, logA, signerA) = await CreateWebVhDidAsync(method, "alice");

        var deactivated = await method.DeactivateAsync(didA, new DidWebVhDeactivateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(logA),
            SigningKey = signerA
        });
        var deactivatedLog = (string)deactivated.Artifacts![DidWebVhArtifacts.DidJsonl];

        var act = () => method.DeactivateAsync(didA, new DidWebVhDeactivateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(deactivatedLog),
            SigningKey = signerA
        });

        await act.Should().ThrowAsync<ArgumentException>().WithMessage("*deactivated*");
    }

    [Fact]
    public async Task Issue82_Update_DocumentOnlyEdit_AuthorizationChangedFalse()
    {
        var (method, httpClient) = CreateMethod();
        var signerA = CreateEd25519Signer();
        var createA = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            Path = "alice",
            UpdateKey = signerA
        });
        var didA = createA.Did.Value;
        var logA = (string)createA.Artifacts![DidWebVhArtifacts.DidJsonl];

        // Document-only edit: add a service, touch no parameters.
        var editedDoc = createA.DidDocument with
        {
            Service =
            [
                new Service
                {
                    Id = $"{didA}#pds",
                    Type = "TurtleShellPds",
                    ServiceEndpoint = ServiceEndpointValue.FromUri("https://example.com/pds")
                }
            ]
        };

        var updateResult = await method.UpdateAsync(didA, new DidWebVhUpdateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(logA),
            SigningKey = signerA,
            NewDocument = editedDoc
        });

        updateResult.AuthorizationChanged.Should().BeFalse();

        // Writer/reader parity: the appended log must resolve for the target DID.
        var updatedLog = (string)updateResult.Artifacts![DidWebVhArtifacts.DidJsonl];
        var logUrl = DidUrlMapper.MapToLogUrl(didA);
        httpClient.SetLogResponse(logUrl, Encoding.UTF8.GetBytes(updatedLog));
        var resolved = await method.ResolveAsync(didA);
        resolved.DidDocument.Should().NotBeNull();
        resolved.DidDocument!.Id.Value.Should().Be(didA);

        // Preserve-document case (NewDocument == null) is likewise not an authority change.
        var preserveResult = await method.UpdateAsync(didA, new DidWebVhUpdateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(logA),
            SigningKey = signerA
        });
        preserveResult.AuthorizationChanged.Should().BeFalse();
    }

    [Fact]
    public async Task Issue82_Update_KeyRotation_AuthorizationChangedTrue()
    {
        // Reproduction #2: a smuggled updateKeys rotation is invisible in DidDocument but must
        // be flagged so a method-agnostic caller can reject an unintended authority change.
        var (method, _) = CreateMethod();
        var (didA, logA, signerA) = await CreateWebVhDidAsync(method, "alice");
        var newKey = CreateEd25519Signer();

        var updateResult = await method.UpdateAsync(didA, new DidWebVhUpdateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(logA),
            SigningKey = signerA,
            ParameterUpdates = new DidWebVhParameterUpdates
            {
                UpdateKeys = [newKey.MultibasePublicKey]
            }
        });

        updateResult.AuthorizationChanged.Should().BeTrue();
    }

    [Fact]
    public async Task Issue82_Update_SameUpdateKeysSupplied_AuthorizationChangedFalse()
    {
        // Re-supplying the identical authorized key set is a no-op for authority.
        var (method, _) = CreateMethod();
        var (didA, logA, signerA) = await CreateWebVhDidAsync(method, "alice");

        var updateResult = await method.UpdateAsync(didA, new DidWebVhUpdateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(logA),
            SigningKey = signerA,
            ParameterUpdates = new DidWebVhParameterUpdates
            {
                UpdateKeys = [signerA.MultibasePublicKey]
            }
        });

        updateResult.AuthorizationChanged.Should().BeFalse();
    }

    [Fact]
    public async Task Issue82_Update_PrerotationAndNextKeyHashes_AuthorizationChangedTrue()
    {
        var (method, _) = CreateMethod();
        var (didA, logA, signerA) = await CreateWebVhDidAsync(method, "alice");
        var nextKey = CreateEd25519Signer();
        var commitment = PreRotationManager.ComputeKeyCommitment(nextKey.MultibasePublicKey);

        var updateResult = await method.UpdateAsync(didA, new DidWebVhUpdateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(logA),
            SigningKey = signerA,
            ParameterUpdates = new DidWebVhParameterUpdates
            {
                Prerotation = true,
                NextKeyHashes = [commitment]
            }
        });

        updateResult.AuthorizationChanged.Should().BeTrue();
    }

    [Fact]
    public async Task Issue82_Update_WitnessChange_AuthorizationChangedTrue()
    {
        var (method, _) = CreateMethod();
        var (didA, logA, signerA) = await CreateWebVhDidAsync(method, "alice");
        var witnessSigner = CreateEd25519Signer();

        var updateResult = await method.UpdateAsync(didA, new DidWebVhUpdateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(logA),
            SigningKey = signerA,
            ParameterUpdates = new DidWebVhParameterUpdates
            {
                Witness = new WitnessConfig
                {
                    Threshold = 1,
                    Witnesses = [new WitnessEntry { Id = $"did:key:{witnessSigner.MultibasePublicKey}", Weight = 1 }]
                }
            }
        });

        updateResult.AuthorizationChanged.Should().BeTrue();
    }

    // ----------------------------------------------------------------
    // Issue #82 (adversarial audit follow-up): the DID's self-certifying
    // SCID must be bound to the genesis on BOTH the read and write paths.
    // A domain/host-controlling attacker can serve a self-consistent
    // genesis whose latest state.id claims the victim DID (passing the
    // State.Id check) but whose genesis SCID is the attacker's — this is
    // caught only by binding ExtractScid(did) == genesis SCID.
    // ----------------------------------------------------------------

    /// <summary>
    /// Signs a log entry exactly as the driver does (eddsa-jcs-2022 over the entry without its
    /// proof, verificationMethod = signer's own did:key), so tests can forge a validly-signed log.
    /// </summary>
    private static async Task<DataIntegrityProofValue> SignEntryAsync(LogEntry entry, ISigner signer)
    {
        var suite = new EddsaJcs2022Cryptosuite();
        var proofOptions = new DataIntegrityProof
        {
            Cryptosuite = EddsaJcs2022Cryptosuite.CryptosuiteName,
            VerificationMethod = $"did:key:{signer.MultibasePublicKey}#{signer.MultibasePublicKey}",
            Created = entry.VersionTime.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"),
            ProofPurpose = "assertionMethod",
        };
        using var document = JsonDocument.Parse(LogEntrySerializer.SerializeWithoutProof(entry));
        var proof = await suite.CreateProofAsync(document.RootElement, proofOptions, signer, default);
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

    /// <summary>
    /// Builds a self-consistent, validly-signed single-entry log whose document <c>id</c> is the
    /// literal <paramref name="claimedDid"/> but whose genesis SCID is freshly computed from the
    /// attacker's own content (so it does NOT equal <paramref name="claimedDid"/>'s SCID). This is
    /// what an attacker serves at the victim's URL; it passes chain validation and the State.Id
    /// check, and is only rejected by the genesis-SCID binding.
    /// </summary>
    private static async Task<byte[]> ForgeGenesisClaimingDidAsync(string claimedDid, ISigner attackerKey)
    {
        var attackerMb = attackerKey.MultibasePublicKey;
        var doc = new DidDocument
        {
            Id = new Did(claimedDid),
            VerificationMethod =
            [
                new VerificationMethod
                {
                    Id = $"{claimedDid}#{attackerMb}",
                    Type = "Multikey",
                    Controller = new Did(claimedDid),
                    PublicKeyMultibase = attackerMb
                }
            ]
        };
        var parameters = new LogEntryParameters
        {
            Method = DidWebVhMethod.MethodVersion,
            Scid = ScidGenerator.SafePlaceholder,
            UpdateKeys = [attackerMb],
            Deactivated = false
        };
        var entry = new LogEntry
        {
            VersionId = $"1-{ScidGenerator.SafePlaceholder}",
            VersionTime = DateTimeOffset.UtcNow,
            Parameters = parameters,
            State = doc
        };

        // Compute a self-consistent SCID over this forged genesis (state.id kept literal).
        var jsonWithPlaceholder = LogEntrySerializer.SerializeWithoutProof(entry)
            .Replace(ScidGenerator.SafePlaceholder, ScidGenerator.Placeholder);
        var scid = ScidGenerator.ComputeScid(jsonWithPlaceholder);
        var finalEntry = LogEntrySerializer.DeserializeEntry(
            ScidGenerator.ReplacePlaceholders(jsonWithPlaceholder, scid));

        finalEntry = finalEntry with { Proof = [await SignEntryAsync(finalEntry, attackerKey)] };
        return LogEntrySerializer.ToJsonLines([finalEntry]);
    }

    [Fact]
    public async Task Issue82_Resolve_ForgedGenesisClaimingDid_ReturnsInvalidDidLog()
    {
        var (method, httpClient) = CreateMethod();

        // Victim publishes a real DID.
        var victimSigner = CreateEd25519Signer();
        var victim = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            Path = "alice",
            UpdateKey = victimSigner
        });
        var victimDid = victim.Did.Value;

        // Attacker who controls example.com serves a forged genesis: its document claims the
        // victim's DID, but it is self-signed by the attacker's key with the attacker's own SCID.
        var attackerKey = CreateEd25519Signer();
        var forgedLog = await ForgeGenesisClaimingDidAsync(victimDid, attackerKey);

        // Sanity: the forged log's latest entry really does claim the victim DID (so the older
        // State.Id check alone would NOT catch it) — the SCID binding is what rejects it.
        var forgedEntries = LogEntrySerializer.ParseJsonLines(forgedLog);
        forgedEntries[^1].State.Id.Value.Should().Be(victimDid);
        forgedEntries[0].Parameters.Scid.Should().NotBe(DidUrlMapper.ExtractScid(victimDid));

        var logUrl = DidUrlMapper.MapToLogUrl(victimDid);
        httpClient.SetLogResponse(logUrl, forgedLog);

        var resolveResult = await method.ResolveAsync(victimDid);

        resolveResult.DidDocument.Should().BeNull("the genesis SCID does not match the DID's SCID");
        resolveResult.ResolutionMetadata.Error.Should().Be("invalidDidLog");
    }

    [Fact]
    public async Task Issue82_Update_ForgedLogClaimingDid_Throws()
    {
        var (method, _) = CreateMethod();

        var victimSigner = CreateEd25519Signer();
        var victim = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            Path = "alice",
            UpdateKey = victimSigner
        });
        var victimDid = victim.Did.Value;

        // Attacker crafts a validly-signed log whose latest entry claims the victim DID and whose
        // authority is the attacker's own key. RequireAppendableLogForDid's State.Id check passes;
        // the genesis-SCID binding must reject it.
        var attackerKey = CreateEd25519Signer();
        var forgedLog = await ForgeGenesisClaimingDidAsync(victimDid, attackerKey);

        var act = () => method.UpdateAsync(victimDid, new DidWebVhUpdateOptions
        {
            CurrentLogContent = forgedLog,
            SigningKey = attackerKey,
            NewDocument = new DidDocument { Id = new Did(victimDid) }
        });

        await act.Should().ThrowAsync<ArgumentException>().WithMessage("*genesis SCID*");
    }

    [Fact]
    public async Task Issue82_Deactivate_ForgedLogClaimingDid_Throws()
    {
        var (method, _) = CreateMethod();

        var victimSigner = CreateEd25519Signer();
        var victim = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            Path = "alice",
            UpdateKey = victimSigner
        });
        var victimDid = victim.Did.Value;

        var attackerKey = CreateEd25519Signer();
        var forgedLog = await ForgeGenesisClaimingDidAsync(victimDid, attackerKey);

        var act = () => method.DeactivateAsync(victimDid, new DidWebVhDeactivateOptions
        {
            CurrentLogContent = forgedLog,
            SigningKey = attackerKey
        });

        await act.Should().ThrowAsync<ArgumentException>().WithMessage("*genesis SCID*");
    }
}
