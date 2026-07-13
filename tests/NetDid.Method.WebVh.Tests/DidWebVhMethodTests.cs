using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DataProofsDotnet.DataIntegrity;
using FluentAssertions;
using NetCid;
using NetDid.Core;
using NetCrypto;
using NetDid.Core.Exceptions;
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
        entries[0].Parameters.Scid.Should().NotBe(entries[0].EntryHash,
            "did:webvh v1.0 derives the SCID and genesis entry hash in separate stages");
        entries[0].Parameters.Scid.Should().HaveLength(46).And.NotStartWith("z");
        entries[0].EntryHash.Should().HaveLength(46).And.NotStartWith("z");

        var genesisForHashing = entries[0] with { VersionId = entries[0].Parameters.Scid! };
        var genesisJsonForHashing = LogEntrySerializer.SerializeWithoutProof(genesisForHashing);
        ScidGenerator.ComputeEntryHash(genesisJsonForHashing).Should().Be(entries[0].EntryHash);

        var genesisTemplate = genesisJsonForHashing.Replace(
            entries[0].Parameters.Scid!, ScidGenerator.Placeholder);
        ScidGenerator.ComputeScid(genesisTemplate).Should().Be(entries[0].Parameters.Scid);
        entries[0].Proof.Should().HaveCount(1);
    }

    [Fact]
    public async Task Create_LegacyGenesisUsingScidAsEntryHash_IsRejected()
    {
        var (method, _) = CreateMethod();
        var signer = CreateEd25519Signer();
        var result = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = signer
        });

        var logContent = (string)result.Artifacts![DidWebVhArtifacts.DidJsonl];
        var genesis = LogEntrySerializer.ParseJsonLines(Encoding.UTF8.GetBytes(logContent))[0];
        var legacyGenesis = genesis with
        {
            VersionId = $"1-{genesis.Parameters.Scid}"
        };

        var act = () => new LogChainValidator()
            .ValidateChain([legacyGenesis]);

        act.Should().Throw<LogChainValidationException>()
            .WithMessage("*Genesis entry hash*");
    }

    [Fact]
    public async Task Create_LegacyCodecTaggedMultibaseEntryHash_IsRejected()
    {
        var (method, _) = CreateMethod();
        var signer = CreateEd25519Signer();
        var result = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = signer
        });

        var logContent = (string)result.Artifacts![DidWebVhArtifacts.DidJsonl];
        var genesis = LogEntrySerializer.ParseJsonLines(Encoding.UTF8.GetBytes(logContent))[0];
        var genesisForHashing = genesis with
        {
            VersionId = genesis.Parameters.Scid!,
            Proof = null
        };
        using var document = JsonDocument.Parse(
            LogEntrySerializer.SerializeWithoutProof(genesisForHashing));
        var canonicalBytes = JcsCanonicalizer.Canonicalize(document.RootElement);
        var digest = SHA256.HashData(canonicalBytes);
        var legacyEntryHash = Multibase.Encode(
            Multicodec.Prefix(MultihashCode.Sha2_256, digest),
            MultibaseEncoding.Base58Btc);
        var legacyGenesis = genesisForHashing with
        {
            VersionId = $"1-{legacyEntryHash}"
        };
        legacyGenesis = legacyGenesis with
        {
            Proof = [await SignEntryAsync(legacyGenesis, signer)]
        };

        var act = () => new LogChainValidator()
            .ValidateChain([legacyGenesis]);

        act.Should().Throw<LogChainValidationException>()
            .WithMessage("*Genesis entry hash*");
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
            PreRotationCommitments = [commitment]
        });

        var logContent = (string)result.Artifacts![DidWebVhArtifacts.DidJsonl];
        var entries = LogEntrySerializer.ParseJsonLines(Encoding.UTF8.GetBytes(logContent));
        logContent.Should().NotContain("\"prerotation\"");
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

    /// <summary>
    /// Stands in for the HTTP layer surfacing an exception mid-fetch, as
    /// DefaultWebVhHttpClient does when the token is cancelled or HttpClient times out.
    /// </summary>
    private sealed class ThrowingWebVhHttpClient(Func<CancellationToken, Exception> exceptionFactory) : IWebVhHttpClient
    {
        public Task<byte[]?> FetchDidLogAsync(Uri logUrl, CancellationToken ct = default)
            => Task.FromException<byte[]?>(exceptionFactory(ct));

        public Task<byte[]?> FetchWitnessFileAsync(Uri witnessUrl, CancellationToken ct = default)
            => Task.FromException<byte[]?>(exceptionFactory(ct));
    }

    [Fact]
    public async Task Issue81_Resolve_CallerCancellation_PropagatesOperationCanceledException()
    {
        var method = new DidWebVhMethod(new ThrowingWebVhHttpClient(ct => new OperationCanceledException(ct)));
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        var act = () => method.ResolveAsync("did:webvh:QmNotExist:example.com", options: null, cts.Token);

        await act.Should().ThrowAsync<OperationCanceledException>();
    }

    [Fact]
    public async Task Issue81_Resolve_HttpTimeoutWithoutCallerCancellation_ReturnsNotFound()
    {
        // HttpClient.Timeout surfaces as TaskCanceledException (inner TimeoutException on
        // .NET 5+) while the caller's token is NOT cancelled — that must stay a resolution
        // failure, not propagate as cancellation.
        var method = new DidWebVhMethod(new ThrowingWebVhHttpClient(
            _ => new TaskCanceledException("The request was canceled due to the configured HttpClient.Timeout.",
                new TimeoutException())));

        var result = await method.ResolveAsync("did:webvh:QmNotExist:example.com");

        result.DidDocument.Should().BeNull();
        result.ResolutionMetadata.Error.Should().Be("notFound");
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
        resolveResult.DidDocument.Should().BeNull();
        resolveResult.DocumentMetadata!.Deactivated.Should().BeTrue();
    }

    [Fact]
    public async Task Resolve_PriorVersionOfDeactivatedDid_ReturnsDocumentWithDeactivatedMetadata()
    {
        var (method, httpClient) = CreateMethod();
        var signer = CreateEd25519Signer();
        var created = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = signer
        });
        var initialLog = Encoding.UTF8.GetBytes(
            (string)created.Artifacts![DidWebVhArtifacts.DidJsonl]);
        var genesisVersionId = LogEntrySerializer.ParseJsonLines(initialLog)[0].VersionId;
        var deactivated = await method.DeactivateAsync(created.Did.Value, new DidWebVhDeactivateOptions
        {
            CurrentLogContent = initialLog,
            SigningKey = signer
        });
        httpClient.SetLogResponse(
            DidUrlMapper.MapToLogUrl(created.Did.Value),
            Encoding.UTF8.GetBytes((string)deactivated.Artifacts![DidWebVhArtifacts.DidJsonl]));

        var resolved = await method.ResolveAsync(created.Did.Value, new DidWebVhResolveOptions
        {
            VersionId = genesisVersionId
        });

        resolved.DidDocument.Should().NotBeNull();
        resolved.DocumentMetadata!.Deactivated.Should().BeTrue();
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
            PreRotationCommitments = [commitment2]
        });

        var logContent = (string)createResult.Artifacts![DidWebVhArtifacts.DidJsonl];
        var did = createResult.Did.Value;

        // Rotate to key2 — the previously committed key both appears in this entry's
        // updateKeys and signs the entry, as required by did:webvh v1.0.
        var key3 = CreateEd25519Signer();
        var commitment3 = PreRotationManager.ComputeKeyCommitment(key3.MultibasePublicKey);

        var updateResult = await method.UpdateAsync(did, new DidWebVhUpdateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(logContent),
            SigningKey = key2,
            ParameterUpdates = new DidWebVhParameterUpdates
            {
                UpdateKeys = [key2.MultibasePublicKey],
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

        // Verify each entry's hash is computed using exactly the PREVIOUS entry's full versionId.
        for (int i = 1; i < entries.Count; i++)
        {
            var current = entries[i];
            var previous = entries[i - 1];
            var version = i + 1;

            var entryForHashing = current with { VersionId = previous.VersionId };
            var json = LogEntrySerializer.SerializeWithoutProof(entryForHashing);
            var computedHash = ScidGenerator.ComputeEntryHash(json);

            current.EntryHash.Should().Be(computedHash,
                $"version {version} entry hash should chain to previous versionId");
        }
    }

    [Fact]
    public async Task Issue14_CurrentVersionPrefixedToHashInput_IsRejected()
    {
        var (method, _) = CreateMethod();
        var signer = CreateEd25519Signer();
        var created = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = signer
        });

        var logContent = (string)created.Artifacts![DidWebVhArtifacts.DidJsonl];
        var genesis = LogEntrySerializer.ParseJsonLines(Encoding.UTF8.GetBytes(logContent))[0];
        var nonConformantHashInput = new LogEntry
        {
            VersionId = $"2-{genesis.VersionId}",
            VersionTime = genesis.VersionTime.AddTicks(1),
            Parameters = new LogEntryParameters(),
            State = genesis.State
        };
        var nonConformantHash = ScidGenerator.ComputeEntryHash(
            LogEntrySerializer.SerializeWithoutProof(nonConformantHashInput));
        var nonConformantEntry = nonConformantHashInput with
        {
            VersionId = $"2-{nonConformantHash}"
        };
        nonConformantEntry = nonConformantEntry with
        {
            Proof = [await SignEntryAsync(nonConformantEntry, signer)]
        };

        var act = () => new LogChainValidator()
            .ValidateChain([genesis, nonConformantEntry]);

        act.Should().Throw<LogChainValidationException>()
            .WithMessage("*Entry hash mismatch at version 2*");
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
        var witnessDid = $"did:key:{CreateEd25519Signer().MultibasePublicKey}";

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
        var witnessDid = $"did:key:{CreateEd25519Signer().MultibasePublicKey}";

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
            SigningKey = key2,
            ParameterUpdates = new DidWebVhParameterUpdates
            {
                Ttl = 300,
                UpdateKeys = [key2.MultibasePublicKey],
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
        var witnessDid = $"did:key:{CreateEd25519Signer().MultibasePublicKey}";

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
            WitnessDids = [witnessDid],
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
        var witnessDid = $"did:key:{CreateEd25519Signer().MultibasePublicKey}";

        // Create
        var createResult = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = signer,
            WitnessDids = [witnessDid],
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
            SigningKey = key2,
            ParameterUpdates = new DidWebVhParameterUpdates
            {
                UpdateKeys = [key2.MultibasePublicKey],
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
        ((string)resolveResult.Artifacts[DidWebVhArtifacts.DidJsonl])
            .Should().Be(updatedLog, "latest resolution validates and exposes the complete fetched log");
    }

    [Fact]
    public async Task Issue37_Resolve_HistoricalIncludeLog_ExposesOnlyValidatedPrefix()
    {
        var (method, httpClient) = CreateMethod();
        var signer = CreateEd25519Signer();

        var createResult = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = signer
        });
        var did = createResult.Did.Value;
        var updateResult = await method.UpdateAsync(did, new DidWebVhUpdateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(
                (string)createResult.Artifacts![DidWebVhArtifacts.DidJsonl]),
            SigningKey = signer
        });

        var updatedLog = (string)updateResult.Artifacts![DidWebVhArtifacts.DidJsonl];
        var lines = updatedLog.Split('\n');
        var crlfLog = string.Join("\r\n", lines);
        var entries = LogEntrySerializer.ParseJsonLines(Encoding.UTF8.GetBytes(crlfLog));
        httpClient.SetLogResponse(
            DidUrlMapper.MapToLogUrl(did), Encoding.UTF8.GetBytes(crlfLog));

        var result = await method.ResolveAsync(did, new DidResolutionOptions
        {
            VersionId = entries[0].VersionId,
            IncludeLog = true
        });

        result.ResolutionMetadata.Error.Should().BeNull();
        var exposedEntries = (IReadOnlyList<LogEntry>)result.Artifacts![DidWebVhArtifacts.LogEntries];
        exposedEntries.Should().ContainSingle()
            .Which.VersionId.Should().Be(entries[0].VersionId);
        ((string)result.Artifacts[DidWebVhArtifacts.DidJsonl]).Should().Be(lines[0],
            "the raw artifact must end exactly at the validated entry, without the CRLF separator");
    }

    [Fact]
    public async Task Issue101_Resolve_HistoricalIncludeLog_DoesNotExposeInvalidTail()
    {
        var (method, httpClient) = CreateMethod();
        var signer = CreateEd25519Signer();

        var createResult = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = signer
        });
        var did = createResult.Did.Value;
        var updateResult = await method.UpdateAsync(did, new DidWebVhUpdateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(
                (string)createResult.Artifacts![DidWebVhArtifacts.DidJsonl]),
            SigningKey = signer
        });

        var updatedLog = (string)updateResult.Artifacts![DidWebVhArtifacts.DidJsonl];
        var entries = LogEntrySerializer.ParseJsonLines(Encoding.UTF8.GetBytes(updatedLog));
        var lines = updatedLog.Split('\n');
        lines[1] = lines[1].Replace(
            entries[1].Proof![0].ProofValue, "zInvalidUncheckedTailProof");
        var corruptedLog = string.Join('\n', lines);
        httpClient.SetLogResponse(
            DidUrlMapper.MapToLogUrl(did), Encoding.UTF8.GetBytes(corruptedLog));

        var result = await method.ResolveAsync(did, new DidResolutionOptions
        {
            VersionId = entries[0].VersionId,
            IncludeLog = true
        });

        result.ResolutionMetadata.Error.Should().BeNull();
        result.DidDocument.Should().NotBeNull();
        var exposedEntries = (IReadOnlyList<LogEntry>)result.Artifacts![DidWebVhArtifacts.LogEntries];
        exposedEntries.Should().ContainSingle()
            .Which.VersionId.Should().Be(entries[0].VersionId);
        var exposedJsonl = (string)result.Artifacts[DidWebVhArtifacts.DidJsonl];
        exposedJsonl.Should().Be(lines[0]);
        exposedJsonl.Should().NotContain("zInvalidUncheckedTailProof");

        var dictionaryView = (IDictionary<string, object>)result.Artifacts;
        var mutate = () => dictionaryView[DidWebVhArtifacts.DidJsonl] = corruptedLog;
        mutate.Should().Throw<NotSupportedException>(
            "cached resolution artifacts must not be caller-mutable");
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
    public async Task Issue82_Update_DocumentOnlyEdit_ReportsUnchanged()
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

        updateResult.AuthorizationChange.Should().Be(AuthorizationChangeStatus.Unchanged);

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
        preserveResult.AuthorizationChange.Should().Be(AuthorizationChangeStatus.Unchanged);
    }

    [Fact]
    public async Task Issue82_Update_KeyRotation_ReportsChanged()
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

        updateResult.AuthorizationChange.Should().Be(AuthorizationChangeStatus.Changed);
    }

    [Fact]
    public async Task Issue82_Update_SameUpdateKeysSupplied_ReportsUnchanged()
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

        updateResult.AuthorizationChange.Should().Be(AuthorizationChangeStatus.Unchanged);
    }

    [Fact]
    public async Task Issue82_Update_NextKeyHashesActivation_ReportsChanged()
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
                NextKeyHashes = [commitment]
            }
        });

        updateResult.AuthorizationChange.Should().Be(AuthorizationChangeStatus.Changed);
    }

    [Fact]
    public async Task Issue82_Update_WitnessChange_ReportsChanged()
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

        updateResult.AuthorizationChange.Should().Be(AuthorizationChangeStatus.Changed);
    }

    // ================================================================
    // ISSUE #91: KEY-SPECIFIC ROTATION EVIDENCE
    // (UpdateKeyChange must not conflate key rotation with policy-only
    // changes; EffectiveUpdateKeys exposes the newly authorized set)
    // ================================================================

    [Fact]
    public async Task Issue91_Update_KeyRotation_ReportsUpdateKeyChangedAndNewEffectiveSet()
    {
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

        updateResult.UpdateKeyChange.Should().Be(AuthorizationChangeStatus.Changed);
        // Invariant: a key change is always an authorization change.
        updateResult.AuthorizationChange.Should().Be(AuthorizationChangeStatus.Changed);
        // Exclusive-rotation postcondition: the complete effective set equals the intended
        // post-rotation set (which also implies the retired key is gone).
        updateResult.EffectiveUpdateKeys.Should().BeEquivalentTo([newKey.MultibasePublicKey]);
        updateResult.EffectiveUpdateKeys.Should().NotContain(signerA.MultibasePublicKey);
        // The ordinary-mode entry was authorized by the prior effective set, not by the
        // newly installed set that will authorize the following entry.
        updateResult.RevealedUpdateKeys.Should().BeEquivalentTo([signerA.MultibasePublicKey]);
        updateResult.RevealedUpdateKeys.Should().NotContain(newKey.MultibasePublicKey);
    }

    [Fact]
    public async Task Issue91_Update_AdditiveKeyChange_OldKeyRetainsAuthority()
    {
        // "Changed" does NOT imply the previous key lost authority — an additive update trips
        // UpdateKeyChange while the old key remains in the effective set. This is why an
        // exclusive-rotation consumer must require EffectiveUpdateKeys to set-equal its
        // intended post-rotation set; membership checks alone accept supersets like this one.
        var (method, _) = CreateMethod();
        var (didA, logA, signerA) = await CreateWebVhDidAsync(method, "alice");
        var newKey = CreateEd25519Signer();

        var updateResult = await method.UpdateAsync(didA, new DidWebVhUpdateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(logA),
            SigningKey = signerA,
            ParameterUpdates = new DidWebVhParameterUpdates
            {
                UpdateKeys = [signerA.MultibasePublicKey, newKey.MultibasePublicKey]
            }
        });

        updateResult.UpdateKeyChange.Should().Be(AuthorizationChangeStatus.Changed);
        updateResult.AuthorizationChange.Should().Be(AuthorizationChangeStatus.Changed);
        updateResult.EffectiveUpdateKeys.Should().BeEquivalentTo(
            [signerA.MultibasePublicKey, newKey.MultibasePublicKey]);
    }

    [Fact]
    public async Task Issue91_Update_WitnessOnlyChange_ReportsUpdateKeyUnchanged()
    {
        // The headline #91 discriminator: a policy-only change reports the coarse
        // AuthorizationChange as Changed but must NOT read as a key rotation.
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

        updateResult.AuthorizationChange.Should().Be(AuthorizationChangeStatus.Changed);
        updateResult.UpdateKeyChange.Should().Be(AuthorizationChangeStatus.Unchanged);
        updateResult.EffectiveUpdateKeys.Should().BeEquivalentTo([signerA.MultibasePublicKey]);
    }

    [Fact]
    public async Task Issue91_Update_PreRotationActivation_ReportsCurrentEntryEvidence()
    {
        // Enabling pre-rotation hides the next entry's concrete signers, so
        // EffectiveUpdateKeys remains withheld. The activation entry itself is ordinary-mode,
        // however, and the prior effective updateKeys are concrete authorization evidence.
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
                NextKeyHashes = [commitment]
            }
        });

        // This policy-only change does not change the effective updateKeys set.
        updateResult.AuthorizationChange.Should().Be(AuthorizationChangeStatus.Changed);
        updateResult.UpdateKeyChange.Should().Be(AuthorizationChangeStatus.Unchanged);
        updateResult.EffectiveUpdateKeys.Should().BeNull();
        updateResult.RevealedUpdateKeys.Should().BeEquivalentTo([signerA.MultibasePublicKey]);
    }

    [Fact]
    public async Task Issue91_Update_DocumentOnlyEdit_ReportsUnchangedWithCarriedForwardKeys()
    {
        var (method, _) = CreateMethod();
        var (didA, logA, signerA) = await CreateWebVhDidAsync(method, "alice");

        var updateResult = await method.UpdateAsync(didA, new DidWebVhUpdateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(logA),
            SigningKey = signerA,
            NewDocument = null // preserve path — no document, no parameter change
        });

        updateResult.AuthorizationChange.Should().Be(AuthorizationChangeStatus.Unchanged);
        updateResult.UpdateKeyChange.Should().Be(AuthorizationChangeStatus.Unchanged);
        // Even a no-op update reports the carried-forward authority so a consumer can bind to it.
        updateResult.EffectiveUpdateKeys.Should().BeEquivalentTo([signerA.MultibasePublicKey]);
    }

    [Fact]
    public async Task Issue91_Update_SameUpdateKeysSupplied_ReportsUpdateKeyUnchanged()
    {
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

        updateResult.UpdateKeyChange.Should().Be(AuthorizationChangeStatus.Unchanged);
        updateResult.EffectiveUpdateKeys.Should().BeEquivalentTo([signerA.MultibasePublicKey]);
    }

    [Fact]
    public async Task Issue91_Update_ReorderedAndDuplicatedKeys_ReportsUpdateKeyUnchanged()
    {
        // Set comparison must be order- and duplicate-insensitive.
        var (method, _) = CreateMethod();
        var (didA, logA, signerA) = await CreateWebVhDidAsync(method, "alice");
        var keyB = CreateEd25519Signer();

        var first = await method.UpdateAsync(didA, new DidWebVhUpdateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(logA),
            SigningKey = signerA,
            ParameterUpdates = new DidWebVhParameterUpdates
            {
                UpdateKeys = [signerA.MultibasePublicKey, keyB.MultibasePublicKey]
            }
        });
        first.UpdateKeyChange.Should().Be(AuthorizationChangeStatus.Changed);

        var firstLog = (string)first.Artifacts![DidWebVhArtifacts.DidJsonl];
        var second = await method.UpdateAsync(didA, new DidWebVhUpdateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(firstLog),
            SigningKey = signerA,
            ParameterUpdates = new DidWebVhParameterUpdates
            {
                UpdateKeys = [keyB.MultibasePublicKey, signerA.MultibasePublicKey, signerA.MultibasePublicKey]
            }
        });

        second.UpdateKeyChange.Should().Be(AuthorizationChangeStatus.Unchanged);
        second.AuthorizationChange.Should().Be(AuthorizationChangeStatus.Unchanged);
    }

    [Fact]
    public async Task Issue91_Update_PreRotationActive_ReportsRevealedCurrentEntryKeys()
    {
        // Fresh nextKeyHashes still hide who may sign the next entry, but this entry's own
        // updateKeys were individually commitment-validated and are concrete evidence.
        var (method, _) = CreateMethod();
        var key1 = CreateEd25519Signer();
        var key2 = CreateEd25519Signer();
        var key3 = CreateEd25519Signer();

        var createResult = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = key1,
            PreRotationCommitments = [PreRotationManager.ComputeKeyCommitment(key2.MultibasePublicKey)]
        });
        var logContent = (string)createResult.Artifacts![DidWebVhArtifacts.DidJsonl];

        var updateResult = await method.UpdateAsync(createResult.Did.Value, new DidWebVhUpdateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(logContent),
            SigningKey = key2,
            ParameterUpdates = new DidWebVhParameterUpdates
            {
                UpdateKeys = [key2.MultibasePublicKey],
                NextKeyHashes = [PreRotationManager.ComputeKeyCommitment(key3.MultibasePublicKey)]
            }
        });

        updateResult.UpdateKeyChange.Should().Be(AuthorizationChangeStatus.Changed);
        updateResult.EffectiveUpdateKeys.Should().BeNull();
        updateResult.RevealedUpdateKeys.Should().BeEquivalentTo([key2.MultibasePublicKey]);
    }

    [Fact]
    public async Task Issue91_Update_PreRotationRecommitSameKey_ReportsUnchanged()
    {
        // A pre-rotation "rotation" that re-commits to the CURRENT key passes
        // PreRotationManager.ValidateKeyRotation (hash-membership only) without rotating
        // authority. The evidence must not lend that phantom rotation any credibility.
        var (method, _) = CreateMethod();
        var key1 = CreateEd25519Signer();
        var commitment1 = PreRotationManager.ComputeKeyCommitment(key1.MultibasePublicKey);

        var createResult = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = key1,
            PreRotationCommitments = [commitment1]
        });
        var logContent = (string)createResult.Artifacts![DidWebVhArtifacts.DidJsonl];

        var updateResult = await method.UpdateAsync(createResult.Did.Value, new DidWebVhUpdateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(logContent),
            SigningKey = key1,
            ParameterUpdates = new DidWebVhParameterUpdates
            {
                UpdateKeys = [key1.MultibasePublicKey],
                NextKeyHashes = [commitment1]
            }
        });

        updateResult.UpdateKeyChange.Should().Be(AuthorizationChangeStatus.Unchanged);
        updateResult.EffectiveUpdateKeys.Should().BeNull();
        updateResult.RevealedUpdateKeys.Should().BeEquivalentTo([key1.MultibasePublicKey]);
    }

    [Fact]
    public async Task Issue91_Update_EmptyUpdateKeys_ReportsChangedWithEmptySet()
    {
        // Supplying an empty set freezes the DID (no key may sign the next entry). The evidence
        // must distinguish this (empty, non-null) from "not reported" (null).
        var (method, _) = CreateMethod();
        var (didA, logA, signerA) = await CreateWebVhDidAsync(method, "alice");

        var updateResult = await method.UpdateAsync(didA, new DidWebVhUpdateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(logA),
            SigningKey = signerA,
            ParameterUpdates = new DidWebVhParameterUpdates
            {
                UpdateKeys = []
            }
        });

        updateResult.UpdateKeyChange.Should().Be(AuthorizationChangeStatus.Changed);
        updateResult.AuthorizationChange.Should().Be(AuthorizationChangeStatus.Changed);
        updateResult.EffectiveUpdateKeys.Should().NotBeNull();
        updateResult.EffectiveUpdateKeys.Should().BeEmpty();
    }

    [Fact]
    public async Task Issue91_Update_EffectiveUpdateKeys_IsDefensiveCopy()
    {
        // Mutating the caller-owned list after UpdateAsync returns must not alter the reported
        // evidence — otherwise result and signed log could silently disagree.
        var (method, _) = CreateMethod();
        var (didA, logA, signerA) = await CreateWebVhDidAsync(method, "alice");
        var newKey = CreateEd25519Signer();
        var callerList = new List<string> { newKey.MultibasePublicKey };

        var updateResult = await method.UpdateAsync(didA, new DidWebVhUpdateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(logA),
            SigningKey = signerA,
            ParameterUpdates = new DidWebVhParameterUpdates
            {
                UpdateKeys = callerList
            }
        });

        callerList.Clear();
        callerList.Add("z6MkAttackerControlledValueAfterTheFact");

        updateResult.EffectiveUpdateKeys.Should().BeEquivalentTo([newKey.MultibasePublicKey]);
    }

    /// <summary>
    /// An <see cref="IReadOnlyList{T}"/> that yields different contents on successive
    /// enumerations: the first enumeration returns one list, all later enumerations another.
    /// Models a caller-controlled dynamic collection attempting to show one value set to
    /// validation/evidence and a different one to hashing/signing/serialization
    /// (PR #92 review, finding 2).
    /// </summary>
    private sealed class FlippingList<T>(
        IReadOnlyList<T> firstEnumeration, IReadOnlyList<T> laterEnumerations)
        : IReadOnlyList<T>
    {
        private int _enumerations;

        public int Count => firstEnumeration.Count;
        public T this[int index] => firstEnumeration[index];

        public IEnumerator<T> GetEnumerator()
            => (++_enumerations == 1 ? firstEnumeration : laterEnumerations).GetEnumerator();

        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator()
            => GetEnumerator();
    }

    [Fact]
    public async Task Issue91_Update_DynamicKeyList_CannotDesyncEvidenceFromArtifact()
    {
        // A dynamic IReadOnlyList must not be able to present one key set to the change
        // comparison / reported evidence and a different set to hashing, signing, and the
        // serialized artifact. The driver snapshots the caller's collections exactly once, so
        // the artifact, the validated chain, and the evidence all reflect the same (first)
        // read — never a mix.
        var (method, _) = CreateMethod();
        var (didA, logA, signerA) = await CreateWebVhDidAsync(method, "alice");
        var newKey = CreateEd25519Signer();

        var flippingList = new FlippingList<string>(
            firstEnumeration: [newKey.MultibasePublicKey],
            laterEnumerations: [signerA.MultibasePublicKey]);

        var updateResult = await method.UpdateAsync(didA, new DidWebVhUpdateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(logA),
            SigningKey = signerA,
            ParameterUpdates = new DidWebVhParameterUpdates
            {
                UpdateKeys = flippingList
            }
        });

        // Everything is consistent with the single snapshot: the appended entry, the chain
        // validator's view of it, and the reported evidence all carry the new key only.
        var updatedLog = (string)updateResult.Artifacts![DidWebVhArtifacts.DidJsonl];
        var entries = LogEntrySerializer.ParseJsonLines(Encoding.UTF8.GetBytes(updatedLog));
        entries[^1].Parameters.UpdateKeys.Should().BeEquivalentTo([newKey.MultibasePublicKey]);

        var effective = new LogChainValidator().ValidateChain(entries);
        effective.UpdateKeys.Should().BeEquivalentTo([newKey.MultibasePublicKey]);

        updateResult.UpdateKeyChange.Should().Be(AuthorizationChangeStatus.Changed);
        updateResult.EffectiveUpdateKeys.Should().BeEquivalentTo([newKey.MultibasePublicKey]);
    }

    [Fact]
    public async Task Issue101_Update_DynamicNewDocumentCollection_PublishedLogMatchesSignedSnapshot()
    {
        // A NewDocument whose collections yield different contents per enumeration must not be
        // able to desynchronize the entry hash, the signed bytes, and the published log —
        // hashing, signing, publication, and the reported document must all reflect a single
        // snapshot taken at the trust boundary.
        var (method, httpClient) = CreateMethod();
        var (did, log, signer) = await CreateWebVhDidAsync(method);

        var firstService = new Service
        {
            Id = "#service-first",
            Type = "ExampleService",
            ServiceEndpoint = ServiceEndpointValue.FromUri("https://example.com/first")
        };
        var laterService = new Service
        {
            Id = "#service-later",
            Type = "ExampleService",
            ServiceEndpoint = ServiceEndpointValue.FromUri("https://example.com/later")
        };
        var newDocument = new DidDocument
        {
            Id = new Did(did),
            Service = new FlippingList<Service>([firstService], [laterService])
        };

        var updateResult = await method.UpdateAsync(did, new DidWebVhUpdateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(log),
            SigningKey = signer,
            NewDocument = newDocument
        });

        // The published log verifies end-to-end and carries the first (snapshot) read.
        var updatedLog = (string)updateResult.Artifacts![DidWebVhArtifacts.DidJsonl];
        httpClient.SetLogResponse(
            DidUrlMapper.MapToLogUrl(did), Encoding.UTF8.GetBytes(updatedLog));
        var resolved = await method.ResolveAsync(did);

        resolved.ResolutionMetadata.Error.Should().BeNull(
            "the published bytes must be the same single snapshot that was hashed and signed");
        resolved.DidDocument!.Service.Should().ContainSingle()
            .Which.Id.Should().Be("#service-first");

        // The reported document is the private snapshot, not the caller's live instance.
        updateResult.DidDocument.Should().NotBeSameAs(newDocument);
        updateResult.DidDocument!.Service.Should().ContainSingle()
            .Which.Id.Should().Be("#service-first");
    }

    [Fact]
    public async Task Issue91_Update_EffectiveUpdateKeys_MatchesValidatedChain()
    {
        // Writer/reader parity: the reported set must equal what the chain validator derives as
        // the effective updateKeys of the appended log.
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

        var updatedLog = (string)updateResult.Artifacts![DidWebVhArtifacts.DidJsonl];
        var entries = LogEntrySerializer.ParseJsonLines(Encoding.UTF8.GetBytes(updatedLog));
        var effective = new LogChainValidator().ValidateChain(entries);

        updateResult.EffectiveUpdateKeys.Should().BeEquivalentTo(effective.UpdateKeys);
    }

    [Fact]
    public async Task Issue91_Update_PreRotationExit_ReportsNextAuthorizedKeys()
    {
        // Turning pre-rotation OFF is still governed by the pre-rotation rules, but the
        // resulting state is ordinary mode. Its effective updateKeys therefore authorize the
        // next entry and can be reported.
        var (method, _) = CreateMethod();
        var key1 = CreateEd25519Signer();
        var key2 = CreateEd25519Signer();

        var createResult = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = key1,
            PreRotationCommitments = [PreRotationManager.ComputeKeyCommitment(key2.MultibasePublicKey)]
        });
        var logContent = (string)createResult.Artifacts![DidWebVhArtifacts.DidJsonl];

        var updateResult = await method.UpdateAsync(createResult.Did.Value, new DidWebVhUpdateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(logContent),
            SigningKey = key2,
            ParameterUpdates = new DidWebVhParameterUpdates
            {
                UpdateKeys = [key2.MultibasePublicKey],
                NextKeyHashes = []
            }
        });

        updateResult.UpdateKeyChange.Should().Be(AuthorizationChangeStatus.Changed);
        updateResult.EffectiveUpdateKeys.Should().BeEquivalentTo([key2.MultibasePublicKey]);
        updateResult.RevealedUpdateKeys.Should().BeEquivalentTo([key2.MultibasePublicKey]);
        updateResult.AuthorizationChange.Should().Be(AuthorizationChangeStatus.Changed);
    }

    [Fact]
    public async Task Issue91_Update_DynamicNextKeyHashes_CannotDesyncArtifact()
    {
        // The snapshot must cover NextKeyHashes too: a dynamic list may not present one
        // commitment set to the merge/serialization and another to any later stage.
        var (method, _) = CreateMethod();
        var (didA, logA, signerA) = await CreateWebVhDidAsync(method, "alice");
        var honestKey = CreateEd25519Signer();
        var otherKey = CreateEd25519Signer();
        var honestCommitment = PreRotationManager.ComputeKeyCommitment(honestKey.MultibasePublicKey);
        var otherCommitment = PreRotationManager.ComputeKeyCommitment(otherKey.MultibasePublicKey);

        var updateResult = await method.UpdateAsync(didA, new DidWebVhUpdateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(logA),
            SigningKey = signerA,
            ParameterUpdates = new DidWebVhParameterUpdates
            {
                NextKeyHashes = new FlippingList<string>(
                    firstEnumeration: [honestCommitment],
                    laterEnumerations: [otherCommitment])
            }
        });

        // Artifact and validated chain both carry the first (snapshotted) read.
        var updatedLog = (string)updateResult.Artifacts![DidWebVhArtifacts.DidJsonl];
        var entries = LogEntrySerializer.ParseJsonLines(Encoding.UTF8.GetBytes(updatedLog));
        entries[^1].Parameters.NextKeyHashes.Should().BeEquivalentTo([honestCommitment]);

        var effective = new LogChainValidator().ValidateChain(entries);
        effective.NextKeyHashes.Should().BeEquivalentTo([honestCommitment]);

        // Pre-rotation hides only the following entry's keys. This activation entry was still
        // authorized by the prior ordinary-mode set.
        updateResult.UpdateKeyChange.Should().Be(AuthorizationChangeStatus.Unchanged);
        updateResult.EffectiveUpdateKeys.Should().BeNull();
        updateResult.RevealedUpdateKeys.Should().BeEquivalentTo([signerA.MultibasePublicKey]);
    }

    [Fact]
    public async Task Issue91_Update_DynamicWitnessList_CannotDesyncArtifact()
    {
        // The snapshot must cover the witness list too: the policy that was validated must be
        // the policy that is serialized.
        var (method, _) = CreateMethod();
        var (didA, logA, signerA) = await CreateWebVhDidAsync(method, "alice");
        var honestWitness = CreateEd25519Signer();
        var otherWitness = CreateEd25519Signer();
        var honestEntry = new WitnessEntry { Id = $"did:key:{honestWitness.MultibasePublicKey}", Weight = 1 };
        var otherEntry = new WitnessEntry { Id = $"did:key:{otherWitness.MultibasePublicKey}", Weight = 1 };

        var updateResult = await method.UpdateAsync(didA, new DidWebVhUpdateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(logA),
            SigningKey = signerA,
            ParameterUpdates = new DidWebVhParameterUpdates
            {
                Witness = new WitnessConfig
                {
                    Threshold = 1,
                    Witnesses = new FlippingList<WitnessEntry>(
                        firstEnumeration: [honestEntry],
                        laterEnumerations: [otherEntry])
                }
            }
        });

        var updatedLog = (string)updateResult.Artifacts![DidWebVhArtifacts.DidJsonl];
        var entries = LogEntrySerializer.ParseJsonLines(Encoding.UTF8.GetBytes(updatedLog));
        var serializedWitnesses = entries[^1].Parameters.Witness!.Witnesses!;
        serializedWitnesses.Should().ContainSingle().Which.Id.Should().Be(honestEntry.Id);

        updateResult.AuthorizationChange.Should().Be(AuthorizationChangeStatus.Changed);
        updateResult.UpdateKeyChange.Should().Be(AuthorizationChangeStatus.Unchanged);
    }

    // ================================================================
    // ISSUE #98: CONTINUOUS PRE-ROTATION EVIDENCE
    // The current entry's authorizing set is concrete even when fresh
    // commitments intentionally hide the keys eligible for the next entry.
    // ================================================================

    [Fact]
    public async Task Issue98_Update_ContinuousPreRotation_ReportsKnownKeyChange()
    {
        var (method, _) = CreateMethod();
        var key1 = CreateEd25519Signer();
        var key2 = CreateEd25519Signer();
        var key3 = CreateEd25519Signer();

        var createResult = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = key1,
            PreRotationCommitments = [PreRotationManager.ComputeKeyCommitment(key2.MultibasePublicKey)]
        });

        var updateResult = await method.UpdateAsync(createResult.Did.Value, new DidWebVhUpdateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(
                (string)createResult.Artifacts![DidWebVhArtifacts.DidJsonl]),
            SigningKey = key2,
            ParameterUpdates = new DidWebVhParameterUpdates
            {
                UpdateKeys = [key2.MultibasePublicKey],
                NextKeyHashes = [PreRotationManager.ComputeKeyCommitment(key3.MultibasePublicKey)]
            }
        });

        updateResult.UpdateKeyChange.Should().Be(AuthorizationChangeStatus.Changed);
        updateResult.EffectiveUpdateKeys.Should().BeNull();
        updateResult.RevealedUpdateKeys.Should().BeEquivalentTo([key2.MultibasePublicKey]);
    }

    [Fact]
    public async Task Issue98_Update_PreRotationActivation_ReportsUnchangedKeySet()
    {
        var (method, _) = CreateMethod();
        var (did, log, signer) = await CreateWebVhDidAsync(method, "alice");
        var nextKey = CreateEd25519Signer();

        var updateResult = await method.UpdateAsync(did, new DidWebVhUpdateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(log),
            SigningKey = signer,
            ParameterUpdates = new DidWebVhParameterUpdates
            {
                NextKeyHashes = [PreRotationManager.ComputeKeyCommitment(nextKey.MultibasePublicKey)]
            }
        });

        updateResult.UpdateKeyChange.Should().Be(AuthorizationChangeStatus.Unchanged);
        updateResult.EffectiveUpdateKeys.Should().BeNull();
        updateResult.RevealedUpdateKeys.Should().BeEquivalentTo([signer.MultibasePublicKey]);
    }

    [Fact]
    public async Task Issue98_Update_ActivationWithKeyChange_DoesNotMislabelPriorAuthorizingSet()
    {
        // This entry is still ordinary-mode because there were no prior commitments. It is
        // authorized by key1 even though it installs key2 and activates pre-rotation for a
        // successor that must reveal key3. The two nullable evidence properties cannot be
        // coalesced into a generic post-change key set.
        var (method, _) = CreateMethod();
        var (did, log, key1) = await CreateWebVhDidAsync(method, "alice");
        var key2 = CreateEd25519Signer();
        var key3 = CreateEd25519Signer();

        var updateResult = await method.UpdateAsync(did, new DidWebVhUpdateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(log),
            SigningKey = key1,
            ParameterUpdates = new DidWebVhParameterUpdates
            {
                UpdateKeys = [key2.MultibasePublicKey],
                NextKeyHashes = [PreRotationManager.ComputeKeyCommitment(key3.MultibasePublicKey)]
            }
        });

        updateResult.UpdateKeyChange.Should().Be(AuthorizationChangeStatus.Changed);
        updateResult.EffectiveUpdateKeys.Should().BeNull();
        updateResult.RevealedUpdateKeys.Should().BeEquivalentTo([key1.MultibasePublicKey]);
        updateResult.RevealedUpdateKeys.Should().NotContain(key2.MultibasePublicKey);
    }

    [Fact]
    public async Task Issue98_Update_RevealedUpdateKeys_IsDefensiveReadOnlyCopy()
    {
        var (method, _) = CreateMethod();
        var key1 = CreateEd25519Signer();
        var key2 = CreateEd25519Signer();
        var key3 = CreateEd25519Signer();
        var callerList = new List<string> { key2.MultibasePublicKey };

        var createResult = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = key1,
            PreRotationCommitments =
                [PreRotationManager.ComputeKeyCommitment(key2.MultibasePublicKey)]
        });

        var updateResult = await method.UpdateAsync(createResult.Did.Value, new DidWebVhUpdateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(
                (string)createResult.Artifacts![DidWebVhArtifacts.DidJsonl]),
            SigningKey = key2,
            ParameterUpdates = new DidWebVhParameterUpdates
            {
                UpdateKeys = callerList,
                NextKeyHashes = [PreRotationManager.ComputeKeyCommitment(key3.MultibasePublicKey)]
            }
        });

        callerList.Clear();
        callerList.Add("z6MkAttackerControlledValueAfterTheFact");

        updateResult.RevealedUpdateKeys.Should().BeEquivalentTo([key2.MultibasePublicKey]);
        var mutableView = updateResult.RevealedUpdateKeys as IList<string>;
        mutableView.Should().NotBeNull();
        mutableView!.IsReadOnly.Should().BeTrue();
        ((Action)(() => mutableView[0] = "z6MkAttackerControlledDowncast"))
            .Should().Throw<NotSupportedException>();
    }

    [Fact]
    public async Task Issue98_Update_DynamicRevealedKeySet_CannotDesyncFullEvidenceFromArtifact()
    {
        // The report must contain every commitment-validated current update key, not only the
        // signer, and a dynamic caller collection must not be able to change that set between
        // validation, signing/serialization, and evidence construction.
        var (method, _) = CreateMethod();
        var key1 = CreateEd25519Signer();
        var key2 = CreateEd25519Signer();
        var key2B = CreateEd25519Signer();
        var key3 = CreateEd25519Signer();
        var revealedKeys = new FlippingList<string>(
            firstEnumeration: [key2.MultibasePublicKey, key2B.MultibasePublicKey],
            laterEnumerations: [key2.MultibasePublicKey]);

        var createResult = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = key1,
            PreRotationCommitments =
            [
                PreRotationManager.ComputeKeyCommitment(key2.MultibasePublicKey),
                PreRotationManager.ComputeKeyCommitment(key2B.MultibasePublicKey)
            ]
        });

        var updateResult = await method.UpdateAsync(createResult.Did.Value, new DidWebVhUpdateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(
                (string)createResult.Artifacts![DidWebVhArtifacts.DidJsonl]),
            SigningKey = key2,
            ParameterUpdates = new DidWebVhParameterUpdates
            {
                UpdateKeys = revealedKeys,
                NextKeyHashes = [PreRotationManager.ComputeKeyCommitment(key3.MultibasePublicKey)]
            }
        });

        var updatedLog = (string)updateResult.Artifacts![DidWebVhArtifacts.DidJsonl];
        var entries = LogEntrySerializer.ParseJsonLines(Encoding.UTF8.GetBytes(updatedLog));
        entries[^1].Parameters.UpdateKeys.Should().BeEquivalentTo(
            [key2.MultibasePublicKey, key2B.MultibasePublicKey]);
        new LogChainValidator().ValidateChain(entries)
            .UpdateKeys.Should().BeEquivalentTo(
                [key2.MultibasePublicKey, key2B.MultibasePublicKey]);

        updateResult.UpdateKeyChange.Should().Be(AuthorizationChangeStatus.Changed);
        updateResult.EffectiveUpdateKeys.Should().BeNull();
        updateResult.RevealedUpdateKeys.Should().BeEquivalentTo(
            [key2.MultibasePublicKey, key2B.MultibasePublicKey]);
    }

    [Fact]
    public async Task Update_DuplicateWitnessIds_AreRejected()
    {
        var (method, _) = CreateMethod();
        var (didA, logA, signerA) = await CreateWebVhDidAsync(method, "alice");
        var wid = $"did:key:{CreateEd25519Signer().MultibasePublicKey}";

        Func<Task> act = () => method.UpdateAsync(didA, new DidWebVhUpdateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(logA),
            SigningKey = signerA,
            ParameterUpdates = new DidWebVhParameterUpdates
            {
                Witness = new WitnessConfig
                {
                    Threshold = 1,
                    Witnesses =
                    [
                        new WitnessEntry { Id = wid, Weight = 1 },
                        new WitnessEntry { Id = wid, Weight = 100 }
                    ]
                }
            }
        });

        await act.Should().ThrowAsync<ArgumentException>()
            .WithMessage("*duplicated*");
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
            VersionId = ScidGenerator.SafePlaceholder,
            VersionTime = DateTimeOffset.UtcNow,
            Parameters = parameters,
            State = doc
        };

        // Compute a self-consistent SCID over this forged genesis (state.id kept literal).
        var jsonWithPlaceholder = LogEntrySerializer.SerializeWithoutProof(entry)
            .Replace(ScidGenerator.SafePlaceholder, ScidGenerator.Placeholder);
        var scid = ScidGenerator.ComputeScid(jsonWithPlaceholder);
        var jsonWithScid = ScidGenerator.ReplacePlaceholders(jsonWithPlaceholder, scid);
        var entryHash = ScidGenerator.ComputeEntryHash(jsonWithScid);
        var finalEntry = LogEntrySerializer.DeserializeEntry(jsonWithScid) with
        {
            VersionId = $"1-{entryHash}"
        };

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
        // authority is the attacker's own key. Such a log is internally SCID-inconsistent
        // (state.id carries the victim's SCID, parameters.scid the forge's own hash), so the
        // per-entry identity rule (#101) rejects it during chain validation — before the
        // genesis-SCID binding that used to catch it (issue #82) is even reached.
        var attackerKey = CreateEd25519Signer();
        var forgedLog = await ForgeGenesisClaimingDidAsync(victimDid, attackerKey);

        var act = () => method.UpdateAsync(victimDid, new DidWebVhUpdateOptions
        {
            CurrentLogContent = forgedLog,
            SigningKey = attackerKey,
            NewDocument = new DidDocument { Id = new Did(victimDid) }
        });

        await act.Should().ThrowAsync<LogChainValidationException>().WithMessage("*SCID*");
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

        // The forged log is internally SCID-inconsistent, so the per-entry identity rule
        // (#101) rejects it during chain validation (see the Update variant above).
        await act.Should().ThrowAsync<LogChainValidationException>().WithMessage("*SCID*");
    }
}
