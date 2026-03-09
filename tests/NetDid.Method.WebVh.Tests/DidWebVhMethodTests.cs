using FluentAssertions;
using NetDid.Core;
using NetDid.Core.Crypto;
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
        var method = new DidWebVhMethod(httpClient, _crypto);
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
        result.Artifacts.Should().ContainKey("did.jsonl");
        result.Artifacts.Should().ContainKey("did.json");
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

        var logContent = (byte[])result.Artifacts!["did.jsonl"];
        logContent.Should().NotBeEmpty();

        // Parse the generated log
        var entries = LogEntrySerializer.ParseJsonLines(logContent);
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

        var logContent = (byte[])result.Artifacts!["did.jsonl"];
        var entries = LogEntrySerializer.ParseJsonLines(logContent);
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
        var logContent = (byte[])createResult.Artifacts!["did.jsonl"];
        var logUrl = DidUrlMapper.MapToLogUrl(createResult.Did.Value);
        httpClient.SetLogResponse(logUrl, logContent);

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

        var logContent = (byte[])createResult.Artifacts!["did.jsonl"];
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
            CurrentLogContent = logContent,
            SigningKey = signer,
            NewDocument = updatedDoc
        });

        updateResult.DidDocument.Service.Should().HaveCount(1);
        updateResult.DidDocument.Service![0].Type.Should().Be("TurtleShellPds");
        updateResult.Artifacts.Should().ContainKey("did.jsonl");

        // Verify the updated log has 2 entries
        var updatedLog = (byte[])updateResult.Artifacts!["did.jsonl"];
        var entries = LogEntrySerializer.ParseJsonLines(updatedLog);
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

        var logContent = (byte[])createResult.Artifacts!["did.jsonl"];
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
            CurrentLogContent = logContent,
            SigningKey = signer,
            NewDocument = updatedDoc
        });

        var updatedLog = (byte[])updateResult.Artifacts!["did.jsonl"];

        // Resolve
        var logUrl = DidUrlMapper.MapToLogUrl(did);
        httpClient.SetLogResponse(logUrl, updatedLog);

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

        var logContent = (byte[])createResult.Artifacts!["did.jsonl"];
        var did = createResult.Did.Value;

        // Rotate to a new key
        var newKey = CreateEd25519Signer();

        var updateResult = await method.UpdateAsync(did, new DidWebVhUpdateOptions
        {
            CurrentLogContent = logContent,
            SigningKey = originalKey,
            ParameterUpdates = new DidWebVhParameterUpdates
            {
                UpdateKeys = [newKey.MultibasePublicKey]
            }
        });

        var updatedLog = (byte[])updateResult.Artifacts!["did.jsonl"];
        var entries = LogEntrySerializer.ParseJsonLines(updatedLog);

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

        var logContent = (byte[])createResult.Artifacts!["did.jsonl"];
        var did = createResult.Did.Value;

        var act = () => method.UpdateAsync(did, new DidWebVhUpdateOptions
        {
            CurrentLogContent = logContent,
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

        var logContent = (byte[])createResult.Artifacts!["did.jsonl"];
        var did = createResult.Did.Value;

        // Deactivate
        var deactivateResult = await method.DeactivateAsync(did, new DidWebVhDeactivateOptions
        {
            CurrentLogContent = logContent,
            SigningKey = signer
        });

        deactivateResult.Success.Should().BeTrue();
        deactivateResult.Artifacts.Should().ContainKey("did.jsonl");

        // Resolve should show deactivated
        var updatedLog = (byte[])deactivateResult.Artifacts!["did.jsonl"];
        var logUrl = DidUrlMapper.MapToLogUrl(did);
        httpClient.SetLogResponse(logUrl, updatedLog);

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

        var logContent = (byte[])createResult.Artifacts!["did.jsonl"];
        var did = createResult.Did.Value;

        var act = () => method.DeactivateAsync(did, new DidWebVhDeactivateOptions
        {
            CurrentLogContent = logContent,
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

        var logContent = (byte[])createResult.Artifacts!["did.jsonl"];
        var did = createResult.Did.Value;

        // Rotate to key2 — signed by key1 (the current authorized key),
        // with key2 becoming the new updateKey (validator checks commitment)
        var key3 = CreateEd25519Signer();
        var commitment3 = PreRotationManager.ComputeKeyCommitment(key3.MultibasePublicKey);

        var updateResult = await method.UpdateAsync(did, new DidWebVhUpdateOptions
        {
            CurrentLogContent = logContent,
            SigningKey = key1,
            ParameterUpdates = new DidWebVhParameterUpdates
            {
                UpdateKeys = [key2.MultibasePublicKey],
                Prerotation = true,
                NextKeyHashes = [commitment3]
            }
        });

        // Verify the update succeeded and is resolvable
        var updatedLog = (byte[])updateResult.Artifacts!["did.jsonl"];
        var logUrl = DidUrlMapper.MapToLogUrl(did);
        httpClient.SetLogResponse(logUrl, updatedLog);

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

        var logContent = (byte[])createResult.Artifacts!["did.jsonl"];
        var did = createResult.Did.Value;

        // First update
        var update1 = await method.UpdateAsync(did, new DidWebVhUpdateOptions
        {
            CurrentLogContent = logContent,
            SigningKey = signer
        });
        logContent = (byte[])update1.Artifacts!["did.jsonl"];

        // Second update
        var update2 = await method.UpdateAsync(did, new DidWebVhUpdateOptions
        {
            CurrentLogContent = logContent,
            SigningKey = signer
        });
        logContent = (byte[])update2.Artifacts!["did.jsonl"];

        // Third update
        var update3 = await method.UpdateAsync(did, new DidWebVhUpdateOptions
        {
            CurrentLogContent = logContent,
            SigningKey = signer
        });
        logContent = (byte[])update3.Artifacts!["did.jsonl"];

        // Verify 4 entries total
        var entries = LogEntrySerializer.ParseJsonLines(logContent);
        entries.Should().HaveCount(4);

        // Resolve should return the latest document
        var logUrl = DidUrlMapper.MapToLogUrl(did);
        httpClient.SetLogResponse(logUrl, logContent);

        var resolveResult = await method.ResolveAsync(did);
        resolveResult.DidDocument.Should().NotBeNull();
        resolveResult.DocumentMetadata!.VersionId.Should().StartWith("4-");
    }
}
