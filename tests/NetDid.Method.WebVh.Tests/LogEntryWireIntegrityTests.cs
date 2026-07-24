using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using DataProofsDotnet.DataIntegrity;
using FluentAssertions;
using NetCrypto;
using NetDid.Core.Model;

namespace NetDid.Method.WebVh.Tests;

/// <summary>
/// Security regressions for preserving the fetched log entry as the integrity input. A resolver
/// must verify the JSON that arrived on the wire, not a reduced object-model reconstruction.
/// </summary>
public sealed class LogEntryWireIntegrityTests
{
    private readonly DefaultKeyGenerator _keyGenerator = new();
    private readonly DefaultCryptoProvider _crypto = new();

    [Fact]
    public async Task Issue101_PostSignNestedVerificationMethodMutation_ResolvesInvalidDidLogWithoutArtifacts()
    {
        var (method, httpClient, signer) = CreateMethodAndSigner();
        var created = await CreateAsync(method, signer);
        var did = created.Did.Value;
        var log = (string)created.Artifacts![DidWebVhArtifacts.DidJsonl];
        var entry = JsonNode.Parse(log)!.AsObject();

        entry["state"]!["verificationMethod"]![0]!["attackerInjected"] =
            "not-covered-by-signature";
        httpClient.SetLogResponse(
            DidUrlMapper.MapToLogUrl(did), Encoding.UTF8.GetBytes(entry.ToJsonString()));

        var result = await method.ResolveAsync(
            did, new DidResolutionOptions { IncludeLog = true });

        result.DidDocument.Should().BeNull();
        result.ResolutionMetadata.Error.Should().Be("invalidDidLog");
        result.Artifacts.Should().BeNull();
    }

    [Fact]
    public async Task Issue101_InvalidUtf8ReplacingSignedReplacementCharacter_ResolvesInvalidDidLog()
    {
        var (method, httpClient, signer) = CreateMethodAndSigner();
        var created = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = signer,
            Services =
            [
                new Service
                {
                    Id = "#service",
                    Type = "ExampleService",
                    ServiceEndpoint = ServiceEndpointValue.FromUri("https://example.com/service"),
                    AdditionalProperties = new Dictionary<string, JsonElement>
                    {
                        ["marker"] = JsonSerializer.SerializeToElement("\uFFFD")
                    }
                }
            ]
        });
        var did = created.Did.Value;
        var signedBytes = Encoding.UTF8.GetBytes(
            (string)created.Artifacts![DidWebVhArtifacts.DidJsonl]);
        var invalidUtf8 = ReplaceOnce(
            signedBytes, Encoding.ASCII.GetBytes("\\uFFFD"), [0xFF]);
        httpClient.SetLogResponse(DidUrlMapper.MapToLogUrl(did), invalidUtf8);

        var result = await method.ResolveAsync(
            did, new DidResolutionOptions { IncludeLog = true });

        result.DidDocument.Should().BeNull();
        result.ResolutionMetadata.Error.Should().Be("invalidDidLog");
        result.Artifacts.Should().BeNull();
    }

    [Fact]
    public async Task Issue101_GenuinelySignedNestedVerificationMethodExtension_Resolves()
    {
        var (method, httpClient, signer) = CreateMethodAndSigner();
        var created = await CreateAsync(method, signer);
        var did = created.Did.Value;
        var foreignLog = await BuildLogWithSignedNestedStateExtensionAsync(
            method, did, created, signer);
        httpClient.SetLogResponse(
            DidUrlMapper.MapToLogUrl(did), Encoding.UTF8.GetBytes(foreignLog));

        var result = await method.ResolveAsync(
            did, new DidResolutionOptions { IncludeLog = true });

        result.ResolutionMetadata.Error.Should().BeNull();
        result.DidDocument.Should().NotBeNull();
        ((string)result.Artifacts![DidWebVhArtifacts.DidJsonl])
            .Should().Contain("foreignExtension");

        var republished = await method.UpdateAsync(did, new DidWebVhUpdateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(foreignLog),
            SigningKey = signer
        });
        ((string)republished.Artifacts![DidWebVhArtifacts.DidJsonl])
            .Split('\n')[1]
            .Should().Contain("foreignExtension",
                "Update must preserve fetched prior entries instead of reducing their state model");

        var deactivated = await method.DeactivateAsync(did, new DidWebVhDeactivateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(foreignLog),
            SigningKey = signer
        });
        ((string)deactivated.Artifacts![DidWebVhArtifacts.DidJsonl])
            .Split('\n')[1]
            .Should().Contain("foreignExtension",
                "Deactivate must preserve fetched prior entries instead of reducing their state model");
    }

    [Fact]
    public async Task Issue101_PreserveModeUpdate_CarriesSignedNestedStateExtensionIntoNewHead()
    {
        var (method, httpClient, signer) = CreateMethodAndSigner();
        var created = await CreateAsync(method, signer);
        var did = created.Did.Value;
        var foreignLog = await BuildLogWithSignedNestedStateExtensionAsync(
            method, did, created, signer);

        // NewDocument == null promises "the previous document is preserved" — the new signed
        // head must republish the previous state verbatim, not a reduced typed-model
        // reconstruction that silently erases signed extension members.
        var updated = await method.UpdateAsync(did, new DidWebVhUpdateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(foreignLog),
            SigningKey = signer
        });

        var updatedLog = (string)updated.Artifacts![DidWebVhArtifacts.DidJsonl];
        var lines = updatedLog.Split('\n');
        lines.Should().HaveCount(3);
        var previousState = JsonNode.Parse(lines[1])!["state"]!.ToJsonString();
        var headState = JsonNode.Parse(lines[2])!["state"]!.ToJsonString();
        headState.Should().Be(previousState,
            "a preserve-mode update must carry the previous signed document into the new head");

        httpClient.SetLogResponse(
            DidUrlMapper.MapToLogUrl(did), Encoding.UTF8.GetBytes(updatedLog));
        var resolved = await method.ResolveAsync(did);
        resolved.ResolutionMetadata.Error.Should().BeNull();
        resolved.DidDocument.Should().NotBeNull();
    }

    [Fact]
    public async Task Issue101_Deactivate_HeadRemainsMinimalDocumentByDesign()
    {
        // Deactivation intentionally publishes a minimal final document; it is not a
        // preserve-mode update and must not start carrying prior-state extensions.
        var (method, _, signer) = CreateMethodAndSigner();
        var created = await CreateAsync(method, signer);
        var did = created.Did.Value;
        var foreignLog = await BuildLogWithSignedNestedStateExtensionAsync(
            method, did, created, signer);

        var deactivated = await method.DeactivateAsync(did, new DidWebVhDeactivateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(foreignLog),
            SigningKey = signer
        });

        var head = JsonNode.Parse(
            ((string)deactivated.Artifacts![DidWebVhArtifacts.DidJsonl]).Split('\n')[^1])!;
        head["state"]!["id"]!.GetValue<string>().Should().Be(did);
        head["state"]!.ToJsonString().Should().NotContain("foreignExtension");
    }

    [Fact]
    public void Issue101_WitnessFileWithInvalidUtf8_IsRejected()
    {
        var validJson = """
            [{"versionId":"1-test","proofs":[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","verificationMethod":"did:key:zTest#zTest","created":"2026-07-13T12:00:00Z","proofPurpose":"assertionMethod","proofValue":"\uFFFD"}]}]
            """;
        var invalidUtf8 = ReplaceOnce(
            Encoding.UTF8.GetBytes(validJson),
            Encoding.ASCII.GetBytes("\\uFFFD"),
            [0xFF]);

        var parsed = WitnessValidator.ParseWitnessFile(invalidUtf8);

        parsed.Should().BeNull("witness JSON is also a strict UTF-8 trust boundary");
    }

    private (DidWebVhMethod Method, MockWebVhHttpClient HttpClient, KeyPairSigner Signer)
        CreateMethodAndSigner()
    {
        var httpClient = new MockWebVhHttpClient();
        var method = new DidWebVhMethod(httpClient);
        var keyPair = _keyGenerator.Generate(KeyType.Ed25519);
        var signer = new KeyPairSigner(keyPair, _crypto);
        return (method, httpClient, signer);
    }

    private static Task<DidCreateResult> CreateAsync(DidWebVhMethod method, KeyPairSigner signer)
        => method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = signer
        });

    /// <summary>
    /// Builds a two-entry log whose second entry is genuinely signed and carries a nested
    /// verification-method extension member that the typed model does not surface
    /// (<c>foreignExtension</c>), simulating a conforming foreign controller's document.
    /// </summary>
    private static async Task<string> BuildLogWithSignedNestedStateExtensionAsync(
        DidWebVhMethod method, string did, DidCreateResult created, KeyPairSigner signer)
    {
        var updated = await method.UpdateAsync(did, new DidWebVhUpdateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(
                (string)created.Artifacts![DidWebVhArtifacts.DidJsonl]),
            SigningKey = signer
        });
        var lines = ((string)updated.Artifacts![DidWebVhArtifacts.DidJsonl]).Split('\n');
        lines.Should().HaveCount(2);

        var previousVersionId = JsonNode.Parse(lines[0])!["versionId"]!.GetValue<string>();
        var unsigned = JsonNode.Parse(lines[1])!.AsObject();
        unsigned.Remove("proof");
        unsigned["state"]!["verificationMethod"]![0]!["foreignExtension"] =
            new JsonObject { ["policy"] = "preserved" };

        // did:webvh hashes an update with its versionId temporarily set to the previous full
        // versionId, then publishes the resulting hash in the update's actual versionId.
        unsigned["versionId"] = previousVersionId;
        var entryHash = ScidGenerator.ComputeEntryHash(unsigned.ToJsonString());
        unsigned["versionId"] = $"2-{entryHash}";

        using var unsignedDocument = JsonDocument.Parse(unsigned.ToJsonString());
        var verificationMethod =
            $"did:key:{signer.MultibasePublicKey}#{signer.MultibasePublicKey}";
        var secured = await new DataIntegrityProofPipeline().AddProofAsync(
            unsignedDocument.RootElement,
            new DataIntegrityProof
            {
                Cryptosuite = EddsaJcs2022Cryptosuite.CryptosuiteName,
                VerificationMethod = verificationMethod,
                ProofPurpose = "assertionMethod"
            },
            signer);
        return $"{lines[0]}\n{secured.GetRawText()}";
    }

    private static byte[] ReplaceOnce(byte[] source, byte[] oldValue, byte[] newValue)
    {
        var index = source.AsSpan().IndexOf(oldValue);
        index.Should().BeGreaterThanOrEqualTo(0,
            "the signed JSON must contain the escaped replacement character");

        var result = new byte[source.Length - oldValue.Length + newValue.Length];
        source.AsSpan(0, index).CopyTo(result);
        newValue.CopyTo(result.AsSpan(index));
        source.AsSpan(index + oldValue.Length)
            .CopyTo(result.AsSpan(index + newValue.Length));
        return result;
    }
}
