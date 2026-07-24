using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using DataProofsDotnet.DataIntegrity;
using FluentAssertions;
using NetCrypto;
using NetDid.Core.Exceptions;
using NetDid.Core.Model;

namespace NetDid.Method.WebVh.Tests;

/// <summary>
/// Regressions for the did:webvh v1.0 per-entry SCID identity rule: "The SCID segment of
/// state.id MUST be byte-for-byte identical to the scid value in the DID and the first entry's
/// parameters.scid. This check MUST apply to every entry's state.id, not just the first. A
/// mismatch MUST terminate resolution." Only the host/path portion may change under
/// portability; the SCID segment is immutable for the life of the DID.
/// </summary>
public sealed class ScidConsistencyTests
{
    private readonly DefaultKeyGenerator _keyGenerator = new();
    private readonly DefaultCryptoProvider _crypto = new();

    [Fact]
    public async Task Issue101_MiddleEntryStateIdWithForeignScid_ResolvesInvalidDidLog()
    {
        var (method, httpClient, signer) = CreateMethodAndSigner();
        var created = await CreateAsync(method, signer);
        var did = created.Did.Value;
        var genesisLog = (string)created.Artifacts![DidWebVhArtifacts.DidJsonl];
        var genesisState = JsonNode.Parse(genesisLog)!["state"]!.DeepClone();

        // A genuinely signed middle entry whose document claims a different SCID identity,
        // followed by a genuinely signed head that restores the requested DID. Every hash and
        // proof verifies; only the identity rule can reject this log.
        var log = await AppendCraftedEntryAsync(genesisLog, signer, entry =>
            entry["state"]!["id"] = "did:webvh:zQmForgedForeignScidValue:example.com");
        log = await AppendCraftedEntryAsync(log, signer, entry =>
            entry["state"] = genesisState.DeepClone());
        httpClient.SetLogResponse(DidUrlMapper.MapToLogUrl(did), Encoding.UTF8.GetBytes(log));

        var result = await method.ResolveAsync(did, new DidResolutionOptions { IncludeLog = true });

        result.DidDocument.Should().BeNull();
        result.ResolutionMetadata.Error.Should().Be("invalidDidLog",
            "every validated entry's state.id must carry the log's SCID, not just the target's");
        result.Artifacts.Should().BeNull();
    }

    [Fact]
    public async Task Issue101_GenesisStateIdWithForeignScid_TargetV2_ResolvesInvalidDidLog()
    {
        var (method, httpClient, signer) = CreateMethodAndSigner();

        // A fully self-consistent genesis (SCID and entry hash verify) whose state.id carries
        // a foreign SCID. The foreign value is not the SCID, so it survives the placeholder
        // reverse-substitution untouched and the log remains self-certifying.
        var genesisLine = await CraftGenesisWithStateIdAsync(
            signer, "did:webvh:zQmForgedForeignScidValue:example.com");
        var scid = JsonNode.Parse(genesisLine)!["parameters"]!["scid"]!.GetValue<string>();
        var did = $"did:webvh:{scid}:example.com";

        // A genuinely signed v2 whose document claims the requested DID, so the target-entry
        // identity check passes and only the genesis state.id is inconsistent.
        var log = await AppendCraftedEntryAsync(genesisLine, signer, entry =>
            entry["state"]!["id"] = did);
        httpClient.SetLogResponse(DidUrlMapper.MapToLogUrl(did), Encoding.UTF8.GetBytes(log));

        var result = await method.ResolveAsync(did);

        result.DidDocument.Should().BeNull();
        result.ResolutionMetadata.Error.Should().Be("invalidDidLog",
            "the genesis state.id SCID must match parameters.scid even when it is not the target");
    }

    [Fact]
    public async Task Issue101_MiddleEntryStateMissingId_ResolvesInvalidDidLog()
    {
        var (method, httpClient, signer) = CreateMethodAndSigner();
        var created = await CreateAsync(method, signer);
        var did = created.Did.Value;
        var genesisLog = (string)created.Artifacts![DidWebVhArtifacts.DidJsonl];
        var genesisState = JsonNode.Parse(genesisLog)!["state"]!.DeepClone();

        var log = await AppendCraftedEntryAsync(genesisLog, signer, entry =>
            entry["state"]!.AsObject().Remove("id"));
        log = await AppendCraftedEntryAsync(log, signer, entry =>
            entry["state"] = genesisState.DeepClone());
        httpClient.SetLogResponse(DidUrlMapper.MapToLogUrl(did), Encoding.UTF8.GetBytes(log));

        var result = await method.ResolveAsync(did);

        result.DidDocument.Should().BeNull();
        result.ResolutionMetadata.Error.Should().Be("invalidDidLog",
            "an entry whose document has no id cannot satisfy the per-entry SCID identity rule");
    }

    [Fact]
    public async Task Issue101_HistoricalTargetBeforeForeignScidTail_StillResolves()
    {
        // Historical resolution intentionally validates only the selected prefix; a corrupt
        // tail must not revoke an already-established version. This pins the boundary of the
        // per-entry rule: it covers every entry that establishes the returned result.
        var (method, httpClient, signer) = CreateMethodAndSigner();
        var created = await CreateAsync(method, signer);
        var did = created.Did.Value;
        var genesisLog = (string)created.Artifacts![DidWebVhArtifacts.DidJsonl];
        var genesisVersionId = JsonNode.Parse(genesisLog)!["versionId"]!.GetValue<string>();

        var log = await AppendCraftedEntryAsync(genesisLog, signer, entry =>
            entry["state"]!["id"] = "did:webvh:zQmForgedForeignScidValue:example.com");
        httpClient.SetLogResponse(DidUrlMapper.MapToLogUrl(did), Encoding.UTF8.GetBytes(log));

        var result = await method.ResolveAsync(
            did, new DidResolutionOptions { VersionId = genesisVersionId });

        result.ResolutionMetadata.Error.Should().BeNull();
        result.DidDocument.Should().NotBeNull();
        result.DidDocument!.Id.Value.Should().Be(did);
    }

    [Fact]
    public async Task Issue101_Update_MiddleEntryForeignScid_ThrowsLogChainValidationException()
    {
        // Writer parity: the driver must not append to a log its own resolver rejects on
        // identity grounds.
        var (method, _, signer) = CreateMethodAndSigner();
        var created = await CreateAsync(method, signer);
        var did = created.Did.Value;
        var genesisLog = (string)created.Artifacts![DidWebVhArtifacts.DidJsonl];
        var genesisState = JsonNode.Parse(genesisLog)!["state"]!.DeepClone();

        var log = await AppendCraftedEntryAsync(genesisLog, signer, entry =>
            entry["state"]!["id"] = "did:webvh:zQmForgedForeignScidValue:example.com");
        log = await AppendCraftedEntryAsync(log, signer, entry =>
            entry["state"] = genesisState.DeepClone());

        var act = () => method.UpdateAsync(did, new DidWebVhUpdateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(log),
            SigningKey = signer
        });

        await act.Should().ThrowAsync<LogChainValidationException>();
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
    /// Appends a genuinely signed entry to a JSON Lines log: clones the previous entry's state,
    /// applies <paramref name="mutate"/>, computes the entry hash with the spec's
    /// previous-versionId substitution, and signs the result with the authorized key.
    /// </summary>
    private static async Task<string> AppendCraftedEntryAsync(
        string log, KeyPairSigner signer, Action<JsonObject> mutate)
    {
        var lines = log.Split('\n');
        var previous = JsonNode.Parse(lines[^1])!.AsObject();
        var previousVersionId = previous["versionId"]!.GetValue<string>();
        var previousTime = WebVhTimestamp.Parse(previous["versionTime"]!.GetValue<string>());

        var entry = new JsonObject
        {
            ["versionId"] = previousVersionId,
            ["versionTime"] = WebVhTimestamp.Format(previousTime.AddSeconds(1)),
            ["parameters"] = new JsonObject(),
            ["state"] = previous["state"]!.DeepClone()
        };
        mutate(entry);

        var entryHash = ScidGenerator.ComputeEntryHash(entry.ToJsonString());
        entry["versionId"] = $"{lines.Length + 1}-{entryHash}";

        return $"{log}\n{await SignEntryAsync(entry, signer)}";
    }

    /// <summary>
    /// Crafts a fully self-consistent signed genesis entry (SCID and entry hash verify) whose
    /// state.id is the supplied literal instead of the DID derived from the computed SCID.
    /// </summary>
    private static async Task<string> CraftGenesisWithStateIdAsync(
        KeyPairSigner signer, string stateId)
    {
        var template = new JsonObject
        {
            ["versionId"] = ScidGenerator.Placeholder,
            ["versionTime"] = WebVhTimestamp.Format(DateTimeOffset.UtcNow),
            ["parameters"] = new JsonObject
            {
                ["method"] = DidWebVhMethod.MethodVersion,
                ["scid"] = ScidGenerator.Placeholder,
                ["updateKeys"] = new JsonArray(signer.MultibasePublicKey)
            },
            ["state"] = new JsonObject
            {
                ["@context"] = new JsonArray("https://www.w3.org/ns/did/v1"),
                ["id"] = stateId
            }
        };

        var scid = ScidGenerator.ComputeScid(template.ToJsonString());
        var preliminaryJson = ScidGenerator.ReplacePlaceholders(template.ToJsonString(), scid);
        var entryHash = ScidGenerator.ComputeEntryHash(preliminaryJson);

        var entry = JsonNode.Parse(preliminaryJson)!.AsObject();
        entry["versionId"] = $"1-{entryHash}";

        return await SignEntryAsync(entry, signer);
    }

    private static async Task<string> SignEntryAsync(JsonObject entry, KeyPairSigner signer)
    {
        using var unsignedDocument = JsonDocument.Parse(entry.ToJsonString());
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
        return secured.GetRawText();
    }
}
