using System.Globalization;
using System.Text;
using System.Text.Json;
using DataProofsDotnet;
using DataProofsDotnet.DataIntegrity;
using FluentAssertions;
using NetCrypto;
using NetDid.Core.Model;
using NetDid.Method.WebVh.Model;

namespace NetDid.Method.WebVh.Tests;

/// <summary>
/// Public-boundary regression tests for proof identifiers. Every proof constructed here is
/// genuinely signed over its final <c>id</c>/<c>previousProof</c> configuration so rejection
/// cannot be explained by post-signature mutation.
/// </summary>
public class ProofIdBoundaryTests
{
    private readonly DefaultKeyGenerator _keyGenerator = new();
    private readonly DefaultCryptoProvider _cryptoProvider = new();

    [Fact]
    public async Task Issue101_WhitespaceWrappedProofId_ResolvesInvalidDidLog()
    {
        var fixture = await CreateGenesisAsync();
        fixture.Entries[0] = fixture.Entries[0] with
        {
            Proof =
            [
                await SignEntryAsync(
                    fixture.Entries[0],
                    fixture.KeyPair,
                    fixture.Created,
                    id: " urn:proof:wrapped ")
            ]
        };

        var result = await ResolveAsync(
            fixture.Did, LogEntrySerializer.ToJsonLines(fixture.Entries));

        result.DidDocument.Should().BeNull();
        result.ResolutionMetadata.Error.Should().Be("invalidDidLog");
    }

    [Theory]
    [InlineData("urn:proof:1", true)]
    [InlineData("did:example:proof-1", true)]
    [InlineData("https://proof.example/1", true)]
    [InlineData("a:b", false)]
    public async Task Issue101_ConservativeProofIdPolicy_AcceptsExpectedSchemesOnly(
        string proofId,
        bool shouldResolve)
    {
        var fixture = await CreateGenesisAsync();
        fixture.Entries[0] = fixture.Entries[0] with
        {
            Proof =
            [
                await SignEntryAsync(
                    fixture.Entries[0],
                    fixture.KeyPair,
                    fixture.Created,
                    id: proofId)
            ]
        };

        var result = await ResolveAsync(
            fixture.Did, LogEntrySerializer.ToJsonLines(fixture.Entries));

        if (shouldResolve)
        {
            result.ResolutionMetadata.Error.Should().BeNull();
            result.DidDocument.Should().NotBeNull();
        }
        else
        {
            result.DidDocument.Should().BeNull();
            result.ResolutionMetadata.Error.Should().Be("invalidDidLog");
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Issue101_DuplicateSignedProofIdsInProofSet_EitherOrder_ResolveInvalidDidLog(
        bool reverseDuplicateRoots)
    {
        const string duplicateId = "urn:proof:duplicate";
        var fixture = await CreateGenesisAsync();
        var baseInstant = DateTimeOffset.Parse(
            fixture.Created,
            CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal);

        var first = await SignEntryAsync(
            fixture.Entries[0], fixture.KeyPair, fixture.Created, id: duplicateId);
        var second = await SignEntryAsync(
            fixture.Entries[0],
            fixture.KeyPair,
            baseInstant.AddSeconds(-1).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture),
            id: duplicateId);
        fixture.Entries[0] = fixture.Entries[0] with
        {
            Proof = reverseDuplicateRoots
                ? [second, first]
                : [first, second]
        };

        var result = await ResolveAsync(
            fixture.Did, LogEntrySerializer.ToJsonLines(fixture.Entries));

        result.DidDocument.Should().BeNull();
        result.ResolutionMetadata.Error.Should().Be("invalidDidLog");
    }

    private async Task<GenesisFixture> CreateGenesisAsync()
    {
        var keyPair = _keyGenerator.Generate(KeyType.Ed25519);
        var signer = new KeyPairSigner(keyPair, _cryptoProvider);
        var method = new DidWebVhMethod(new MockWebVhHttpClient());
        var created = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = signer
        });
        var entries = LogEntrySerializer.ParseJsonLines(Encoding.UTF8.GetBytes(
            (string)created.Artifacts![DidWebVhArtifacts.DidJsonl])).ToList();

        return new GenesisFixture(
            created.Did.Value,
            entries,
            keyPair,
            entries[0].Proof![0].Created!);
    }

    private async Task<DataIntegrityProofValue> SignEntryAsync(
        LogEntry entry,
        KeyPair keyPair,
        string created,
        string id,
        PreviousProofReference? previousProof = null)
    {
        var proofOptions = new DataIntegrityProof
        {
            Id = id,
            Cryptosuite = EddsaJcs2022Cryptosuite.CryptosuiteName,
            VerificationMethod =
                $"did:key:{keyPair.MultibasePublicKey}#{keyPair.MultibasePublicKey}",
            Created = created,
            ProofPurpose = "assertionMethod",
            PreviousProof = previousProof
        };
        using var unsecured = JsonDocument.Parse(
            LogEntrySerializer.SerializeWithoutProof(entry));
        var suite = new EddsaJcs2022Cryptosuite();
        var proof = await suite.CreateProofAsync(
            unsecured.RootElement,
            proofOptions,
            new KeyPairSigner(keyPair, _cryptoProvider));

        suite.VerifyProof(
                unsecured.RootElement,
                proof,
                PublicKeyMaterial.FromMultikey(keyPair.MultibasePublicKey))
            .Verified.Should().BeTrue(
                "the fixture must prove its final proof configuration is self-consistently signed");

        return new DataIntegrityProofValue
        {
            Type = proof.Type,
            Cryptosuite = proof.Cryptosuite!,
            VerificationMethod = proof.VerificationMethod!,
            Created = proof.Created,
            ProofPurpose = proof.ProofPurpose!,
            ProofValue = proof.ProofValue!,
            RawJson = JsonSerializer.Serialize(proof, DataProofsJsonOptions.Default)
        };
    }

    private static async Task<DidResolutionResult> ResolveAsync(string did, byte[] log)
    {
        var httpClient = new MockWebVhHttpClient();
        httpClient.SetLogResponse(DidUrlMapper.MapToLogUrl(did), log);
        return await new DidWebVhMethod(httpClient).ResolveAsync(did);
    }

    private sealed record GenesisFixture(
        string Did,
        List<LogEntry> Entries,
        KeyPair KeyPair,
        string Created);
}
