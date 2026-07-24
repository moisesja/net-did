using System.Text;
using FluentAssertions;
using NetCrypto;
using NetDid.Method.WebVh.Model;

namespace NetDid.Method.WebVh.Tests;

public sealed class WitnessPolicyValidatorTests
{
    [Fact]
    public void EmptyObject_DisablesWitnessing()
    {
        WitnessPolicyValidator.GetValidationError(new WitnessConfig())
            .Should().BeNull();
    }

    [Fact]
    public void DuplicateWitnessIds_AreRejected()
    {
        var id = CreateWitnessId();
        var config = new WitnessConfig
        {
            Threshold = 1,
            Witnesses =
            [
                new WitnessEntry { Id = id },
                new WitnessEntry { Id = id }
            ]
        };

        WitnessPolicyValidator.GetValidationError(config)
            .Should().Contain("duplicated");
    }

    [Fact]
    public void NonNormalizedWitnessId_IsRejectedBeforeItCanBecomeUnsatisfiable()
    {
        const string id =
            "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
        var disguisedId = id.Replace('K', '\u212A'); // KELVIN SIGN NFC-normalizes to ASCII K.
        var config = new WitnessConfig
        {
            Threshold = 1,
            Witnesses = [new WitnessEntry { Id = disguisedId }]
        };

        WitnessPolicyValidator.GetValidationError(config)
            .Should().Contain("NFC-normalized");
    }

    [Fact]
    public void ZeroThresholdWithWitnesses_IsRejected()
    {
        var config = new WitnessConfig
        {
            Threshold = 0,
            Witnesses = [new WitnessEntry { Id = CreateWitnessId() }]
        };

        WitnessPolicyValidator.GetValidationError(config)
            .Should().Contain("at least 1");
    }

    [Fact]
    public void NullWitnessEntry_IsRejectedWithoutCrashing()
    {
        var config = new WitnessConfig
        {
            Threshold = 1,
            Witnesses = [null!]
        };

        WitnessPolicyValidator.GetValidationError(config)
            .Should().Contain("non-empty did:key");
    }

    [Fact]
    public void ThresholdAboveDistinctWitnessCount_IsRejected()
    {
        var config = new WitnessConfig
        {
            Threshold = 2,
            Witnesses = [new WitnessEntry { Id = CreateWitnessId() }]
        };

        WitnessPolicyValidator.GetValidationError(config)
            .Should().Contain("exceeds");
    }

    [Fact]
    public void NonEd25519WitnessId_IsRejectedAtPolicyValidation()
    {
        var key = new DefaultKeyGenerator().Generate(KeyType.P256);
        var config = new WitnessConfig
        {
            Threshold = 1,
            Witnesses = [new WitnessEntry { Id = $"did:key:{key.MultibasePublicKey}" }]
        };

        WitnessPolicyValidator.GetValidationError(config)
            .Should().Contain("Ed25519");
    }

    [Fact]
    public async Task Create_RejectsConfiguredWitnessesWithZeroThreshold()
    {
        var method = new DidWebVhMethod(new MockWebVhHttpClient());
        var signer = CreateSigner();

        Func<Task> act = () => method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = signer,
            WitnessDids = [CreateWitnessId()],
            WitnessThreshold = 0
        });

        await act.Should().ThrowAsync<ArgumentException>()
            .WithMessage("*at least 1*");
    }

    [Fact]
    public async Task Create_RejectsThresholdAboveWitnessCount()
    {
        var method = new DidWebVhMethod(new MockWebVhHttpClient());

        Func<Task> act = () => method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = CreateSigner(),
            WitnessDids = [CreateWitnessId()],
            WitnessThreshold = 2
        });

        await act.Should().ThrowAsync<ArgumentException>()
            .WithMessage("*exceeds*");
    }

    [Fact]
    public async Task Create_RejectsDuplicateWitnessIds()
    {
        var method = new DidWebVhMethod(new MockWebVhHttpClient());
        var witnessId = CreateWitnessId();

        Func<Task> act = () => method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = CreateSigner(),
            WitnessDids = [witnessId, witnessId],
            WitnessThreshold = 1
        });

        await act.Should().ThrowAsync<ArgumentException>()
            .WithMessage("*duplicated*");
    }

    [Fact]
    public async Task Resolve_StructurallyMalformedWitnessPolicy_ReturnsInvalidDidLog()
    {
        var httpClient = new MockWebVhHttpClient();
        var method = new DidWebVhMethod(httpClient);
        var created = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = CreateSigner()
        });
        var log = (string)created.Artifacts![DidWebVhArtifacts.DidJsonl];
        var malformed = log.Replace(
            "\"parameters\":{",
            "\"parameters\":{\"witness\":{\"threshold\":\"one\",\"witnesses\":[]},",
            StringComparison.Ordinal);
        httpClient.SetLogResponse(
            DidUrlMapper.MapToLogUrl(created.Did.Value),
            Encoding.UTF8.GetBytes(malformed));

        var result = await method.ResolveAsync(created.Did.Value);

        result.DidDocument.Should().BeNull();
        result.ResolutionMetadata.Error.Should().Be("invalidDidLog");
    }

    private static ISigner CreateSigner()
    {
        var key = new DefaultKeyGenerator().Generate(KeyType.Ed25519);
        return new KeyPairSigner(key, new DefaultCryptoProvider());
    }

    private static string CreateWitnessId()
        => $"did:key:{CreateSigner().MultibasePublicKey}";
}
