using System.Text;
using FluentAssertions;
using NetCrypto;
using NetDid.Core.Exceptions;
using NetDid.Method.WebVh.Model;

namespace NetDid.Method.WebVh.Tests;

public class ControllerProofBudgetTests
{
    private readonly DefaultKeyGenerator _keyGenerator = new();
    private readonly DefaultCryptoProvider _cryptoProvider = new();

    [Fact]
    public async Task Issue101_DefaultBudget_RejectsEntryAboveEightProofs()
    {
        var entry = await CreateGenesisWithProofCountAsync(
            LogChainValidator.DefaultMaxControllerProofsPerEntry + 1);

        var act = () => new LogChainValidator().ValidateChain([entry]);

        act.Should().Throw<LogChainValidationException>()
            .WithMessage("*exceeding the resolver's limit of 8*");
    }

    [Fact]
    public async Task Issue101_RaisedValidatorBudget_AcceptsEntryAboveDefault()
    {
        var raisedBudget = LogChainValidator.DefaultMaxControllerProofsPerEntry + 1;
        var entry = await CreateGenesisWithProofCountAsync(raisedBudget);

        var act = () => new LogChainValidator(raisedBudget).ValidateChain([entry]);

        act.Should().NotThrow();
    }

    [Fact]
    public async Task Issue101_LoweredValidatorBudget_RejectsEntryAboveConfiguredLimit()
    {
        var entry = await CreateGenesisWithProofCountAsync(2);

        var act = () => new LogChainValidator(1).ValidateChain([entry]);

        act.Should().Throw<LogChainValidationException>()
            .WithMessage("*exceeding the resolver's limit of 1*");
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void Issue101_ValidatorBudgetBelowOne_ThrowsArgumentOutOfRangeException(
        int invalidBudget)
    {
        var act = () => new LogChainValidator(invalidBudget);

        act.Should().Throw<ArgumentOutOfRangeException>()
            .Which.ParamName.Should().Be("maxControllerProofsPerEntry");
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void Issue101_PublicMethodBudgetBelowOne_ThrowsArgumentOutOfRangeException(
        int invalidBudget)
    {
        var act = () => new DidWebVhMethod(
            new MockWebVhHttpClient(),
            logger: null,
            maxControllerProofsPerEntry: invalidBudget);

        act.Should().Throw<ArgumentOutOfRangeException>()
            .Which.ParamName.Should().Be("maxControllerProofsPerEntry");
    }

    [Fact]
    public void Issue101_ExistingUntypedDefaultLoggerCall_RemainsSourceCompatible()
    {
        var method = new DidWebVhMethod(new MockWebVhHttpClient(), default);

        method.Should().NotBeNull();
    }

    private async Task<LogEntry> CreateGenesisWithProofCountAsync(int proofCount)
    {
        var updateKey = _keyGenerator.Generate(KeyType.Ed25519);
        var signer = new KeyPairSigner(updateKey, _cryptoProvider);
        var method = new DidWebVhMethod(new MockWebVhHttpClient());
        var created = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = signer
        });

        var log = (string)created.Artifacts![DidWebVhArtifacts.DidJsonl];
        var genesis = LogEntrySerializer.ParseJsonLines(Encoding.UTF8.GetBytes(log)).Single();
        var proof = genesis.Proof!.Single();

        return genesis with
        {
            Proof = Enumerable.Repeat(proof, proofCount).ToArray()
        };
    }
}
