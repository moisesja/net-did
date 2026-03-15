using FluentAssertions;
using NetDid.Core.Crypto;
using NetDid.Core.Exceptions;
using NetDid.Method.WebVh;

namespace NetDid.Method.WebVh.Tests;

public class PreRotationManagerTests
{
    private readonly DefaultKeyGenerator _keyGen = new();

    [Fact]
    public void ComputeKeyCommitment_Deterministic()
    {
        var keyPair = _keyGen.Generate(KeyType.Ed25519);
        var commitment1 = PreRotationManager.ComputeKeyCommitment(keyPair.MultibasePublicKey);
        var commitment2 = PreRotationManager.ComputeKeyCommitment(keyPair.MultibasePublicKey);

        commitment1.Should().Be(commitment2);
        commitment1.Should().StartWith("z");
    }

    [Fact]
    public void ComputeKeyCommitment_DifferentKeys_DifferentResult()
    {
        var key1 = _keyGen.Generate(KeyType.Ed25519);
        var key2 = _keyGen.Generate(KeyType.Ed25519);

        var c1 = PreRotationManager.ComputeKeyCommitment(key1.MultibasePublicKey);
        var c2 = PreRotationManager.ComputeKeyCommitment(key2.MultibasePublicKey);

        c1.Should().NotBe(c2);
    }

    [Fact]
    public void ValidateKeyRotation_MatchingCommitment_DoesNotThrow()
    {
        var keyPair = _keyGen.Generate(KeyType.Ed25519);
        var commitment = PreRotationManager.ComputeKeyCommitment(keyPair.MultibasePublicKey);

        var act = () => PreRotationManager.ValidateKeyRotation(
            keyPair.MultibasePublicKey, [commitment], 2);

        act.Should().NotThrow();
    }

    [Fact]
    public void ValidateKeyRotation_NoMatch_Throws()
    {
        var key1 = _keyGen.Generate(KeyType.Ed25519);
        var key2 = _keyGen.Generate(KeyType.Ed25519);
        var commitment = PreRotationManager.ComputeKeyCommitment(key1.MultibasePublicKey);

        var act = () => PreRotationManager.ValidateKeyRotation(
            key2.MultibasePublicKey, [commitment], 2);

        act.Should().Throw<LogChainValidationException>()
            .WithMessage("*Pre-rotation*");
    }
}
