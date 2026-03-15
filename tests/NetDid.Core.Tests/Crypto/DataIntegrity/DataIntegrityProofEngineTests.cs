using FluentAssertions;
using NetDid.Core.Crypto;
using NetDid.Core.Crypto.DataIntegrity;

namespace NetDid.Core.Tests.Crypto.DataIntegrity;

public class DataIntegrityProofEngineTests
{
    private readonly DefaultKeyGenerator _keyGen = new();
    private readonly DefaultCryptoProvider _crypto = new();

    [Fact]
    public async Task CreateAndVerify_RoundTrip_Succeeds()
    {
        var engine = new DataIntegrityProofEngine(_crypto);
        var keyPair = _keyGen.Generate(KeyType.Ed25519);
        var signer = new KeyPairSigner(keyPair, _crypto);

        var json = """{"id":"did:example:123","name":"test"}""";
        var proof = await engine.CreateProofAsync(json, signer, "assertionMethod", DateTimeOffset.UtcNow);

        proof.Type.Should().Be("DataIntegrityProof");
        proof.Cryptosuite.Should().Be("eddsa-jcs-2022");
        proof.ProofPurpose.Should().Be("assertionMethod");
        proof.ProofValue.Should().StartWith("z"); // base58btc multibase prefix
        proof.VerificationMethod.Should().Contain("did:key:");
        proof.VerificationMethod.Should().Contain("#");

        var valid = engine.VerifyProof(json, proof);
        valid.Should().BeTrue();
    }

    [Fact]
    public async Task Verify_TamperedData_Fails()
    {
        var engine = new DataIntegrityProofEngine(_crypto);
        var keyPair = _keyGen.Generate(KeyType.Ed25519);
        var signer = new KeyPairSigner(keyPair, _crypto);

        var json = """{"id":"did:example:123","name":"test"}""";
        var proof = await engine.CreateProofAsync(json, signer, "assertionMethod", DateTimeOffset.UtcNow);

        var tampered = """{"id":"did:example:123","name":"tampered"}""";
        var valid = engine.VerifyProof(tampered, proof);
        valid.Should().BeFalse();
    }

    [Fact]
    public async Task Verify_WrongKey_Fails()
    {
        var engine = new DataIntegrityProofEngine(_crypto);
        var keyPair1 = _keyGen.Generate(KeyType.Ed25519);
        var keyPair2 = _keyGen.Generate(KeyType.Ed25519);
        var signer1 = new KeyPairSigner(keyPair1, _crypto);

        var json = """{"id":"did:example:123"}""";
        var proof = await engine.CreateProofAsync(json, signer1, "assertionMethod", DateTimeOffset.UtcNow);

        // Replace verificationMethod with a different key
        var wrongProof = proof with
        {
            VerificationMethod = $"did:key:{keyPair2.MultibasePublicKey}#{keyPair2.MultibasePublicKey}"
        };

        var valid = engine.VerifyProof(json, wrongProof);
        valid.Should().BeFalse();
    }

    [Fact]
    public async Task Verify_WrongCryptosuite_Fails()
    {
        var engine = new DataIntegrityProofEngine(_crypto);
        var keyPair = _keyGen.Generate(KeyType.Ed25519);
        var signer = new KeyPairSigner(keyPair, _crypto);

        var json = """{"id":"did:example:123"}""";
        var proof = await engine.CreateProofAsync(json, signer, "assertionMethod", DateTimeOffset.UtcNow);

        var wrongProof = proof with { Cryptosuite = "unknown-suite" };
        var valid = engine.VerifyProof(json, wrongProof);
        valid.Should().BeFalse();
    }

    [Fact]
    public async Task Create_NonEd25519Signer_Throws()
    {
        var engine = new DataIntegrityProofEngine(_crypto);
        var keyPair = _keyGen.Generate(KeyType.P256);
        var signer = new KeyPairSigner(keyPair, _crypto);

        var act = () => engine.CreateProofAsync("""{"id":"test"}""", signer, "assertionMethod", DateTimeOffset.UtcNow);
        await act.Should().ThrowAsync<ArgumentException>().WithMessage("*Ed25519*");
    }

    [Fact]
    public async Task Verify_EquivalentJson_Succeeds_DueToJcs()
    {
        // JCS canonicalization means equivalent JSON with different formatting should verify
        var engine = new DataIntegrityProofEngine(_crypto);
        var keyPair = _keyGen.Generate(KeyType.Ed25519);
        var signer = new KeyPairSigner(keyPair, _crypto);

        var json = """{"b":"2","a":"1"}""";
        var proof = await engine.CreateProofAsync(json, signer, "assertionMethod", DateTimeOffset.UtcNow);

        // Same data but different property order — JCS produces same canonical form
        var equivalent = """{"a":"1","b":"2"}""";
        var valid = engine.VerifyProof(equivalent, proof);
        valid.Should().BeTrue();
    }

    [Fact]
    public void ExtractPublicKeyFromDidKey_WithFragment_Works()
    {
        var keyPair = _keyGen.Generate(KeyType.Ed25519);
        var mb = keyPair.MultibasePublicKey;
        var didUrl = $"did:key:{mb}#{mb}";

        var key = DataIntegrityProofEngine.ExtractPublicKeyFromDidKey(didUrl);
        key.Should().NotBeNull();
        key.Should().BeEquivalentTo(keyPair.PublicKey);
    }

    [Fact]
    public void ExtractPublicKeyFromDidKey_WithoutFragment_Works()
    {
        var keyPair = _keyGen.Generate(KeyType.Ed25519);
        var mb = keyPair.MultibasePublicKey;
        var did = $"did:key:{mb}";

        var key = DataIntegrityProofEngine.ExtractPublicKeyFromDidKey(did);
        key.Should().NotBeNull();
        key.Should().BeEquivalentTo(keyPair.PublicKey);
    }

    [Fact]
    public void ExtractPublicKeyFromDidKey_NonDidKey_ReturnsNull()
    {
        var key = DataIntegrityProofEngine.ExtractPublicKeyFromDidKey("did:web:example.com");
        key.Should().BeNull();
    }
}
