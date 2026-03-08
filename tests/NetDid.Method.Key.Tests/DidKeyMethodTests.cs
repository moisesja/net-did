using FluentAssertions;
using NetDid.Core;
using NetDid.Core.Crypto;
using NetDid.Core.Model;
using NetDid.Method.Key;

namespace NetDid.Method.Key.Tests;

public class DidKeyMethodTests
{
    private readonly DefaultKeyGenerator _keyGen = new();
    private readonly DefaultCryptoProvider _crypto = new();
    private readonly DidKeyMethod _method;

    public DidKeyMethodTests()
    {
        _method = new DidKeyMethod(_keyGen);
    }

    // --- Create + Resolve round-trip for each key type ---

    [Theory]
    [InlineData(KeyType.Ed25519)]
    [InlineData(KeyType.X25519)]
    [InlineData(KeyType.P256)]
    [InlineData(KeyType.P384)]
    [InlineData(KeyType.Secp256k1)]
    [InlineData(KeyType.Bls12381G1)]
    [InlineData(KeyType.Bls12381G2)]
    public async Task CreateAndResolve_RoundTrip_AllKeyTypes(KeyType keyType)
    {
        var createResult = await _method.CreateAsync(new DidKeyCreateOptions { KeyType = keyType });

        createResult.Did.Value.Should().StartWith("did:key:z");
        createResult.DidDocument.Should().NotBeNull();
        createResult.DidDocument.Id.Value.Should().Be(createResult.Did.Value);
        createResult.DidDocument.VerificationMethod.Should().NotBeEmpty();

        var resolveResult = await _method.ResolveAsync(createResult.Did.Value);

        resolveResult.DidDocument.Should().NotBeNull();
        resolveResult.ResolutionMetadata.Error.Should().BeNull();
        resolveResult.DidDocument!.Id.Value.Should().Be(createResult.Did.Value);
        resolveResult.DidDocument.VerificationMethod.Should().HaveCount(
            createResult.DidDocument.VerificationMethod!.Count);
    }

    [Fact]
    public async Task Create_Ed25519_HasKeyAgreement()
    {
        var result = await _method.CreateAsync(new DidKeyCreateOptions { KeyType = KeyType.Ed25519 });

        result.DidDocument.VerificationMethod.Should().HaveCount(2); // Ed25519 + X25519
        result.DidDocument.KeyAgreement.Should().HaveCount(1);
        result.DidDocument.Authentication.Should().HaveCount(1);
        result.DidDocument.AssertionMethod.Should().HaveCount(1);
        result.DidDocument.CapabilityInvocation.Should().HaveCount(1);
        result.DidDocument.CapabilityDelegation.Should().HaveCount(1);

        // The second VM should be X25519
        var x25519Vm = result.DidDocument.VerificationMethod![1];
        x25519Vm.Type.Should().Be("Multikey");

        // KeyAgreement should reference the X25519 VM
        var kaRef = result.DidDocument.KeyAgreement![0];
        kaRef.IsReference.Should().BeTrue();
        kaRef.Reference.Should().Be(x25519Vm.Id);
    }

    [Fact]
    public async Task Create_Ed25519_DisableEncryptionKeyDerivation()
    {
        var result = await _method.CreateAsync(new DidKeyCreateOptions
        {
            KeyType = KeyType.Ed25519,
            EnableEncryptionKeyDerivation = false
        });

        result.DidDocument.VerificationMethod.Should().HaveCount(1);
        result.DidDocument.KeyAgreement.Should().BeNull();
    }

    [Fact]
    public async Task Create_X25519_OnlyKeyAgreement()
    {
        var result = await _method.CreateAsync(new DidKeyCreateOptions { KeyType = KeyType.X25519 });

        result.DidDocument.VerificationMethod.Should().HaveCount(1);
        result.DidDocument.KeyAgreement.Should().HaveCount(1);
        result.DidDocument.Authentication.Should().BeNull();
        result.DidDocument.AssertionMethod.Should().BeNull();
    }

    [Fact]
    public async Task Create_BlsG2_NoAuthentication()
    {
        var result = await _method.CreateAsync(new DidKeyCreateOptions { KeyType = KeyType.Bls12381G2 });

        result.DidDocument.VerificationMethod.Should().HaveCount(1);
        result.DidDocument.AssertionMethod.Should().HaveCount(1);
        result.DidDocument.CapabilityInvocation.Should().HaveCount(1);
        result.DidDocument.Authentication.Should().BeNull();
        result.DidDocument.CapabilityDelegation.Should().BeNull();
    }

    [Fact]
    public async Task Create_BlsG1_NoAuthentication()
    {
        var result = await _method.CreateAsync(new DidKeyCreateOptions { KeyType = KeyType.Bls12381G1 });

        result.DidDocument.Authentication.Should().BeNull();
        result.DidDocument.AssertionMethod.Should().HaveCount(1);
        result.DidDocument.CapabilityInvocation.Should().HaveCount(1);
    }

    // --- ExistingKey path ---

    [Fact]
    public async Task Create_WithExistingKey_UsesThatKey()
    {
        var keyPair = _keyGen.Generate(KeyType.P256);
        var signer = new KeyPairSigner(keyPair, _crypto);

        var result = await _method.CreateAsync(new DidKeyCreateOptions
        {
            KeyType = KeyType.P256,
            ExistingKey = signer
        });

        result.Did.Value.Should().StartWith("did:key:z");

        // Resolve and verify the VM references the same key
        var resolved = await _method.ResolveAsync(result.Did.Value);
        resolved.DidDocument!.VerificationMethod![0].PublicKeyMultibase
            .Should().Be(result.DidDocument.VerificationMethod![0].PublicKeyMultibase);
    }

    [Fact]
    public async Task Create_WithExistingKey_MismatchedKeyType_Throws()
    {
        var keyPair = _keyGen.Generate(KeyType.Ed25519);
        var signer = new KeyPairSigner(keyPair, _crypto);

        var act = () => _method.CreateAsync(new DidKeyCreateOptions
        {
            KeyType = KeyType.P256,
            ExistingKey = signer
        });

        await act.Should().ThrowAsync<ArgumentException>();
    }

    // --- Representation ---

    [Fact]
    public async Task Create_Multikey_HasPublicKeyMultibase()
    {
        var result = await _method.CreateAsync(new DidKeyCreateOptions
        {
            KeyType = KeyType.Ed25519,
            Representation = VerificationMethodRepresentation.Multikey
        });

        var vm = result.DidDocument.VerificationMethod![0];
        vm.Type.Should().Be("Multikey");
        vm.PublicKeyMultibase.Should().NotBeNull();
        vm.PublicKeyJwk.Should().BeNull();
    }

    [Fact]
    public async Task Create_JsonWebKey2020_HasPublicKeyJwk()
    {
        var result = await _method.CreateAsync(new DidKeyCreateOptions
        {
            KeyType = KeyType.Ed25519,
            Representation = VerificationMethodRepresentation.JsonWebKey2020
        });

        var vm = result.DidDocument.VerificationMethod![0];
        vm.Type.Should().Be("JsonWebKey2020");
        vm.PublicKeyJwk.Should().NotBeNull();
        vm.PublicKeyMultibase.Should().BeNull();
    }

    // --- Resolution edge cases ---

    [Fact]
    public async Task Resolve_InvalidDid_ReturnsError()
    {
        var result = await _method.ResolveAsync("did:key:invalid");

        result.DidDocument.Should().BeNull();
        result.ResolutionMetadata.Error.Should().Be("invalidDid");
    }

    [Fact]
    public async Task Resolve_WrongMethod_ReturnsMethodNotSupported()
    {
        var result = await _method.ResolveAsync("did:peer:0z6Mktest");

        result.DidDocument.Should().BeNull();
        result.ResolutionMetadata.Error.Should().Be("methodNotSupported");
    }

    // --- Document structure validation ---

    [Fact]
    public async Task Resolve_VerifiesDocumentStructure()
    {
        var createResult = await _method.CreateAsync(new DidKeyCreateOptions { KeyType = KeyType.P256 });
        var did = createResult.Did.Value;

        var resolved = await _method.ResolveAsync(did);
        var doc = resolved.DidDocument!;

        doc.Id.Value.Should().Be(did);
        doc.VerificationMethod.Should().HaveCount(1);

        var vm = doc.VerificationMethod![0];
        vm.Id.Should().StartWith(did + "#");
        vm.Controller.Value.Should().Be(did);
        vm.Type.Should().Be("Multikey");
        vm.PublicKeyMultibase.Should().NotBeNull();
    }

    // --- X25519 public key derivation consistency ---

    [Fact]
    public async Task Ed25519_X25519Derivation_ConsistentBetweenCreateAndResolve()
    {
        var result = await _method.CreateAsync(new DidKeyCreateOptions { KeyType = KeyType.Ed25519 });
        var resolved = await _method.ResolveAsync(result.Did.Value);

        // Both should have 2 VMs
        result.DidDocument.VerificationMethod.Should().HaveCount(2);
        resolved.DidDocument!.VerificationMethod.Should().HaveCount(2);

        // X25519 VMs should match
        var createX25519 = result.DidDocument.VerificationMethod![1];
        var resolveX25519 = resolved.DidDocument.VerificationMethod![1];

        createX25519.Id.Should().Be(resolveX25519.Id);
        createX25519.PublicKeyMultibase.Should().Be(resolveX25519.PublicKeyMultibase);
    }

    // --- Capabilities ---

    [Fact]
    public void Capabilities_CreateAndResolve()
    {
        _method.Capabilities.Should().HaveFlag(DidMethodCapabilities.Create);
        _method.Capabilities.Should().HaveFlag(DidMethodCapabilities.Resolve);
        _method.Capabilities.Should().NotHaveFlag(DidMethodCapabilities.Update);
        _method.Capabilities.Should().NotHaveFlag(DidMethodCapabilities.Deactivate);
    }

    [Fact]
    public void MethodName_IsKey()
    {
        _method.MethodName.Should().Be("key");
    }
}
