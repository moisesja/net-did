using FluentAssertions;
using NetCid;
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

    // --- ExistingKey EC normalization ---

    [Fact]
    public async Task Create_ExistingKey_UncompressedP256_NormalizedToCompressed()
    {
        // Generate a P-256 key pair using ECDsa to get access to the uncompressed form
        using var ecdsa = System.Security.Cryptography.ECDsa.Create(
            System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
        var ecParams = ecdsa.ExportParameters(includePrivateParameters: true);

        // Build uncompressed public key: 0x04 || x || y
        var uncompressed = new byte[65];
        uncompressed[0] = 0x04;
        ecParams.Q.X!.CopyTo(uncompressed, 1);
        ecParams.Q.Y!.CopyTo(uncompressed, 33);

        // Build compressed public key for comparison
        var yLastByte = ecParams.Q.Y![31];
        var compressedPrefix = (byte)((yLastByte & 1) == 0 ? 0x02 : 0x03);
        var compressedExpected = new byte[33];
        compressedExpected[0] = compressedPrefix;
        ecParams.Q.X.CopyTo(compressedExpected, 1);

        // Create a signer with the uncompressed key
        var signer = new UncompressedKeySigner(KeyType.P256, uncompressed, ecParams.D!, _crypto);

        var result = await _method.CreateAsync(new DidKeyCreateOptions
        {
            KeyType = KeyType.P256,
            ExistingKey = signer
        });

        // The DID should resolve successfully — uncompressed key was normalized
        var resolved = await _method.ResolveAsync(result.Did.Value);
        resolved.DidDocument.Should().NotBeNull();
        resolved.ResolutionMetadata.Error.Should().BeNull();

        // Create from the compressed key directly — should produce the same DID
        var compressedSigner = new UncompressedKeySigner(KeyType.P256, compressedExpected, ecParams.D!, _crypto);
        var compressedResult = await _method.CreateAsync(new DidKeyCreateOptions
        {
            KeyType = KeyType.P256,
            ExistingKey = compressedSigner
        });
        result.Did.Value.Should().Be(compressedResult.Did.Value);
    }

    [Fact]
    public async Task Resolve_MalformedEcPoint_ReturnsInvalidDid()
    {
        // Create a valid P-256 DID first
        var result = await _method.CreateAsync(new DidKeyCreateOptions { KeyType = KeyType.P256 });

        // Tamper with the multibase portion — change last character to corrupt the EC point
        var did = result.Did.Value;
        var lastChar = did[^1];
        var tampered = did[..^1] + (lastChar == 'a' ? 'b' : 'a');

        var resolved = await _method.ResolveAsync(tampered);
        resolved.DidDocument.Should().BeNull();
        resolved.ResolutionMetadata.Error.Should().Be("invalidDid");
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

    /// <summary>Test helper: ISigner that returns uncompressed EC public key bytes.</summary>
    private sealed class UncompressedKeySigner : ISigner
    {
        private readonly byte[] _privateKey;
        private readonly ICryptoProvider _crypto;

        public UncompressedKeySigner(KeyType keyType, byte[] uncompressedPublicKey, byte[] privateKey, ICryptoProvider crypto)
        {
            KeyType = keyType;
            PublicKey = uncompressedPublicKey;
            _privateKey = privateKey;
            _crypto = crypto;
            // Build multibase from the uncompressed key (this is intentionally "wrong" — we test normalization)
            var prefixed = Multicodec.Prefix(keyType.GetMulticodec(), uncompressedPublicKey);
            MultibasePublicKey = Multibase.Encode(prefixed, MultibaseEncoding.Base58Btc);
        }

        public KeyType KeyType { get; }
        public ReadOnlyMemory<byte> PublicKey { get; }
        public string MultibasePublicKey { get; }

        public Task<byte[]> SignAsync(ReadOnlyMemory<byte> data, CancellationToken ct = default)
        {
            var sig = _crypto.Sign(KeyType, _privateKey, data.Span);
            return Task.FromResult(sig);
        }
    }
}
