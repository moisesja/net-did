using NetCid;
using NetDid.Core;
using NetDid.Core.Crypto;
using NetDid.Core.Jwk;
using NetDid.Core.Model;
using NetDid.Core.Parsing;

namespace NetDid.Method.Key;

/// <summary>
/// Implementation of the did:key method.
/// did:key is a deterministic, self-certifying DID method where the DID itself
/// encodes the public key. No network interaction is required.
/// </summary>
public sealed class DidKeyMethod : DidMethodBase
{
    private readonly IKeyGenerator _keyGenerator;

    public DidKeyMethod(IKeyGenerator keyGenerator)
    {
        _keyGenerator = keyGenerator ?? throw new ArgumentNullException(nameof(keyGenerator));
    }

    public override string MethodName => "key";
    public override DidMethodCapabilities Capabilities => DidMethodCapabilities.Create | DidMethodCapabilities.Resolve;

    protected override Task<DidCreateResult> CreateCoreAsync(DidCreateOptions options, CancellationToken ct)
    {
        if (options is not DidKeyCreateOptions keyOptions)
            throw new ArgumentException($"Options must be {nameof(DidKeyCreateOptions)}.", nameof(options));

        byte[] publicKey;
        VerificationMethodRepresentation representation = keyOptions.Representation;

        if (keyOptions.ExistingKey is not null)
        {
            if (keyOptions.ExistingKey.KeyType != keyOptions.KeyType)
                throw new ArgumentException(
                    $"ExistingKey.KeyType ({keyOptions.ExistingKey.KeyType}) must match KeyType ({keyOptions.KeyType}).");

            publicKey = keyOptions.KeyType.NormalizeToCompressed(
                keyOptions.ExistingKey.PublicKey.ToArray());
        }
        else
        {
            var keyPair = _keyGenerator.Generate(keyOptions.KeyType);
            publicKey = keyPair.PublicKey;
        }

        var multibasePublicKey = BuildMultibasePublicKey(keyOptions.KeyType, publicKey);
        var did = $"did:key:{multibasePublicKey}";

        var doc = BuildDocument(
            did, keyOptions.KeyType, publicKey, multibasePublicKey,
            representation, keyOptions.EnableEncryptionKeyDerivation);

        return Task.FromResult(new DidCreateResult
        {
            Did = new Did(did),
            DidDocument = doc
        });
    }

    protected override Task<DidResolutionResult> ResolveCoreAsync(
        string did, DidResolutionOptions? options, CancellationToken ct)
    {
        try
        {
            var methodSpecificId = DidParser.ExtractMethodSpecificId(did);
            if (string.IsNullOrEmpty(methodSpecificId))
                return Task.FromResult(DidResolutionResult.InvalidDid(did));

            var decoded = Multibase.Decode(methodSpecificId);
            var (codec, rawKey) = Multicodec.Decode(decoded);
            var keyType = KeyTypeExtensions.ToKeyType(codec);

            if (!keyType.IsValidKeyLength(rawKey.Length))
                return Task.FromResult(DidResolutionResult.InvalidDid(did));

            if (!keyType.IsValidEcPoint(rawKey))
                return Task.FromResult(DidResolutionResult.InvalidDid(did));

            var doc = BuildDocument(
                did, keyType, rawKey, methodSpecificId,
                VerificationMethodRepresentation.Multikey, enableEncryptionKeyDerivation: true);

            return Task.FromResult(new DidResolutionResult
            {
                DidDocument = doc,
                ResolutionMetadata = new DidResolutionMetadata
                {
                    ContentType = DidContentTypes.JsonLd
                }
            });
        }
        catch (Exception)
        {
            return Task.FromResult(DidResolutionResult.InvalidDid(did));
        }
    }

    private DidDocument BuildDocument(
        string did, KeyType keyType, byte[] rawPublicKey, string multibasePublicKey,
        VerificationMethodRepresentation representation, bool enableEncryptionKeyDerivation)
    {
        var vmId = $"{did}#{multibasePublicKey}";
        var didValue = new Did(did);

        var vm = BuildVerificationMethod(vmId, didValue, keyType, rawPublicKey, multibasePublicKey, representation);

        var verificationMethods = new List<VerificationMethod> { vm };
        var vmRef = VerificationRelationshipEntry.FromReference(vmId);

        // Determine which relationships to populate based on key type
        List<VerificationRelationshipEntry>? authentication = null;
        List<VerificationRelationshipEntry>? assertionMethod = null;
        List<VerificationRelationshipEntry>? capabilityInvocation = null;
        List<VerificationRelationshipEntry>? capabilityDelegation = null;
        List<VerificationRelationshipEntry>? keyAgreement = null;

        if (keyType == KeyType.X25519)
        {
            // X25519 is key-agreement only
            keyAgreement = [vmRef];
        }
        else if (keyType is KeyType.Bls12381G2 or KeyType.Bls12381G1)
        {
            // BLS keys: assertionMethod + capabilityInvocation (NOT authentication)
            assertionMethod = [vmRef];
            capabilityInvocation = [vmRef];
        }
        else
        {
            // All other key types: all four verification relationships
            authentication = [vmRef];
            assertionMethod = [vmRef];
            capabilityInvocation = [vmRef];
            capabilityDelegation = [vmRef];
        }

        // Ed25519: derive X25519 key agreement key
        if (keyType == KeyType.Ed25519 && enableEncryptionKeyDerivation)
        {
            var x25519Ref = _keyGenerator.DeriveX25519PublicKeyFromEd25519(rawPublicKey);
            var x25519MultibaseKey = x25519Ref.MultibasePublicKey;
            var x25519VmId = $"{did}#{x25519MultibaseKey}";

            var x25519Vm = BuildVerificationMethod(
                x25519VmId, didValue, KeyType.X25519, x25519Ref.PublicKey,
                x25519MultibaseKey, representation);

            verificationMethods.Add(x25519Vm);
            keyAgreement = [VerificationRelationshipEntry.FromReference(x25519VmId)];
        }

        return new DidDocument
        {
            Id = didValue,
            VerificationMethod = verificationMethods,
            Authentication = authentication,
            AssertionMethod = assertionMethod,
            CapabilityInvocation = capabilityInvocation,
            CapabilityDelegation = capabilityDelegation,
            KeyAgreement = keyAgreement
        };
    }

    private static VerificationMethod BuildVerificationMethod(
        string vmId, Did controller, KeyType keyType, byte[] rawPublicKey,
        string multibasePublicKey, VerificationMethodRepresentation representation)
    {
        return representation switch
        {
            VerificationMethodRepresentation.Multikey => new VerificationMethod
            {
                Id = vmId,
                Type = "Multikey",
                Controller = controller,
                PublicKeyMultibase = multibasePublicKey
            },
            VerificationMethodRepresentation.JsonWebKey2020 => new VerificationMethod
            {
                Id = vmId,
                Type = "JsonWebKey2020",
                Controller = controller,
                PublicKeyJwk = JwkConverter.ToPublicJwk(keyType, rawPublicKey)
            },
            _ => throw new ArgumentOutOfRangeException(nameof(representation))
        };
    }

    private static string BuildMultibasePublicKey(KeyType keyType, byte[] publicKey)
    {
        var prefixed = Multicodec.Prefix(keyType.GetMulticodec(), publicKey);
        return Multibase.Encode(prefixed, MultibaseEncoding.Base58Btc);
    }
}
