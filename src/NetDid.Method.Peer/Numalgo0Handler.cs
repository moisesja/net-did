using NetCid;
using NetDid.Core;
using NetDid.Core.Crypto;
using NetDid.Core.Model;

namespace NetDid.Method.Peer;

/// <summary>
/// Numalgo 0: inception key only. Functionally identical to did:key but with did:peer:0 prefix.
/// </summary>
internal sealed class Numalgo0Handler
{
    private readonly IKeyGenerator _keyGenerator;

    public Numalgo0Handler(IKeyGenerator keyGenerator)
        => _keyGenerator = keyGenerator;

    public DidCreateResult Create(DidPeerCreateOptions options)
    {
        if (options.InceptionKeyType is null && options.ExistingKey is null)
            throw new ArgumentException("Numalgo 0 requires InceptionKeyType or ExistingKey.");

        byte[] publicKey;
        KeyType keyType;

        if (options.ExistingKey is not null)
        {
            keyType = options.ExistingKey.KeyType;
            if (options.InceptionKeyType.HasValue && options.InceptionKeyType.Value != keyType)
                throw new ArgumentException("ExistingKey.KeyType must match InceptionKeyType.");
            publicKey = options.ExistingKey.PublicKey.ToArray();
        }
        else
        {
            keyType = options.InceptionKeyType!.Value;
            var keyPair = _keyGenerator.Generate(keyType);
            publicKey = keyPair.PublicKey;
        }

        var multibaseKey = BuildMultibase(keyType, publicKey);
        var did = $"did:peer:0{multibaseKey}";

        var doc = BuildDocument(did, keyType, publicKey, multibaseKey);
        return new DidCreateResult
        {
            Did = new Did(did),
            DidDocument = doc
        };
    }

    public DidDocument? Resolve(string did, string methodSpecificId)
    {
        // methodSpecificId starts with '0', skip it to get the multibase portion
        var multibaseKey = methodSpecificId[1..];
        var decoded = Multibase.Decode(multibaseKey);
        var (codec, rawKey) = Multicodec.Decode(decoded);
        var keyType = KeyTypeExtensions.ToKeyType(codec);

        if (!keyType.IsValidKeyLength(rawKey.Length))
            return null;

        return BuildDocument(did, keyType, rawKey, multibaseKey);
    }

    private DidDocument BuildDocument(string did, KeyType keyType, byte[] rawPublicKey, string multibaseKey)
    {
        var vmId = $"{did}#{multibaseKey}";
        var didValue = new Did(did);

        var vm = new VerificationMethod
        {
            Id = vmId,
            Type = "Multikey",
            Controller = didValue,
            PublicKeyMultibase = multibaseKey
        };

        var vmRef = VerificationRelationshipEntry.FromReference(vmId);
        var verificationMethods = new List<VerificationMethod> { vm };

        List<VerificationRelationshipEntry>? authentication = null;
        List<VerificationRelationshipEntry>? assertionMethod = null;
        List<VerificationRelationshipEntry>? capabilityInvocation = null;
        List<VerificationRelationshipEntry>? capabilityDelegation = null;
        List<VerificationRelationshipEntry>? keyAgreement = null;

        if (keyType == KeyType.X25519)
        {
            keyAgreement = [vmRef];
        }
        else if (keyType is KeyType.Bls12381G1 or KeyType.Bls12381G2)
        {
            assertionMethod = [vmRef];
            capabilityInvocation = [vmRef];
        }
        else
        {
            authentication = [vmRef];
            assertionMethod = [vmRef];
            capabilityInvocation = [vmRef];
            capabilityDelegation = [vmRef];
        }

        // Ed25519: derive X25519 key agreement
        if (keyType == KeyType.Ed25519)
        {
            var x25519Ref = _keyGenerator.DeriveX25519PublicKeyFromEd25519(rawPublicKey);
            var x25519MultibaseKey = x25519Ref.MultibasePublicKey;
            var x25519VmId = $"{did}#{x25519MultibaseKey}";

            verificationMethods.Add(new VerificationMethod
            {
                Id = x25519VmId,
                Type = "Multikey",
                Controller = didValue,
                PublicKeyMultibase = x25519MultibaseKey
            });
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

    private static string BuildMultibase(KeyType keyType, byte[] publicKey)
    {
        var prefixed = Multicodec.Prefix(keyType.GetMulticodec(), publicKey);
        return Multibase.Encode(prefixed, MultibaseEncoding.Base58Btc);
    }
}
