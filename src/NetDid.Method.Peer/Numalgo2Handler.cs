using NetCid;
using NetDid.Core;
using NetCrypto;
using NetDid.Core.Model;
using NetDid.Core.Serialization;

namespace NetDid.Method.Peer;

/// <summary>
/// Numalgo 2: inline keys and services encoded in the DID string.
/// Purpose prefixes per the DIF peer-DID spec:
/// A = assertion, E = key agreement (encryption), V = authentication (verification),
/// I = capability invocation, D = capability delegation, S = service.
/// </summary>
internal sealed class Numalgo2Handler
{
    public DidCreateResult Create(DidPeerCreateOptions options)
    {
        // Each caller list is read exactly once, and the DID built from that one read is the only
        // representation: the returned document is that DID resolved. Encoding, validation and the
        // result therefore cannot disagree, whatever a caller IReadOnlyList returns on another
        // read (PR #149 review round 2).
        var segments = new List<string>();

        foreach (var keyPurpose in options.Keys ?? [])
        {
            var prefix = keyPurpose.Purpose switch
            {
                PeerPurpose.Assertion => 'A',
                PeerPurpose.KeyAgreement => 'E',
                PeerPurpose.Authentication => 'V',
                PeerPurpose.CapabilityInvocation => 'I',
                PeerPurpose.CapabilityDelegation => 'D',
                _ => throw new ArgumentOutOfRangeException()
            };
            segments.Add($"{prefix}{keyPurpose.Key.MultibasePublicKey}");
        }

        if (segments.Count == 0)
            throw new ArgumentException("Numalgo 2 requires at least one key in Keys.");

        foreach (var service in options.Services ?? [])
        {
            var encoded = Numalgo2ServiceEncoder.Encode(service);
            segments.Add($"S{encoded}");
        }

        var did = "did:peer:2." + string.Join(".", segments);
        DidDocument doc;
        try
        {
            // Resolve runs the DID Core producer checks (id and URI syntax, unique service ids),
            // so NetDid never mints a DID whose document it could not serialize (issue #145).
            doc = Resolve(did, did["did:peer:".Length..]);
        }
        catch (Exception ex) when (ex is not ArgumentException)
        {
            throw new ArgumentException(
                "The keys and services do not encode a resolvable did:peer:2 document.", ex);
        }

        return new DidCreateResult
        {
            Did = new Did(did),
            DidDocument = doc
        };
    }

    public DidDocument Resolve(string did, string methodSpecificId)
    {
        // methodSpecificId starts with "2.", skip "2."
        var body = methodSpecificId[2..];
        var segments = body.Split('.');

        var verificationMethods = new List<VerificationMethod>();
        var authentication = new List<VerificationRelationshipEntry>();
        var assertionMethod = new List<VerificationRelationshipEntry>();
        var keyAgreement = new List<VerificationRelationshipEntry>();
        var capabilityInvocation = new List<VerificationRelationshipEntry>();
        var capabilityDelegation = new List<VerificationRelationshipEntry>();
        var services = new List<Service>();
        var didValue = new Did(did);
        int keyIndex = 1;  // 1-based per spec
        int autoServiceIndex = 0; // tracks auto-generated service IDs

        foreach (var segment in segments)
        {
            if (string.IsNullOrEmpty(segment)) continue;

            var purposeChar = segment[0];
            var rest = segment[1..];

            switch (purposeChar)
            {
                case 'A':
                {
                    var vm = DecodeKeySegment(rest, didValue, ref keyIndex);
                    verificationMethods.Add(vm);
                    assertionMethod.Add(VerificationRelationshipEntry.FromReference(vm.Id));
                    break;
                }
                case 'E':
                {
                    var vm = DecodeKeySegment(rest, didValue, ref keyIndex);
                    verificationMethods.Add(vm);
                    keyAgreement.Add(VerificationRelationshipEntry.FromReference(vm.Id));
                    break;
                }
                case 'V':
                {
                    var vm = DecodeKeySegment(rest, didValue, ref keyIndex);
                    verificationMethods.Add(vm);
                    authentication.Add(VerificationRelationshipEntry.FromReference(vm.Id));
                    break;
                }
                case 'I':
                {
                    var vm = DecodeKeySegment(rest, didValue, ref keyIndex);
                    verificationMethods.Add(vm);
                    capabilityInvocation.Add(VerificationRelationshipEntry.FromReference(vm.Id));
                    break;
                }
                case 'D':
                {
                    var vm = DecodeKeySegment(rest, didValue, ref keyIndex);
                    verificationMethods.Add(vm);
                    capabilityDelegation.Add(VerificationRelationshipEntry.FromReference(vm.Id));
                    break;
                }
                case 'S':
                {
                    var service = Numalgo2ServiceEncoder.Decode(rest, ref autoServiceIndex);
                    services.Add(service);
                    break;
                }
                default:
                    throw new InvalidOperationException($"Unknown purpose prefix: {purposeChar}");
            }
        }

        var document = new DidDocument
        {
            Id = didValue,
            VerificationMethod = verificationMethods.Count > 0 ? verificationMethods : null,
            Authentication = authentication.Count > 0 ? authentication : null,
            AssertionMethod = assertionMethod.Count > 0 ? assertionMethod : null,
            KeyAgreement = keyAgreement.Count > 0 ? keyAgreement : null,
            CapabilityInvocation = capabilityInvocation.Count > 0 ? capabilityInvocation : null,
            CapabilityDelegation = capabilityDelegation.Count > 0 ? capabilityDelegation : null,
            Service = services.Count > 0 ? services : null
        };
        // A resolved document obeys the same rules (W3C DID Core §5.4 requires a consumer to reject
        // duplicate service ids); a violation maps to invalidDid (issue #145).
        DidDocumentSerializer.ValidateForProduction(document);
        return document;
    }

    private static VerificationMethod DecodeKeySegment(string multibaseKey, Did controller, ref int keyIndex)
    {
        // Validate the embedded Multikey the same way did:key and numalgo 0 do:
        // decode multibase, decode multicodec, map to KeyType, length-check, EC point-check.
        // Any failure throws and the outer DidPeerMethod.ResolveCoreAsync returns invalidDid.
        var decoded = Multibase.Decode(multibaseKey);
        var (codec, rawKey) = Multicodec.Decode(decoded);
        var keyType = KeyTypeExtensions.FromMulticodec(codec);

        if (!keyType.IsValidKeyLength(rawKey.Length))
            throw new ArgumentException(
                $"Invalid key length {rawKey.Length} for {keyType} in numalgo 2 segment.");

        if (!keyType.IsValidEcPoint(rawKey))
            throw new ArgumentException(
                $"Invalid EC point for {keyType} in numalgo 2 segment.");

        var vmId = $"#key-{keyIndex}";
        var vm = new VerificationMethod
        {
            Id = vmId,
            Type = "Multikey",
            Controller = controller,
            PublicKeyMultibase = multibaseKey
        };
        keyIndex++;
        return vm;
    }
}
