using NetCid;
using NetDid.Core;
using NetDid.Core.Crypto;
using NetDid.Core.Model;

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
        if (options.Keys is null || options.Keys.Count == 0)
            throw new ArgumentException("Numalgo 2 requires at least one key in Keys.");

        var segments = new List<string>();

        foreach (var keyPurpose in options.Keys)
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

        if (options.Services is not null)
        {
            foreach (var service in options.Services)
            {
                var encoded = Numalgo2ServiceEncoder.Encode(service);
                segments.Add($"S{encoded}");
            }
        }

        var did = "did:peer:2." + string.Join(".", segments);
        var doc = BuildDocument(did, options.Keys, options.Services);

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

        return new DidDocument
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
    }

    private static VerificationMethod DecodeKeySegment(string multibaseKey, Did controller, ref int keyIndex)
    {
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

    private static DidDocument BuildDocument(
        string did, IReadOnlyList<PeerKeyPurpose> keys, IReadOnlyList<Service>? inputServices)
    {
        var didValue = new Did(did);
        var verificationMethods = new List<VerificationMethod>();
        var authentication = new List<VerificationRelationshipEntry>();
        var assertionMethod = new List<VerificationRelationshipEntry>();
        var keyAgreement = new List<VerificationRelationshipEntry>();
        var capabilityInvocation = new List<VerificationRelationshipEntry>();
        var capabilityDelegation = new List<VerificationRelationshipEntry>();
        int keyIndex = 1; // 1-based per spec

        foreach (var keyPurpose in keys)
        {
            var vmId = $"#key-{keyIndex}";
            var vm = new VerificationMethod
            {
                Id = vmId,
                Type = "Multikey",
                Controller = didValue,
                PublicKeyMultibase = keyPurpose.Key.MultibasePublicKey
            };
            verificationMethods.Add(vm);

            var vmRef = VerificationRelationshipEntry.FromReference(vmId);
            switch (keyPurpose.Purpose)
            {
                case PeerPurpose.Assertion:
                    assertionMethod.Add(vmRef);
                    break;
                case PeerPurpose.KeyAgreement:
                    keyAgreement.Add(vmRef);
                    break;
                case PeerPurpose.Authentication:
                    authentication.Add(vmRef);
                    break;
                case PeerPurpose.CapabilityInvocation:
                    capabilityInvocation.Add(vmRef);
                    break;
                case PeerPurpose.CapabilityDelegation:
                    capabilityDelegation.Add(vmRef);
                    break;
            }
            keyIndex++;
        }

        List<Service>? services = null;
        if (inputServices is { Count: > 0 })
        {
            services = new List<Service>();
            int autoServiceIndex = 0;
            for (int i = 0; i < inputServices.Count; i++)
            {
                services.Add(new Service
                {
                    Id = GenerateServiceId(inputServices[i].Id, ref autoServiceIndex),
                    Type = inputServices[i].Type,
                    ServiceEndpoint = inputServices[i].ServiceEndpoint,
                    AdditionalProperties = inputServices[i].AdditionalProperties
                });
            }
        }

        return new DidDocument
        {
            Id = didValue,
            VerificationMethod = verificationMethods.Count > 0 ? verificationMethods : null,
            Authentication = authentication.Count > 0 ? authentication : null,
            AssertionMethod = assertionMethod.Count > 0 ? assertionMethod : null,
            KeyAgreement = keyAgreement.Count > 0 ? keyAgreement : null,
            CapabilityInvocation = capabilityInvocation.Count > 0 ? capabilityInvocation : null,
            CapabilityDelegation = capabilityDelegation.Count > 0 ? capabilityDelegation : null,
            Service = services
        };
    }

    /// <summary>
    /// Per DIF peer-DID spec: if the service has an explicit ID, preserve it;
    /// otherwise auto-generate: first = "#service", subsequent = "#service-1", "#service-2", etc.
    /// IDs use relative fragment form per spec.
    /// </summary>
    private static string GenerateServiceId(string? existingId, ref int autoServiceIndex)
    {
        if (!string.IsNullOrEmpty(existingId) && existingId.StartsWith('#'))
            return existingId;

        var fragment = autoServiceIndex == 0 ? "#service" : $"#service-{autoServiceIndex}";
        autoServiceIndex++;
        return fragment;
    }
}
