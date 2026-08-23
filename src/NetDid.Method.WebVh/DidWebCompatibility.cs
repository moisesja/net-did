using System.Text;
using NetDid.Core;
using NetDid.Core.Model;
using NetDid.Core.Serialization;

namespace NetDid.Method.WebVh;

/// <summary>
/// Converts did:webvh artifacts to did:web compatible format.
///
/// did:webvh:QmRwq46V...:example.com  ->  did:web:example.com
///
/// Generates a did.json file with the DID Document, replacing the id
/// with the did:web equivalent and adding alsoKnownAs linking back
/// to the did:webvh identifier.
/// </summary>
internal static class DidWebCompatibility
{
    /// <summary>
    /// Convert a did:webvh DID to its did:web equivalent.
    /// Drops the SCID segment and replaces the method name.
    /// </summary>
    public static string ToDidWeb(string didWebVh)
    {
        var domain = DidUrlMapper.ExtractDomain(didWebVh);
        var path = DidUrlMapper.ExtractPath(didWebVh);

        if (path is not null)
        {
            // Reformat path separators: did:web uses : for path separators
            var pathParts = path.Split('/');
            return $"did:web:{domain}:{string.Join(":", pathParts)}";
        }

        return $"did:web:{domain}";
    }

    /// <summary>
    /// Generate a did.json file content for did:web compatibility.
    /// The document uses the did:web identifier as id and includes
    /// alsoKnownAs linking back to the did:webvh DID.
    /// </summary>
    public static byte[] GenerateDidJson(string didWebVh, DidDocument document)
    {
        var didWeb = ToDidWeb(didWebVh);
        var didWebValue = new Did(didWeb);
        var projectedDocument = ImplicitWebVhServices.Materialize(didWebVh, document);

        // Build alsoKnownAs: include the did:webvh DID and any existing alsoKnownAs
        var alsoKnownAs = new List<string> { didWebVh };
        if (projectedDocument.AlsoKnownAs is not null)
        {
            foreach (var aka in projectedDocument.AlsoKnownAs)
            {
                if (aka != didWebVh)
                    alsoKnownAs.Add(aka);
            }
        }

        // Rewrite the document with did:web id
        var webDoc = new DidDocument
        {
            Id = didWebValue,
            AlsoKnownAs = alsoKnownAs,
            Controller = projectedDocument.Controller,
            VerificationMethod = projectedDocument.VerificationMethod?.Select(vm =>
                RewriteVerificationMethod(vm, didWebVh, didWeb, didWebValue)).ToList(),
            Authentication = RewriteRelationships(projectedDocument.Authentication, didWebVh, didWeb),
            AssertionMethod = RewriteRelationships(projectedDocument.AssertionMethod, didWebVh, didWeb),
            KeyAgreement = RewriteRelationships(projectedDocument.KeyAgreement, didWebVh, didWeb),
            CapabilityInvocation = RewriteRelationships(projectedDocument.CapabilityInvocation, didWebVh, didWeb),
            CapabilityDelegation = RewriteRelationships(projectedDocument.CapabilityDelegation, didWebVh, didWeb),
            Service = RewriteServices(projectedDocument.Service, didWebVh, didWeb),
            Context = projectedDocument.Context,
            AdditionalProperties = projectedDocument.AdditionalProperties
        };

        var json = DidDocumentSerializer.Serialize(webDoc, DidContentTypes.JsonLd);
        return Encoding.UTF8.GetBytes(json);
    }

    private static VerificationMethod RewriteVerificationMethod(
        VerificationMethod vm, string fromDid, string toDid, Did toDidValue)
    {
        return new VerificationMethod
        {
            Id = vm.Id.Replace(fromDid, toDid),
            Type = vm.Type,
            Controller = vm.Controller.Value == fromDid ? toDidValue : vm.Controller,
            PublicKeyMultibase = vm.PublicKeyMultibase,
            PublicKeyJwk = vm.PublicKeyJwk,
            BlockchainAccountId = vm.BlockchainAccountId
        };
    }

    private static List<VerificationRelationshipEntry>? RewriteRelationships(
        IReadOnlyList<VerificationRelationshipEntry>? entries, string fromDid, string toDid)
    {
        if (entries is null) return null;

        return entries.Select(entry =>
        {
            if (entry.IsReference)
                return VerificationRelationshipEntry.FromReference(entry.Reference!.Replace(fromDid, toDid));
            return entry;
        }).ToList();
    }

    private static List<Service>? RewriteServices(
        IReadOnlyList<Service>? services, string fromDid, string toDid)
    {
        if (services is null) return null;

        return services.Select(service => new Service
        {
            Id = IsDidUrlFor(service.Id, fromDid)
                ? toDid + service.Id[fromDid.Length..]
                : service.Id,
            Type = service.Type,
            ServiceEndpoint = service.ServiceEndpoint,
            AdditionalProperties = service.AdditionalProperties
        }).ToList();
    }

    private static bool IsDidUrlFor(string value, string did) =>
        value.StartsWith(did, StringComparison.Ordinal) &&
        (value.Length == did.Length || value[did.Length] is '#' or '/' or '?' or ';');
}
