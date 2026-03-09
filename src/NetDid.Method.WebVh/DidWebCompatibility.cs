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

        // Build alsoKnownAs: include the did:webvh DID and any existing alsoKnownAs
        var alsoKnownAs = new List<string> { didWebVh };
        if (document.AlsoKnownAs is not null)
        {
            foreach (var aka in document.AlsoKnownAs)
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
            Controller = document.Controller,
            VerificationMethod = document.VerificationMethod?.Select(vm =>
                RewriteVerificationMethod(vm, didWebVh, didWeb, didWebValue)).ToList(),
            Authentication = RewriteRelationships(document.Authentication, didWebVh, didWeb),
            AssertionMethod = RewriteRelationships(document.AssertionMethod, didWebVh, didWeb),
            KeyAgreement = RewriteRelationships(document.KeyAgreement, didWebVh, didWeb),
            CapabilityInvocation = RewriteRelationships(document.CapabilityInvocation, didWebVh, didWeb),
            CapabilityDelegation = RewriteRelationships(document.CapabilityDelegation, didWebVh, didWeb),
            Service = document.Service,
            Context = document.Context,
            AdditionalProperties = document.AdditionalProperties
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
}
