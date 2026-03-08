using System.Security.Cryptography;
using System.Text;
using NetCid;
using NetDid.Core;
using NetDid.Core.Model;
using NetDid.Core.Serialization;

namespace NetDid.Method.Peer;

/// <summary>
/// Numalgo 4: short-form hash + long-form encoded document.
/// Short form: did:peer:4{hash}
/// Long form:  did:peer:4{hash}:{encoded-document}
/// </summary>
internal sealed class Numalgo4Handler
{
    public DidCreateResult Create(DidPeerCreateOptions options)
    {
        if (options.InputDocument is null)
            throw new ArgumentException("Numalgo 4 requires InputDocument.");

        // Serialize the input document to JSON
        var json = DidDocumentSerializer.Serialize(options.InputDocument, DidContentTypes.Json);
        var docBytes = Encoding.UTF8.GetBytes(json);

        // Compute SHA-256 hash, multicodec-prefix with SHA-256 code (0x12), then multibase-encode
        var hash = SHA256.HashData(docBytes);
        var multihash = Multicodec.Prefix(0x12, hash); // 0x12 = sha2-256
        var shortForm = Multibase.Encode(multihash, MultibaseEncoding.Base58Btc);

        // Long-form: base64url-encode the document bytes
        var longForm = Convert.ToBase64String(docBytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');

        var did = $"did:peer:4{shortForm}:{longForm}";

        // Build the resolved document with the actual DID as id
        var resolvedDoc = BuildResolvedDocument(did, options.InputDocument);

        return new DidCreateResult
        {
            Did = new Did(did),
            DidDocument = resolvedDoc
        };
    }

    public DidDocument? Resolve(string did, string methodSpecificId)
    {
        // methodSpecificId starts with "4"
        var body = methodSpecificId[1..];

        // Check for long-form (contains ':')
        var colonIndex = body.IndexOf(':');
        if (colonIndex < 0)
        {
            // Short-form only — cannot resolve without prior long-form exchange
            return null;
        }

        var shortForm = body[..colonIndex];
        var longForm = body[(colonIndex + 1)..];

        // Decode the long-form document
        var base64 = longForm.Replace('-', '+').Replace('_', '/');
        switch (base64.Length % 4)
        {
            case 2: base64 += "=="; break;
            case 3: base64 += "="; break;
        }

        byte[] docBytes;
        try
        {
            docBytes = Convert.FromBase64String(base64);
        }
        catch
        {
            return null;
        }

        // Verify the hash matches
        var hash = SHA256.HashData(docBytes);
        var multihash = Multicodec.Prefix(0x12, hash);
        var expectedShortForm = Multibase.Encode(multihash, MultibaseEncoding.Base58Btc);

        if (shortForm != expectedShortForm)
            return null; // Hash mismatch — tampered document

        // Parse the document
        var json = Encoding.UTF8.GetString(docBytes);
        DidDocument inputDoc;
        try
        {
            inputDoc = DidDocumentSerializer.Deserialize(json);
        }
        catch
        {
            return null;
        }

        return BuildResolvedDocument(did, inputDoc);
    }

    private static DidDocument BuildResolvedDocument(string did, DidDocument inputDoc)
    {
        var didValue = new Did(did);

        // Replace the id with the actual DID and prefix relative references
        var verificationMethods = inputDoc.VerificationMethod?.Select(vm => new VerificationMethod
        {
            Id = PrefixId(vm.Id, did),
            Type = vm.Type,
            Controller = vm.Controller.Value == inputDoc.Id.Value ? didValue : vm.Controller,
            PublicKeyMultibase = vm.PublicKeyMultibase,
            PublicKeyJwk = vm.PublicKeyJwk,
            BlockchainAccountId = vm.BlockchainAccountId
        }).ToList();

        return new DidDocument
        {
            Id = didValue,
            Controller = inputDoc.Controller,
            VerificationMethod = verificationMethods,
            Authentication = PrefixRelationships(inputDoc.Authentication, did, inputDoc.Id.Value),
            AssertionMethod = PrefixRelationships(inputDoc.AssertionMethod, did, inputDoc.Id.Value),
            KeyAgreement = PrefixRelationships(inputDoc.KeyAgreement, did, inputDoc.Id.Value),
            CapabilityInvocation = PrefixRelationships(inputDoc.CapabilityInvocation, did, inputDoc.Id.Value),
            CapabilityDelegation = PrefixRelationships(inputDoc.CapabilityDelegation, did, inputDoc.Id.Value),
            Service = inputDoc.Service?.Select((svc, i) => new Service
            {
                Id = PrefixId(svc.Id, did),
                Type = svc.Type,
                ServiceEndpoint = svc.ServiceEndpoint,
                AdditionalProperties = svc.AdditionalProperties
            }).ToList(),
            AlsoKnownAs = inputDoc.AlsoKnownAs
        };
    }

    private static string PrefixId(string id, string did)
    {
        // If the id starts with '#', prefix with the DID
        if (id.StartsWith('#'))
            return did + id;
        return id;
    }

    private static List<VerificationRelationshipEntry>? PrefixRelationships(
        IReadOnlyList<VerificationRelationshipEntry>? entries, string did, string originalDid)
    {
        if (entries is null) return null;

        return entries.Select(entry =>
        {
            if (entry.IsReference)
            {
                var reference = entry.Reference!;
                if (reference.StartsWith('#'))
                    reference = did + reference;
                else if (reference.StartsWith(originalDid))
                    reference = did + reference[originalDid.Length..];
                return VerificationRelationshipEntry.FromReference(reference);
            }

            return entry;
        }).ToList();
    }
}
