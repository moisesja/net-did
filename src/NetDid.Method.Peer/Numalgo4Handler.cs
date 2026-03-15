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
    // JSON multicodec code 0x0200, varint-encoded as [0x80, 0x04]
    private const ulong JsonMulticodec = 0x0200;

    public DidCreateResult Create(DidPeerCreateOptions options)
    {
        if (options.InputDocument is null)
            throw new ArgumentException("Numalgo 4 requires InputDocument.");

        // Per did:peer:4 spec:
        // 1. JSON stringify → UTF-8 bytes → multicodec prefix (JSON 0x0200) → multibase base58btc
        // 2. Hash the multibase-encoded STRING, not the raw bytes
        // 3. Multihash prefix [0x12, 0x20] → multibase base58btc
        var json = DidDocumentSerializer.Serialize(options.InputDocument, DidContentTypes.JsonLd);
        var docBytes = Encoding.UTF8.GetBytes(json);

        // Long-form: multicodec(JSON) prefix + multibase base58btc
        var multicodecPrefixed = Multicodec.Prefix(JsonMulticodec, docBytes);
        var longForm = Multibase.Encode(multicodecPrefixed, MultibaseEncoding.Base58Btc);

        // Short-form: SHA-256 hash of the multibase-encoded long-form STRING bytes
        var longFormStringBytes = Encoding.UTF8.GetBytes(longForm);
        var hash = SHA256.HashData(longFormStringBytes);
        var multihash = Multihash.Encode(0x12, hash); // 0x12 = sha2-256
        var shortForm = Multibase.Encode(multihash, MultibaseEncoding.Base58Btc);

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

        // Decode long-form: multibase decode → strip multicodec JSON prefix → UTF-8 JSON
        byte[] multicodecPrefixed;
        try
        {
            multicodecPrefixed = Multibase.Decode(longForm);
        }
        catch
        {
            return null;
        }

        // Strip multicodec JSON prefix and get raw document bytes
        byte[] docBytes;
        try
        {
            var (code, rawBytes) = Multicodec.Decode(multicodecPrefixed);
            if (code != JsonMulticodec)
                return null; // Wrong multicodec — not a JSON document
            docBytes = rawBytes;
        }
        catch
        {
            return null;
        }

        // Verify the hash: SHA-256 of the long-form multibase STRING bytes
        var longFormStringBytes = Encoding.UTF8.GetBytes(longForm);
        var hash = SHA256.HashData(longFormStringBytes);
        var multihash = Multihash.Encode(0x12, hash);
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
        var originalDid = inputDoc.Id.Value;

        // Replace the id with the actual DID and prefix relative references
        var verificationMethods = inputDoc.VerificationMethod?.Select(vm =>
            RewriteVerificationMethod(vm, did, didValue, originalDid)).ToList();

        // Rewrite controller references
        var controller = inputDoc.Controller?.Select(c =>
            c.Value == originalDid ? didValue : c).ToList();

        // Per spec: alsoKnownAs must include the short-form DID
        var shortFormDid = ExtractShortFormDid(did);
        var alsoKnownAs = inputDoc.AlsoKnownAs?.ToList() ?? [];
        if (shortFormDid is not null && !alsoKnownAs.Contains(shortFormDid))
            alsoKnownAs.Add(shortFormDid);

        return new DidDocument
        {
            Id = didValue,
            Controller = controller,
            VerificationMethod = verificationMethods,
            Authentication = RewriteRelationships(inputDoc.Authentication, did, didValue, originalDid),
            AssertionMethod = RewriteRelationships(inputDoc.AssertionMethod, did, didValue, originalDid),
            KeyAgreement = RewriteRelationships(inputDoc.KeyAgreement, did, didValue, originalDid),
            CapabilityInvocation = RewriteRelationships(inputDoc.CapabilityInvocation, did, didValue, originalDid),
            CapabilityDelegation = RewriteRelationships(inputDoc.CapabilityDelegation, did, didValue, originalDid),
            Service = inputDoc.Service?.Select((svc, i) => new Service
            {
                Id = PrefixId(svc.Id, did),
                Type = svc.Type,
                ServiceEndpoint = svc.ServiceEndpoint,
                AdditionalProperties = svc.AdditionalProperties
            }).ToList(),
            AlsoKnownAs = alsoKnownAs.Count > 0 ? alsoKnownAs : null,
            Context = inputDoc.Context,
            AdditionalProperties = inputDoc.AdditionalProperties
        };
    }

    /// <summary>
    /// Extract the short-form DID from a long-form did:peer:4 DID.
    /// Long-form: did:peer:4{hash}:{encoded} → Short-form: did:peer:4{hash}
    /// </summary>
    private static string? ExtractShortFormDid(string did)
    {
        // did = "did:peer:4{shortForm}:{longForm}"
        // We need to find the ':' after "did:peer:4..."
        const string prefix = "did:peer:4";
        if (!did.StartsWith(prefix)) return null;

        var rest = did[prefix.Length..];
        var colonIdx = rest.IndexOf(':');
        if (colonIdx < 0) return null; // Already short-form

        return prefix + rest[..colonIdx];
    }

    private static VerificationMethod RewriteVerificationMethod(
        VerificationMethod vm, string did, Did didValue, string originalDid)
    {
        return new VerificationMethod
        {
            Id = PrefixId(vm.Id, did),
            Type = vm.Type,
            Controller = vm.Controller.Value == originalDid ? didValue : vm.Controller,
            PublicKeyMultibase = vm.PublicKeyMultibase,
            PublicKeyJwk = vm.PublicKeyJwk,
            BlockchainAccountId = vm.BlockchainAccountId
        };
    }

    private static string PrefixId(string id, string did)
    {
        // If the id starts with '#', prefix with the DID
        if (id.StartsWith('#'))
            return did + id;
        return id;
    }

    private static List<VerificationRelationshipEntry>? RewriteRelationships(
        IReadOnlyList<VerificationRelationshipEntry>? entries, string did, Did didValue, string originalDid)
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

            // Embedded verification method — rewrite it too
            if (entry.EmbeddedMethod is not null)
            {
                var rewritten = RewriteVerificationMethod(entry.EmbeddedMethod, did, didValue, originalDid);
                return VerificationRelationshipEntry.FromEmbedded(rewritten);
            }

            return entry;
        }).ToList();
    }
}
