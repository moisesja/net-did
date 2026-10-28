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
        // 1. JSON stringify the input document (without id) → UTF-8 bytes → multicodec prefix (JSON 0x0200) → multibase base58btc
        // 2. Hash the multibase-encoded STRING, not the raw bytes
        // 3. Multihash prefix [0x12, 0x20] → multibase base58btc
        // Serialize the input document. Using JSON-LD preserves @context for round-trip.
        // The id field is omitted automatically when Id.Value is null (per spec: input doc MUST NOT have id).
        // did:peer:4's template legitimately omits verification-method controllers (they are
        // contextualized to this DID at resolution), so use the internal tolerant serializer; the
        // public Serialize requires a controller on every VM (W3C DID Core §5.2).
        var json = DidDocumentSerializer.SerializeAllowingIncompleteVerificationMethods(
            options.InputDocument, DidContentTypes.JsonLd);
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

        // Build the returned document from the JSON that was hashed, exactly as Resolve does, never
        // from the caller's object again: its lists may read differently a second time, and the
        // result must be the document this DID resolves to (PR #149 review round 2).
        DidDocument encodedDoc;
        try
        {
            encodedDoc = DidDocumentSerializer.DeserializeAllowingIncompleteVerificationMethods(json);
        }
        catch (Exception ex) when (ex is not ArgumentException)
        {
            throw new ArgumentException(
                "The input document does not encode a resolvable did:peer:4 document.", ex);
        }
        var resolvedDoc = BuildResolvedDocument(did, encodedDoc);

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

        // Parse the document. did:peer:4's encoded template legitimately omits verification-method
        // controllers (they are contextualized to this DID below), so use the tolerant internal
        // path rather than the public consumption boundary, which requires a controller per §5.2.
        DidDocument inputDoc;
        try
        {
            // Strict: ill-formed UTF-8 must fail, not resolve as U+FFFD (issue #145).
            var json = new UTF8Encoding(false, throwOnInvalidBytes: true).GetString(docBytes);
            inputDoc = DidDocumentSerializer.DeserializeAllowingIncompleteVerificationMethods(json);
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
        var originalDid = inputDoc.Id.Value; // null if input document has no id (per spec)

        // Replace the id with the actual DID and prefix relative references
        var verificationMethods = inputDoc.VerificationMethod?.Select(vm =>
            RewriteVerificationMethod(vm, did, didValue, originalDid)).ToList();

        // Rewrite controller references
        var controller = inputDoc.Controller?.Select(c =>
            c.Value == originalDid || c.Value is null ? didValue : c).ToList();

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
                Id = PrefixId(svc.Id, did, originalDid),
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
        if (!did.StartsWith(prefix, StringComparison.Ordinal)) return null;

        var rest = did[prefix.Length..];
        var colonIdx = rest.IndexOf(':');
        if (colonIdx < 0) return null; // Already short-form

        return prefix + rest[..colonIdx];
    }

    private static VerificationMethod RewriteVerificationMethod(
        VerificationMethod vm, string did, Did didValue, string? originalDid)
    {
        // Set controller to the DID if it matches the original placeholder or was not set
        // (the template legitimately omits it — contextualization fills it in here).
        var controller = (vm.Controller.Value is null || vm.Controller.Value == originalDid)
            ? didValue : vm.Controller;

        return new VerificationMethod
        {
            Id = PrefixId(vm.Id, did, originalDid),
            Type = vm.Type,
            Controller = controller,
            PublicKeyMultibase = vm.PublicKeyMultibase,
            PublicKeyJwk = vm.PublicKeyJwk,
            BlockchainAccountId = vm.BlockchainAccountId
        };
    }

    private static string PrefixId(string id, string did, string? originalDid)
    {
        // If the id starts with '#', prefix with the DID
        if (id.StartsWith('#'))
            return did + id;
        // An id under the template's placeholder DID is rewritten like a reference to it, so
        // the document's references keep pointing at its own methods and services (issue #145).
        if (IsUnderDid(id, originalDid))
            return did + id[originalDid!.Length..];
        return id;
    }

    // Whether value is originalDid itself or a DID URL of it. "did:example:abcd" is another DID,
    // not "did:example:abc" + "d", so the next character must end the DID.
    private static bool IsUnderDid(string value, string? originalDid)
        => originalDid is not null
           && value.StartsWith(originalDid, StringComparison.Ordinal)
           && (value.Length == originalDid.Length || value[originalDid.Length] is '#' or '/' or '?' or ';');

    private static List<VerificationRelationshipEntry>? RewriteRelationships(
        IReadOnlyList<VerificationRelationshipEntry>? entries, string did, Did didValue, string? originalDid)
    {
        if (entries is null) return null;

        return entries.Select(entry =>
        {
            if (entry.IsReference)
            {
                var reference = entry.Reference!;
                if (reference.StartsWith('#'))
                    reference = did + reference;
                else if (IsUnderDid(reference, originalDid))
                    reference = did + reference[originalDid!.Length..];
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
