using System.Text.Json;

namespace NetDid.Core.Model;

public sealed record DidDocument
{
    public required Did Id { get; init; }
    public IReadOnlyList<string>? AlsoKnownAs { get; init; }

    /// <summary>
    /// W3C DID Core §5.1.2: controller is a single DID or an ordered set of DIDs.
    /// Serialized as a string when Count == 1, as an array when Count > 1, omitted when null.
    /// </summary>
    public IReadOnlyList<Did>? Controller { get; init; }

    public IReadOnlyList<VerificationMethod>? VerificationMethod { get; init; }
    public IReadOnlyList<VerificationRelationshipEntry>? Authentication { get; init; }
    public IReadOnlyList<VerificationRelationshipEntry>? AssertionMethod { get; init; }
    public IReadOnlyList<VerificationRelationshipEntry>? KeyAgreement { get; init; }
    public IReadOnlyList<VerificationRelationshipEntry>? CapabilityInvocation { get; init; }
    public IReadOnlyList<VerificationRelationshipEntry>? CapabilityDelegation { get; init; }

    public IReadOnlyList<Service>? Service { get; init; }

    /// <summary>
    /// JSON-LD @context. Present only when the document is produced as application/did+ld+json.
    /// When set, MUST include "https://www.w3.org/ns/did/v1" as the first entry.
    /// </summary>
    public IReadOnlyList<object>? Context { get; init; }

    /// <summary>Extension properties not defined in DID Core.</summary>
    public IReadOnlyDictionary<string, JsonElement>? AdditionalProperties { get; init; }
}
