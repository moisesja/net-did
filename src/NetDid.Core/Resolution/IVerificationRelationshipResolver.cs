using NetDid.Core.Model;

namespace NetDid.Core.Resolution;

/// <summary>
/// Answers, against the <em>controller's</em> DID document, whether a verification method is
/// authorized for a given W3C verification relationship.
/// Used by zcap-dotnet for ZCAP-LD controller-authorization checks (proof-purpose →
/// relationship: <c>capabilityInvocation</c> for invoke, <c>capabilityDelegation</c> for delegate).
/// </summary>
/// <remarks>
/// The check resolves <c>controllerDid</c> (NOT the base DID embedded in
/// <c>verificationMethodDidUrl</c>) so that cross-DID references and per-purpose key separation
/// are honored. Callers passing multiple controllers should query each in turn — this primitive
/// does not walk the resolved document's own <c>controller</c> list.
/// </remarks>
public interface IVerificationRelationshipResolver
{
    /// <summary>
    /// Returns <see cref="AuthorizationDecision.Authorized"/> iff the controller's DID document
    /// contains an entry under <paramref name="relationship"/> that — after normalization against
    /// the document's id — equals <paramref name="verificationMethodDidUrl"/>. Matches both
    /// referenced and embedded entries.
    /// </summary>
    /// <param name="controllerDid">Absolute DID of the controller whose document is consulted
    /// (e.g. <c>"did:web:example.com"</c>). Must be non-empty.</param>
    /// <param name="verificationMethodDidUrl">Identifier of the verification method to check.
    /// Accepts three forms, all normalized against the resolved controller id before comparison:
    /// an absolute DID URL (<c>"did:web:alice.example#key-1"</c>), a fragment-relative
    /// reference (<c>"#key-1"</c> → <c>"{controllerDid}#key-1"</c>), or a bare id
    /// (<c>"key-1"</c> → <c>"{controllerDid}#key-1"</c>). Comparison is ordinal and does NOT
    /// strip query parameters or path segments.</param>
    /// <param name="relationship">The W3C verification relationship to consult.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <exception cref="ArgumentException">Thrown when <paramref name="controllerDid"/> or
    /// <paramref name="verificationMethodDidUrl"/> is null or whitespace.</exception>
    Task<VerificationRelationshipAuthorizationResult> IsAuthorizedForRelationshipAsync(
        string controllerDid,
        string verificationMethodDidUrl,
        VerificationRelationship relationship,
        CancellationToken ct = default);
}
