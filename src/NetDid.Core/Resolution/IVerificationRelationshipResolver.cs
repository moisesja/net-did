using NetDid.Core.Model;

namespace NetDid.Core.Resolution;

/// <summary>
/// The decision returned by <see cref="IVerificationRelationshipResolver"/>. The tri-state shape
/// keeps "infrastructure failed" distinct from "controller's document said no", so a verifier can
/// fail closed and log the underlying cause instead of silently treating both as denial.
/// </summary>
public enum AuthorizationDecision
{
    Authorized,
    NotAuthorized,
    ControllerNotResolvable
}

/// <summary>
/// Outcome of a verification-relationship authorization check. <see cref="ResolutionError"/> and
/// <see cref="Message"/> are populated only when <see cref="Decision"/> is
/// <see cref="AuthorizationDecision.ControllerNotResolvable"/>.
/// </summary>
public sealed record VerificationRelationshipAuthorizationResult
{
    public required AuthorizationDecision Decision { get; init; }

    /// <summary>The underlying resolution error code (e.g. "notFound", "invalidDid", "methodNotSupported").</summary>
    public string? ResolutionError { get; init; }

    /// <summary>Human-readable diagnostic message; never logs key material.</summary>
    public string? Message { get; init; }

    public static VerificationRelationshipAuthorizationResult Authorized() =>
        new() { Decision = AuthorizationDecision.Authorized };

    public static VerificationRelationshipAuthorizationResult NotAuthorized() =>
        new() { Decision = AuthorizationDecision.NotAuthorized };

    public static VerificationRelationshipAuthorizationResult NotResolvable(string error, string message) =>
        new()
        {
            Decision = AuthorizationDecision.ControllerNotResolvable,
            ResolutionError = error,
            Message = message
        };
}

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
    /// <exception cref="ArgumentException">Thrown when <paramref name="controllerDid"/> or
    /// <paramref name="verificationMethodDidUrl"/> is null or whitespace.</exception>
    Task<VerificationRelationshipAuthorizationResult> IsAuthorizedForRelationshipAsync(
        string controllerDid,
        string verificationMethodDidUrl,
        VerificationRelationship relationship,
        CancellationToken ct = default);
}
