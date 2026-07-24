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
