namespace NetDid.Core.Resolution;

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
