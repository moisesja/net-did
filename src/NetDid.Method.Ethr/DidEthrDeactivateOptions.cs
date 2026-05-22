using NetDid.Core.Model;

namespace NetDid.Method.Ethr;

/// <summary>
/// Deactivate options for did:ethr. Carries the full Phase 2 property shape;
/// Phase 1 body throws OperationNotSupportedException.
/// </summary>
public sealed record DidEthrDeactivateOptions : DidDeactivateOptions
{
    public required NetDid.Core.ISigner ControllerKey { get; init; }
    public bool UseMetaTransaction { get; init; } = false;
}
