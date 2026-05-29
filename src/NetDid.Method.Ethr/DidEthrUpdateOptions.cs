using NetDid.Core.Model;

namespace NetDid.Method.Ethr;

/// <summary>
/// Update options for did:ethr. Carries the full Phase 2 property shape so the API
/// is stable; Phase 1 body throws OperationNotSupportedException.
/// </summary>
public sealed record DidEthrUpdateOptions : DidUpdateOptions
{
    public IReadOnlyList<DidEthrServiceAttribute>? AddServices { get; init; }
    public IReadOnlyList<DidEthrServiceAttribute>? RemoveServices { get; init; }
    public IReadOnlyList<DidEthrDelegate>? AddDelegates { get; init; }
    public IReadOnlyList<DidEthrDelegate>? RevokeDelegates { get; init; }
    public string? NewOwnerAddress { get; init; }
    public required NetDid.Core.ISigner ControllerKey { get; init; }
    public bool UseMetaTransaction { get; init; } = false;
}

public sealed record DidEthrDelegate
{
    public required string DelegateType { get; init; }     // "veriKey", "sigAuth"
    public required string DelegateAddress { get; init; }
    public required TimeSpan Validity { get; init; }
}

public sealed record DidEthrServiceAttribute
{
    public required string ServiceType { get; init; }
    public required string ServiceEndpoint { get; init; }
    public TimeSpan Validity { get; init; } = TimeSpan.FromDays(365 * 10);
}
