using NetCrypto;
using NetDid.Core.Exceptions;
using NetDid.Core.Model;
using NetDid.Core.Parsing;
using NetDid.Core.Recovery;

namespace NetDid.Core;

/// <summary>
/// Base class providing shared validation and routing for DID method implementations.
/// Each method overrides the abstract methods for method-specific logic.
/// </summary>
public abstract class DidMethodBase : IDidMethod, IDidResolver
{
    public abstract string MethodName { get; }
    public abstract DidMethodCapabilities Capabilities { get; }

    /// <summary>
    /// The set of <see cref="KeyType"/> values this method accepts as input keys
    /// when creating a new DID. Concrete drivers MUST declare their accepted set.
    /// </summary>
    public abstract IReadOnlyList<KeyType> SupportedKeyTypes { get; }

    /// <summary>
    /// Whether this method exposes a recovery surface. Default: <c>false</c>.
    /// When overridden to <c>true</c>, <see cref="RecoveryMaterialSpec"/> MUST be non-null.
    /// </summary>
    public virtual bool SupportsRecovery => false;

    /// <summary>
    /// Introspection shape for the recovery material this method emits and consumes.
    /// Default: <c>null</c>. Required to be non-null when <see cref="SupportsRecovery"/> is <c>true</c>.
    /// </summary>
    public virtual RecoveryMaterialSpec? RecoveryMaterialSpec => null;

    public async Task<DidCreateResult> CreateAsync(DidCreateOptions options, CancellationToken ct = default)
    {
        if (!Capabilities.HasFlag(DidMethodCapabilities.Create))
            throw new OperationNotSupportedException(MethodName, "Create");
        return await CreateCoreAsync(options, ct);
    }

    public async Task<DidResolutionResult> ResolveAsync(string did, DidResolutionOptions? options = null, CancellationToken ct = default)
    {
        if (!DidParser.IsValid(did))
            return DidResolutionResult.InvalidDid(did);
        var method = DidParser.ExtractMethod(did);
        if (method != MethodName)
            return DidResolutionResult.MethodNotSupported(did);
        return await ResolveCoreAsync(did, options, ct);
    }

    public async Task<DidUpdateResult> UpdateAsync(string did, DidUpdateOptions options, CancellationToken ct = default)
    {
        if (!Capabilities.HasFlag(DidMethodCapabilities.Update))
            throw new OperationNotSupportedException(MethodName, "Update");
        return await UpdateCoreAsync(did, options, ct);
    }

    public async Task<DidDeactivateResult> DeactivateAsync(string did, DidDeactivateOptions options, CancellationToken ct = default)
    {
        if (!Capabilities.HasFlag(DidMethodCapabilities.Deactivate))
            throw new OperationNotSupportedException(MethodName, "Deactivate");
        return await DeactivateCoreAsync(did, options, ct);
    }

    public bool CanResolve(string did) => DidParser.ExtractMethod(did) == MethodName;

    protected abstract Task<DidCreateResult> CreateCoreAsync(DidCreateOptions options, CancellationToken ct);
    protected abstract Task<DidResolutionResult> ResolveCoreAsync(string did, DidResolutionOptions? options, CancellationToken ct);

    protected virtual Task<DidUpdateResult> UpdateCoreAsync(string did, DidUpdateOptions options, CancellationToken ct)
        => throw new OperationNotSupportedException(MethodName, "Update");

    protected virtual Task<DidDeactivateResult> DeactivateCoreAsync(string did, DidDeactivateOptions options, CancellationToken ct)
        => throw new OperationNotSupportedException(MethodName, "Deactivate");
}
