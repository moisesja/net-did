using NetCrypto;
using NetDid.Core.Model;
using NetDid.Core.Recovery;

namespace NetDid.Core;

/// <summary>
/// The unified interface every DID method implements.
/// </summary>
public interface IDidMethod
{
    /// <summary>Method name (e.g., "key", "peer", "webvh", "ethr").</summary>
    string MethodName { get; }

    /// <summary>Which CRUD operations this method supports.</summary>
    DidMethodCapabilities Capabilities { get; }

    /// <summary>
    /// The set of <see cref="KeyType"/> values this method accepts as input keys
    /// when creating a new DID. Used by wallets and other tooling to discover, without
    /// constructing options, which key types a registered method will accept.
    /// Default: empty. Concrete drivers should populate this set.
    /// </summary>
    IReadOnlyList<KeyType> SupportedKeyTypes => Array.Empty<KeyType>();

    /// <summary>
    /// Whether this method exposes a recovery surface. When <c>true</c>,
    /// <see cref="RecoveryMaterialSpec"/> MUST be non-null. The concrete recovery
    /// API per category is defined separately (see ND-E9 / issue #44).
    /// Default: <c>false</c>.
    /// </summary>
    bool SupportsRecovery => false;

    /// <summary>
    /// Introspection shape for the recovery material this method emits and consumes.
    /// Non-null iff <see cref="SupportsRecovery"/> is <c>true</c>. Default: <c>null</c>.
    /// </summary>
    RecoveryMaterialSpec? RecoveryMaterialSpec => null;

    /// <summary>Create a new DID and return the DID Document + any artifacts.</summary>
    Task<DidCreateResult> CreateAsync(DidCreateOptions options, CancellationToken ct = default);

    /// <summary>Resolve a DID to its DID Document.</summary>
    Task<DidResolutionResult> ResolveAsync(string did, DidResolutionOptions? options = null, CancellationToken ct = default);

    /// <summary>Update an existing DID's document (throws for immutable methods).</summary>
    Task<DidUpdateResult> UpdateAsync(string did, DidUpdateOptions options, CancellationToken ct = default);

    /// <summary>Deactivate a DID (throws for immutable methods).</summary>
    Task<DidDeactivateResult> DeactivateAsync(string did, DidDeactivateOptions options, CancellationToken ct = default);
}

[Flags]
public enum DidMethodCapabilities
{
    None = 0,
    Create = 1,
    Resolve = 2,
    Update = 4,
    Deactivate = 8,
    ServiceEndpoints = 16,

    /// <summary>
    /// The method maintains an append-only history of versions. When set, callers may opt
    /// into receiving the parsed history via <see cref="Model.DidResolutionOptions.IncludeLog"/>.
    /// </summary>
    History = 32
}
