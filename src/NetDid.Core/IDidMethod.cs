using NetDid.Core.Model;

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
    ServiceEndpoints = 16
}
