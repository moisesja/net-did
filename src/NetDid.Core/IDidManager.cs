using NetDid.Core.Model;

namespace NetDid.Core;

/// <summary>
/// Unified DID lifecycle manager that routes operations across registered DID methods.
/// Inspired by Veramo's IDIDManager pattern — provides a single entry point for
/// Create, Resolve, Update, and Deactivate across all registered methods.
/// </summary>
public interface IDidManager
{
    /// <summary>Create a DID. The method is inferred from the options type.</summary>
    Task<DidCreateResult> CreateAsync(DidCreateOptions options, CancellationToken ct = default);

    /// <summary>Resolve any DID. The method is determined by parsing the DID string.</summary>
    Task<DidResolutionResult> ResolveAsync(string did, DidResolutionOptions? options = null, CancellationToken ct = default);

    /// <summary>Update a DID's document. The method is determined by parsing the DID string.</summary>
    Task<DidUpdateResult> UpdateAsync(string did, DidUpdateOptions options, CancellationToken ct = default);

    /// <summary>Deactivate a DID. The method is determined by parsing the DID string.</summary>
    Task<DidDeactivateResult> DeactivateAsync(string did, DidDeactivateOptions options, CancellationToken ct = default);

    /// <summary>Get the method implementation for a specific method name. Returns null if not registered.</summary>
    IDidMethod? GetMethod(string methodName);

    /// <summary>All registered method names.</summary>
    IReadOnlyList<string> RegisteredMethods { get; }
}
