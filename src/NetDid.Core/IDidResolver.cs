using NetDid.Core.Model;

namespace NetDid.Core;

/// <summary>
/// Standalone resolver interface for consumers who only need to resolve, not create.
/// </summary>
public interface IDidResolver
{
    Task<DidResolutionResult> ResolveAsync(string did, DidResolutionOptions? options = null, CancellationToken ct = default);
    bool CanResolve(string did);
}
