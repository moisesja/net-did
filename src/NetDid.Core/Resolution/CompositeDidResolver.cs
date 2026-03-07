using NetDid.Core.Model;
using NetDid.Core.Parsing;

namespace NetDid.Core.Resolution;

/// <summary>
/// Aggregates multiple method-specific resolvers into a single <see cref="IDidResolver"/>.
/// </summary>
public sealed class CompositeDidResolver : IDidResolver
{
    private readonly IReadOnlyDictionary<string, IDidMethod> _methods;

    public CompositeDidResolver(IEnumerable<IDidMethod> methods)
    {
        _methods = methods.ToDictionary(m => m.MethodName);
    }

    public bool CanResolve(string did)
    {
        var method = DidParser.ExtractMethod(did);
        return method is not null && _methods.ContainsKey(method);
    }

    public async Task<DidResolutionResult> ResolveAsync(string did, DidResolutionOptions? options = null, CancellationToken ct = default)
    {
        var method = DidParser.ExtractMethod(did);
        if (method is null || !_methods.TryGetValue(method, out var didMethod))
            return DidResolutionResult.MethodNotSupported(did);

        return await didMethod.ResolveAsync(did, options, ct);
    }
}
