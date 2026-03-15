using NetDid.Core.Exceptions;
using NetDid.Core.Model;
using NetDid.Core.Parsing;

namespace NetDid.Core;

/// <summary>
/// Default <see cref="IDidManager"/> implementation that routes operations to registered
/// <see cref="IDidMethod"/> instances by method name.
/// </summary>
public sealed class DidManager : IDidManager, IDidResolver
{
    private readonly IReadOnlyDictionary<string, IDidMethod> _methods;

    public DidManager(IEnumerable<IDidMethod> methods)
    {
        _methods = methods.ToDictionary(m => m.MethodName);
    }

    public IReadOnlyList<string> RegisteredMethods => _methods.Keys.ToList();

    public IDidMethod? GetMethod(string methodName) =>
        _methods.GetValueOrDefault(methodName);

    public Task<DidCreateResult> CreateAsync(string method, DidCreateOptions options, CancellationToken ct = default)
    {
        if (!_methods.TryGetValue(method, out var didMethod))
            throw new MethodNotSupportedException(method);
        return didMethod.CreateAsync(options, ct);
    }

    public Task<DidResolutionResult> ResolveAsync(string did, DidResolutionOptions? options = null, CancellationToken ct = default)
    {
        var method = DidParser.ExtractMethod(did);
        if (method is null || !_methods.TryGetValue(method, out var didMethod))
            return Task.FromResult(DidResolutionResult.MethodNotSupported(did));
        return didMethod.ResolveAsync(did, options, ct);
    }

    public Task<DidUpdateResult> UpdateAsync(string did, DidUpdateOptions options, CancellationToken ct = default)
    {
        var method = DidParser.ExtractMethod(did);
        if (method is null || !_methods.TryGetValue(method, out var didMethod))
            throw new MethodNotSupportedException(method ?? "unknown");
        return didMethod.UpdateAsync(did, options, ct);
    }

    public Task<DidDeactivateResult> DeactivateAsync(string did, DidDeactivateOptions options, CancellationToken ct = default)
    {
        var method = DidParser.ExtractMethod(did);
        if (method is null || !_methods.TryGetValue(method, out var didMethod))
            throw new MethodNotSupportedException(method ?? "unknown");
        return didMethod.DeactivateAsync(did, options, ct);
    }

    public bool CanResolve(string did)
    {
        var method = DidParser.ExtractMethod(did);
        return method is not null && _methods.ContainsKey(method);
    }
}
