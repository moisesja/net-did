using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using NetDid.Core.Model;
using NetDid.Core.Parsing;

namespace NetDid.Core.Resolution;

/// <summary>
/// Aggregates multiple method-specific resolvers into a single <see cref="IDidResolver"/>.
/// </summary>
public sealed class CompositeDidResolver : IDidResolver
{
    private readonly IReadOnlyDictionary<string, IDidMethod> _methods;
    private readonly ILogger<CompositeDidResolver> _logger;

    public CompositeDidResolver(IEnumerable<IDidMethod> methods, ILogger<CompositeDidResolver>? logger = null)
    {
        _methods = methods.ToDictionary(m => m.MethodName);
        _logger = logger ?? NullLogger<CompositeDidResolver>.Instance;
        _logger.LogDebug("Initialized with methods: {Methods}", string.Join(", ", _methods.Keys));
    }

    public bool CanResolve(string did)
    {
        var method = DidParser.ExtractMethod(did);
        return method is not null && _methods.ContainsKey(method);
    }

    public async Task<DidResolutionResult> ResolveAsync(string did, DidResolutionOptions? options = null, CancellationToken ct = default)
    {
        if (!DidParser.IsValid(did))
        {
            _logger.LogWarning("Invalid DID syntax: {Did}", did);
            return DidResolutionResult.InvalidDid(did);
        }

        var method = DidParser.ExtractMethod(did);
        if (method is null || !_methods.TryGetValue(method, out var didMethod))
        {
            _logger.LogWarning("Method not supported for DID: {Did}", did);
            return DidResolutionResult.MethodNotSupported(did);
        }

        _logger.LogDebug("Routing resolution to {Method} for {Did}", method, did);
        return await didMethod.ResolveAsync(did, options, ct);
    }
}
