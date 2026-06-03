using NetDid.Core.Model;

namespace NetDid.Core.Resolution;

/// <summary>
/// Default <see cref="IVerificationRelationshipResolver"/> backed by an <see cref="IDidResolver"/>.
/// Stateless and thread-safe; rely on the registered resolver (e.g. <see cref="CachingDidResolver"/>)
/// for any caching.
/// </summary>
public sealed class DefaultVerificationRelationshipResolver : IVerificationRelationshipResolver
{
    private readonly IDidResolver _resolver;

    public DefaultVerificationRelationshipResolver(IDidResolver resolver)
    {
        ArgumentNullException.ThrowIfNull(resolver);
        _resolver = resolver;
    }

    public async Task<VerificationRelationshipAuthorizationResult> IsAuthorizedForRelationshipAsync(
        string controllerDid,
        string verificationMethodDidUrl,
        VerificationRelationship relationship,
        CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(controllerDid);
        ArgumentException.ThrowIfNullOrWhiteSpace(verificationMethodDidUrl);

        var resolution = await _resolver.ResolveAsync(controllerDid, options: null, ct).ConfigureAwait(false);
        if (resolution.DidDocument is null)
        {
            var error = resolution.ResolutionMetadata.Error ?? "notFound";
            return VerificationRelationshipAuthorizationResult.NotResolvable(
                error,
                $"Controller DID '{controllerDid}' could not be resolved ({error}).");
        }

        var controllerIdStr = resolution.DidDocument.Id.Value
            ?? throw new InvalidOperationException(
                $"Resolved DID document for '{controllerDid}' has no id.");

        var queryNorm = NormalizeVmId(verificationMethodDidUrl, controllerIdStr);

        var entries = resolution.DidDocument.GetRelationshipEntries(relationship);
        if (entries is null || entries.Count == 0)
            return VerificationRelationshipAuthorizationResult.NotAuthorized();

        foreach (var entry in entries)
        {
            var entryId = entry.IsReference
                ? entry.Reference!
                : entry.EmbeddedMethod?.Id;
            if (entryId is null) continue;

            var entryNorm = NormalizeVmId(entryId, controllerIdStr);
            if (string.Equals(entryNorm, queryNorm, StringComparison.Ordinal))
                return VerificationRelationshipAuthorizationResult.Authorized();
        }

        return VerificationRelationshipAuthorizationResult.NotAuthorized();
    }

    /// <summary>
    /// Resolves a verification-method id against the controller's DID. Mirrors the service-id
    /// normalization in <see cref="DefaultDidUrlDereferencer"/> for VM identifiers:
    /// <c>"#k1"</c> becomes <c>"{controllerDid}#k1"</c>, a bare <c>"k1"</c> (no <c>':'</c>) becomes
    /// <c>"{controllerDid}#k1"</c>, and absolute DID URLs are returned unchanged.
    /// Comparison against entries is ordinal.
    /// </summary>
    private static string NormalizeVmId(string id, string controllerDid)
    {
        if (id.StartsWith('#'))
            return controllerDid + id;
        if (!id.Contains(':'))
            return controllerDid + "#" + id;
        return id;
    }
}
