using System.Text.Json;
using NetDid.Core.Model;

namespace NetDid.Method.WebVh;

/// <summary>
/// Projects the services defined implicitly by did:webvh onto resolver and parallel did:web
/// output. The projection never mutates the controller-authored document stored in the signed log.
/// </summary>
internal static class ImplicitWebVhServices
{
    internal const string FilesFragment = "files";
    internal const string WhoisFragment = "whois";
    internal const string LinkedVpContext = "https://identity.foundation/linked-vp/contexts/v1";

    // projectionDid: the DID of the parallel did:web document when projecting for did.json. There,
    // a service id in that DID's form (e.g. "did:web:example.com#whois") is the override too
    // (issue #145).
    internal static DidDocument Materialize(string did, DidDocument document, string? projectionDid = null)
    {
        var services = document.Service?.Select(CanonicalizeConventionalId).ToList() ?? [];
        var resourceBase = DidUrlMapper.MapToResourceBaseUrl(did);

        if (!ContainsService(services, document.Id.Value, did, FilesFragment, projectionDid))
        {
            services.Add(new Service
            {
                Id = "#files",
                Type = "relativeRef",
                ServiceEndpoint = ServiceEndpointValue.FromUri(resourceBase.AbsoluteUri)
            });
        }

        if (!ContainsService(services, document.Id.Value, did, WhoisFragment, projectionDid))
        {
            services.Add(new Service
            {
                Id = "#whois",
                Type = "LinkedVerifiablePresentation",
                ServiceEndpoint = ServiceEndpointValue.FromUri(
                    new Uri(resourceBase, "whois.vp").AbsoluteUri),
                AdditionalProperties = new Dictionary<string, JsonElement>
                {
                    ["@context"] = JsonSerializer.SerializeToElement(LinkedVpContext)
                }
            });
        }

        return document with { Service = services };
    }

    private static Service CanonicalizeConventionalId(Service service)
    {
        var canonicalId = service.Id switch
        {
            FilesFragment => "#files",
            WhoisFragment => "#whois",
            _ => service.Id
        };
        if (canonicalId == service.Id)
            return service;

        return new Service
        {
            Id = canonicalId,
            Type = service.Type,
            ServiceEndpoint = service.ServiceEndpoint,
            AdditionalProperties = service.AdditionalProperties
        };
    }

    private static bool ContainsService(
        IEnumerable<Service> services, string documentDid, string requestedDid, string fragment,
        string? projectionDid)
    {
        var relativeId = $"#{fragment}";
        var documentId = $"{documentDid}{relativeId}";
        var requestedId = $"{requestedDid}{relativeId}";
        var projectedId = projectionDid is null ? null : $"{projectionDid}{relativeId}";

        return services.Any(service =>
            string.Equals(service.Id, fragment, StringComparison.Ordinal)
            || string.Equals(service.Id, relativeId, StringComparison.Ordinal)
            || string.Equals(service.Id, documentId, StringComparison.Ordinal)
            || string.Equals(service.Id, requestedId, StringComparison.Ordinal)
            || string.Equals(service.Id, projectedId, StringComparison.Ordinal));
    }
}
