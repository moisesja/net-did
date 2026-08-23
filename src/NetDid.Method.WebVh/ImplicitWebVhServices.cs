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

    internal static DidDocument Materialize(string did, DidDocument document)
    {
        var services = document.Service?.ToList() ?? [];
        var resourceBase = DidUrlMapper.MapToResourceBaseUrl(did);

        if (!ContainsService(services, document.Id.Value, did, FilesFragment))
        {
            services.Add(new Service
            {
                Id = "#files",
                Type = "relativeRef",
                ServiceEndpoint = ServiceEndpointValue.FromUri(resourceBase.AbsoluteUri)
            });
        }

        if (!ContainsService(services, document.Id.Value, did, WhoisFragment))
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

    private static bool ContainsService(
        IEnumerable<Service> services, string documentDid, string requestedDid, string fragment)
    {
        var relativeId = $"#{fragment}";
        var documentId = $"{documentDid}{relativeId}";
        var requestedId = $"{requestedDid}{relativeId}";

        return services.Any(service =>
            string.Equals(service.Id, relativeId, StringComparison.Ordinal)
            || string.Equals(service.Id, documentId, StringComparison.Ordinal)
            || string.Equals(service.Id, requestedId, StringComparison.Ordinal));
    }
}
