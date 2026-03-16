using System.Web;
using NetDid.Core.Model;
using NetDid.Core.Parsing;

namespace NetDid.Core.Resolution;

/// <summary>
/// Default implementation of <see cref="IDidUrlDereferencer"/>.
/// Implements the W3C §7.2 dereferencing algorithm.
/// </summary>
public sealed class DefaultDidUrlDereferencer : IDidUrlDereferencer
{
    private readonly IDidResolver _resolver;

    public DefaultDidUrlDereferencer(IDidResolver resolver)
        => _resolver = resolver;

    public async Task<DidUrlDereferencingResult> DereferenceAsync(
        string didUrl, DidUrlDereferencingOptions? options = null, CancellationToken ct = default)
    {
        var parsed = DidParser.ParseDidUrl(didUrl);
        if (parsed is null)
            return DidUrlDereferencingResult.Error("invalidDidUrl");

        var accept = options?.Accept ?? DidContentTypes.JsonLd;
        var queryParams = ParseQueryString(parsed.Query);

        // Step 1: Resolve the base DID, passing through versionId/versionTime if present
        var resolutionOptions = new DidResolutionOptions
        {
            Accept = accept,
            VersionId = queryParams.GetValueOrDefault("versionId"),
            VersionTime = queryParams.GetValueOrDefault("versionTime")
        };
        var resolution = await _resolver.ResolveAsync(parsed.Did, resolutionOptions, ct);
        if (resolution.DidDocument is null)
            return DidUrlDereferencingResult.Error(resolution.ResolutionMetadata.Error ?? "notFound");

        // Step 2a: Service endpoint selection by service id (§7.2 service query)
        if (queryParams.TryGetValue("service", out var serviceId))
        {
            var service = FindServiceById(resolution.DidDocument, serviceId);
            if (service is null)
                return DidUrlDereferencingResult.Error("notFound");

            return BuildServiceResult(service, parsed, queryParams, accept);
        }

        // Step 2b: Service endpoint selection by service type
        if (queryParams.TryGetValue("serviceType", out var serviceType))
        {
            var matchingServices = FindServicesByType(resolution.DidDocument, serviceType);
            if (matchingServices.Count == 0)
                return DidUrlDereferencingResult.Error("notFound");

            // For text/uri-list, redirect to the first URI-type endpoint
            if (accept == "text/uri-list")
            {
                var uriService = matchingServices.FirstOrDefault(s => s.ServiceEndpoint.IsUri);
                if (uriService is null)
                    return DidUrlDereferencingResult.Error("notFound");
                return BuildServiceResult(uriService, parsed, queryParams, accept);
            }

            // Otherwise return the matched service(s)
            if (matchingServices.Count == 1)
                return DidUrlDereferencingResult.Success(matchingServices[0], accept);

            return DidUrlDereferencingResult.Success(matchingServices, accept);
        }

        // Step 3: Fragment-only → select resource from DID Document
        if (parsed.Fragment is not null)
        {
            var resource = FindByFragment(resolution.DidDocument, parsed.Fragment);
            if (resource is null)
                return DidUrlDereferencingResult.Error("notFound");
            return DidUrlDereferencingResult.Success(resource, accept);
        }

        // Step 4: Path without service query → DID Core does not define semantics
        if (parsed.Path is not null)
            return DidUrlDereferencingResult.Error("notFound");

        // No path, fragment, or service query: return the full DID Document
        return DidUrlDereferencingResult.Success(
            resolution.DidDocument, accept,
            resolution.DocumentMetadata);
    }

    private static DidUrlDereferencingResult BuildServiceResult(
        Service service, DidUrl parsed, Dictionary<string, string> queryParams, string accept)
    {
        // When Accept is text/uri-list and endpoint is a URI, return a redirect
        if (accept == "text/uri-list")
        {
            if (!service.ServiceEndpoint.IsUri)
                return DidUrlDereferencingResult.Error("notFound");

            var serviceUrl = ConstructServiceUrl(
                service.ServiceEndpoint,
                parsed.Path,
                queryParams.GetValueOrDefault("relativeRef"),
                parsed.Fragment);

            return DidUrlDereferencingResult.ServiceEndpointRedirect(serviceUrl);
        }

        // Default: return the service object itself
        return DidUrlDereferencingResult.Success(service, accept);
    }

    private static Dictionary<string, string> ParseQueryString(string? query)
    {
        if (string.IsNullOrEmpty(query))
            return new Dictionary<string, string>();

        var result = new Dictionary<string, string>();
        var pairs = query.Split('&');
        foreach (var pair in pairs)
        {
            var parts = pair.Split('=', 2);
            if (parts.Length == 2)
                result[HttpUtility.UrlDecode(parts[0])] = HttpUtility.UrlDecode(parts[1]);
            else if (parts.Length == 1)
                result[HttpUtility.UrlDecode(parts[0])] = string.Empty;
        }
        return result;
    }

    private static Service? FindServiceById(DidDocument doc, string serviceId)
    {
        if (doc.Service is null) return null;

        return doc.Service.FirstOrDefault(s =>
        {
            // Match against fragment portion of service id
            var hashIndex = s.Id.IndexOf('#');
            var fragment = hashIndex >= 0 ? s.Id[(hashIndex + 1)..] : s.Id;
            return fragment == serviceId;
        });
    }

    private static IReadOnlyList<Service> FindServicesByType(DidDocument doc, string serviceType)
    {
        if (doc.Service is null) return [];
        return doc.Service.Where(s => s.Type == serviceType).ToList();
    }

    private static object? FindByFragment(DidDocument doc, string fragment)
    {
        // Search top-level verification methods
        if (doc.VerificationMethod is not null)
        {
            var vm = FindVmByFragment(doc.VerificationMethod, fragment);
            if (vm is not null) return vm;
        }

        // Search embedded verification methods in all relationship arrays
        var embedded = FindEmbeddedVmByFragment(doc.Authentication, fragment)
            ?? FindEmbeddedVmByFragment(doc.AssertionMethod, fragment)
            ?? FindEmbeddedVmByFragment(doc.KeyAgreement, fragment)
            ?? FindEmbeddedVmByFragment(doc.CapabilityInvocation, fragment)
            ?? FindEmbeddedVmByFragment(doc.CapabilityDelegation, fragment);
        if (embedded is not null) return embedded;

        // Search services
        if (doc.Service is not null)
        {
            var svc = doc.Service.FirstOrDefault(s =>
            {
                var hashIndex = s.Id.IndexOf('#');
                var svcFragment = hashIndex >= 0 ? s.Id[(hashIndex + 1)..] : s.Id;
                return svcFragment == fragment;
            });
            if (svc is not null) return svc;
        }

        return null;
    }

    private static VerificationMethod? FindVmByFragment(
        IReadOnlyList<VerificationMethod> methods, string fragment)
    {
        return methods.FirstOrDefault(v =>
        {
            var hashIndex = v.Id.IndexOf('#');
            var vmFragment = hashIndex >= 0 ? v.Id[(hashIndex + 1)..] : v.Id;
            return vmFragment == fragment;
        });
    }

    private static VerificationMethod? FindEmbeddedVmByFragment(
        IReadOnlyList<VerificationRelationshipEntry>? entries, string fragment)
    {
        if (entries is null) return null;
        foreach (var entry in entries)
        {
            if (!entry.IsReference && entry.EmbeddedMethod is not null)
            {
                var hashIndex = entry.EmbeddedMethod.Id.IndexOf('#');
                var vmFragment = hashIndex >= 0 ? entry.EmbeddedMethod.Id[(hashIndex + 1)..] : entry.EmbeddedMethod.Id;
                if (vmFragment == fragment) return entry.EmbeddedMethod;
            }
        }
        return null;
    }

    /// <summary>
    /// Construct a service endpoint URL using RFC 3986 reference resolution.
    /// </summary>
    private static string ConstructServiceUrl(
        ServiceEndpointValue endpoint, string? path, string? relativeRef, string? fragment)
    {
        var baseUri = new Uri(endpoint.Uri!);

        // Build the relative reference from path, relativeRef, and fragment
        var relative = string.Empty;
        if (path is not null)
            relative += path;
        if (relativeRef is not null)
            relative += relativeRef;
        if (fragment is not null)
            relative += "#" + fragment;

        if (string.IsNullOrEmpty(relative))
            return baseUri.ToString();

        // Use System.Uri for RFC 3986 reference resolution
        var resolved = new Uri(baseUri, relative);
        return resolved.ToString();
    }
}
