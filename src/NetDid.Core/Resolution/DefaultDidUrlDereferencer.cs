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

        // Step 2: Service endpoint selection + URL construction (§7.2 service query)
        if (queryParams.TryGetValue("service", out var serviceId))
        {
            var service = FindServiceById(resolution.DidDocument, serviceId);
            if (service is null)
                return DidUrlDereferencingResult.Error("notFound");

            var serviceUrl = ConstructServiceUrl(
                service.ServiceEndpoint,
                parsed.Path,
                queryParams.GetValueOrDefault("relativeRef"),
                parsed.Fragment);

            return DidUrlDereferencingResult.ServiceEndpointRedirect(serviceUrl);
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

    private static object? FindByFragment(DidDocument doc, string fragment)
    {
        // Search verification methods
        if (doc.VerificationMethod is not null)
        {
            var vm = doc.VerificationMethod.FirstOrDefault(v =>
            {
                var hashIndex = v.Id.IndexOf('#');
                var vmFragment = hashIndex >= 0 ? v.Id[(hashIndex + 1)..] : v.Id;
                return vmFragment == fragment;
            });
            if (vm is not null) return vm;
        }

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

    private static string ConstructServiceUrl(
        ServiceEndpointValue endpoint, string? path, string? relativeRef, string? fragment)
    {
        // Get the base service endpoint URI
        var baseUrl = endpoint.IsUri ? endpoint.Uri! : throw new InvalidOperationException(
            "Service endpoint must be a URI for URL construction.");

        // Remove trailing slash from base URL for clean concatenation
        baseUrl = baseUrl.TrimEnd('/');

        var result = baseUrl;

        if (path is not null)
            result += path;

        if (relativeRef is not null)
            result += relativeRef;

        if (fragment is not null)
            result += "#" + fragment;

        return result;
    }
}
