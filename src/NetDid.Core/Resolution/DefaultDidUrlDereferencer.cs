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

        var doc = resolution.DidDocument;

        // Step 2a: Service endpoint selection by service id (§7.2 service query)
        if (queryParams.TryGetValue("service", out var serviceId))
        {
            var service = FindServiceById(doc, serviceId);
            if (service is null)
                return DidUrlDereferencingResult.Error("notFound");

            return BuildServiceResult(service, doc, parsed, queryParams, accept);
        }

        // Step 2b: Service endpoint selection by service type
        if (queryParams.TryGetValue("serviceType", out var serviceType))
        {
            var matchingServices = FindServicesByType(doc, serviceType);
            if (matchingServices.Count == 0)
                return DidUrlDereferencingResult.Error("notFound");

            // For text/uri-list, redirect to the first URI-type or set endpoint
            if (accept == "text/uri-list")
            {
                var redirectable = matchingServices.FirstOrDefault(s =>
                    s.ServiceEndpoint.IsUri || s.ServiceEndpoint.IsSet);
                if (redirectable is null)
                    return DidUrlDereferencingResult.Error("notFound");
                return BuildServiceResult(redirectable, doc, parsed, queryParams, accept);
            }

            // Return a DID Document containing the matched service(s)
            var filteredDoc = new DidDocument { Id = doc.Id, Service = matchingServices.ToList() };
            return DidUrlDereferencingResult.Success(filteredDoc, accept);
        }

        // Step 3: Fragment-only → select resource from DID Document
        if (parsed.Fragment is not null)
        {
            var resource = FindByFragment(doc, parsed.Fragment, options?.VerificationRelationship);
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
        Service service, DidDocument doc, DidUrl parsed,
        Dictionary<string, string> queryParams, string accept)
    {
        // When Accept is text/uri-list, return a redirect URL
        if (accept == "text/uri-list")
        {
            var path = parsed.Path;
            var relativeRef = queryParams.GetValueOrDefault("relativeRef");
            var fragment = parsed.Fragment;

            if (service.ServiceEndpoint.IsUri)
            {
                var serviceUrl = ConstructServiceUrl(
                    service.ServiceEndpoint, path, relativeRef, fragment);
                return DidUrlDereferencingResult.ServiceEndpointRedirect(serviceUrl);
            }

            if (service.ServiceEndpoint.IsSet)
            {
                var uris = service.ServiceEndpoint.Set!
                    .Where(ep => ep.IsUri)
                    .Select(ep => ConstructServiceUrl(ep, path, relativeRef, fragment))
                    .ToList();
                if (uris.Count == 0)
                    return DidUrlDereferencingResult.Error("notFound");
                return DidUrlDereferencingResult.ServiceEndpointRedirect(
                    string.Join("\r\n", uris));
            }

            // Map or other non-URI endpoint can't produce a URI list
            return DidUrlDereferencingResult.Error("notFound");
        }

        // Default: return a DID Document containing the selected service
        var filteredDoc = new DidDocument { Id = doc.Id, Service = [service] };
        return DidUrlDereferencingResult.Success(filteredDoc, accept);
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
            // Match against full service ID or fragment portion
            if (s.Id == serviceId) return true;
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

    private static object? FindByFragment(DidDocument doc, string fragment,
        string? verificationRelationship = null)
    {
        // When verificationRelationship is specified, only search that relationship
        if (verificationRelationship is not null)
        {
            var entries = GetRelationshipEntries(doc, verificationRelationship);
            if (entries is null) return null;

            // Check for embedded VM in the specified relationship
            var embedded = FindEmbeddedVmByFragment(entries, fragment);
            if (embedded is not null) return embedded;

            // Check for referenced VM by matching fragment in the relationship
            if (doc.VerificationMethod is not null)
            {
                foreach (var entry in entries)
                {
                    if (!entry.IsReference) continue;
                    var vm = FindVmByFragment(doc.VerificationMethod, fragment);
                    if (vm is not null)
                    {
                        // Verify the reference actually points to this VM
                        var refFragment = entry.Reference!.Contains('#')
                            ? entry.Reference[(entry.Reference.IndexOf('#') + 1)..]
                            : entry.Reference;
                        if (refFragment == fragment) return vm;
                    }
                }
            }

            return null;
        }

        // Search top-level verification methods
        if (doc.VerificationMethod is not null)
        {
            var vm = FindVmByFragment(doc.VerificationMethod, fragment);
            if (vm is not null) return vm;
        }

        // Search embedded verification methods in all relationship arrays
        var embeddedVm = FindEmbeddedVmByFragment(doc.Authentication, fragment)
            ?? FindEmbeddedVmByFragment(doc.AssertionMethod, fragment)
            ?? FindEmbeddedVmByFragment(doc.KeyAgreement, fragment)
            ?? FindEmbeddedVmByFragment(doc.CapabilityInvocation, fragment)
            ?? FindEmbeddedVmByFragment(doc.CapabilityDelegation, fragment);
        if (embeddedVm is not null) return embeddedVm;

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

    private static IReadOnlyList<VerificationRelationshipEntry>? GetRelationshipEntries(
        DidDocument doc, string relationship) => relationship switch
    {
        "authentication" => doc.Authentication,
        "assertionMethod" => doc.AssertionMethod,
        "keyAgreement" => doc.KeyAgreement,
        "capabilityInvocation" => doc.CapabilityInvocation,
        "capabilityDelegation" => doc.CapabilityDelegation,
        _ => null
    };

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
