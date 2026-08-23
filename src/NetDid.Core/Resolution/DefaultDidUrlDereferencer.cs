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

            // For text/uri-list, collect redirect URLs from ALL matching services
            if (accept == "text/uri-list")
            {
                var path = parsed.Path;
                var relativeRef = queryParams.GetValueOrDefault("relativeRef");
                var fragment = parsed.Fragment;
                var allUris = new List<string>();

                foreach (var svc in matchingServices)
                {
                    if (svc.ServiceEndpoint.IsUri)
                        allUris.Add(ConstructServiceUrl(svc.ServiceEndpoint, path, relativeRef, fragment));
                    else if (svc.ServiceEndpoint.IsSet)
                        allUris.AddRange(svc.ServiceEndpoint.Set!
                            .Where(ep => ep.IsUri)
                            .Select(ep => ConstructServiceUrl(ep, path, relativeRef, fragment)));
                }

                if (allUris.Count == 0)
                    return DidUrlDereferencingResult.Error("notFound");
                return DidUrlDereferencingResult.ServiceEndpointRedirect(
                    string.Join("\r\n", allUris));
            }

            // Only DID document content types are valid for non-redirect results
            if (!IsDidDocumentContentType(accept))
                return DidUrlDereferencingResult.Error("representationNotSupported");

            // Return a DID Document containing the matched service(s)
            var filteredDoc = new DidDocument { Id = doc.Id, Service = matchingServices.ToList() };
            return DidUrlDereferencingResult.Success(filteredDoc, accept);
        }

        // Step 3: A conventional #files service maps DID URL paths to external resources.
        // The special /whois path uses #whois directly rather than appending "/whois" to it.
        // did:webvh resolution materializes both implicit services; explicit definitions win.
        if (parsed.Path is not null && parsed.Did.Method == "webvh")
            return BuildPathServiceResult(doc, parsed);

        // Step 4: Fragment-only → select resource from DID Document
        if (parsed.Fragment is not null)
        {
            var resource = FindByFragment(doc, parsed.Fragment, options?.VerificationRelationship);
            if (resource is null)
                return DidUrlDereferencingResult.Error("notFound");
            return DidUrlDereferencingResult.Success(resource, accept);
        }

        // DID Core does not assign generic semantics to a bare path. did:webvh is handled above.
        if (parsed.Path is not null)
            return DidUrlDereferencingResult.Error("notFound");

        // No path, fragment, or service query: return the full DID Document
        return DidUrlDereferencingResult.Success(
            resolution.DidDocument, accept,
            resolution.DocumentMetadata);
    }

    private static DidUrlDereferencingResult BuildPathServiceResult(DidDocument doc, DidUrl parsed)
    {
        var isWhois = string.Equals(parsed.Path, "/whois", StringComparison.Ordinal);
        var service = FindServiceById(doc, isWhois ? "whois" : "files");
        if (service is null)
            return DidUrlDereferencingResult.Error("notFound");

        if (!service.ServiceEndpoint.IsUri
            || !Uri.TryCreate(service.ServiceEndpoint.Uri, UriKind.Absolute, out var endpoint)
            || endpoint.Scheme is not ("http" or "https"))
        {
            return DidUrlDereferencingResult.Error("invalidDid");
        }

        // ParseDidUrl guarantees that a non-null path begins with '/'. Strip exactly that DID
        // URL separator so RFC 3986 resolution appends beneath a deployment-path endpoint rather
        // than treating it as an origin-rooted reference.
        var externalPath = isWhois ? null : parsed.Path![1..];
        if (externalPath is not null && ContainsControlCharacter(externalPath))
            return DidUrlDereferencingResult.Error("invalidDidUrl");

        // Force the stripped path to remain an RFC 3986 relative-path reference. Without this
        // prefix, a valid first segment containing ':' or extra leading slashes can be interpreted
        // as a new scheme or authority instead of content beneath the selected service endpoint.
        var externalUrl = parsed with
        {
            Path = externalPath is null ? null : "./" + externalPath
        };
        string serviceUrl;
        try
        {
            // relativeRef is meaningful only with explicit ?service= selection. A conventional
            // DID URL path is itself the relative reference and must not accept a second one.
            serviceUrl = ConstructServiceUrl(service.ServiceEndpoint, externalUrl.Path, null,
                externalUrl.Fragment);
        }
        catch (UriFormatException)
        {
            return DidUrlDereferencingResult.Error("invalidDidUrl");
        }

        if (!Uri.TryCreate(serviceUrl, UriKind.Absolute, out var resolved)
            || !HasSameAuthority(endpoint, resolved)
            || !IsWithinResolutionBase(endpoint, resolved))
        {
            return DidUrlDereferencingResult.Error("invalidDidUrl");
        }

        return DidUrlDereferencingResult.ServiceEndpointRedirect(resolved.AbsoluteUri);
    }

    private static bool ContainsControlCharacter(string value)
    {
        if (value.Any(character => char.IsControl(character)))
            return true;

        try
        {
            // One decode catches direct percent-encoded CR/LF without creating an unbounded
            // nested-decoding loop. The returned redirect is separately canonicalized through
            // Uri.AbsoluteUri, so encoded percent signs cannot become raw URI-list delimiters.
            return Uri.UnescapeDataString(value).Any(character => char.IsControl(character));
        }
        catch (UriFormatException)
        {
            return true;
        }
    }

    private static bool HasSameAuthority(Uri expected, Uri actual) =>
        string.Equals(expected.Scheme, actual.Scheme, StringComparison.OrdinalIgnoreCase)
        && string.Equals(expected.IdnHost, actual.IdnHost, StringComparison.OrdinalIgnoreCase)
        && expected.Port == actual.Port
        && string.Equals(expected.UserInfo, actual.UserInfo, StringComparison.Ordinal);

    private static bool IsWithinResolutionBase(Uri endpoint, Uri resolved)
    {
        var endpointPath = endpoint.AbsolutePath;
        var basePath = endpointPath.EndsWith('/')
            ? endpointPath
            : endpointPath[..(endpointPath.LastIndexOf('/') + 1)];
        return resolved.AbsolutePath.StartsWith(basePath, StringComparison.Ordinal);
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

        // Only DID document content types are valid for non-redirect results
        if (!IsDidDocumentContentType(accept))
            return DidUrlDereferencingResult.Error("representationNotSupported");

        // Return a DID Document containing the selected service
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

        // Normalize the query value to an absolute URI using the document's id
        var normalizedQuery = NormalizeServiceId(serviceId, doc.Id);

        return doc.Service.FirstOrDefault(s =>
        {
            var normalizedSvcId = NormalizeServiceId(s.Id, doc.Id);
            return normalizedSvcId == normalizedQuery;
        });
    }

    /// <summary>
    /// Resolves a service ID to an absolute URI. Relative references like "#svc"
    /// are resolved against the DID base, producing "did:example:123#svc".
    /// </summary>
    private static string NormalizeServiceId(string id, string did)
    {
        if (id.StartsWith('#'))
            return did + id;
        if (!id.Contains(':'))
            return did + "#" + id;
        return id;
    }

    private static bool IsDidDocumentContentType(string accept)
        => accept is DidContentTypes.JsonLd or DidContentTypes.Json;

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
            var entries = doc.GetRelationshipEntries(verificationRelationship);
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
    /// If the service endpoint URI already contains a fragment, the DID URL
    /// fragment is not appended (the endpoint's own fragment takes precedence).
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

        // Preserve an endpoint fragment across relative path resolution; otherwise append the
        // DID URL fragment. A relative path would otherwise silently discard the base fragment.
        if (!string.IsNullOrEmpty(baseUri.Fragment))
            relative += baseUri.Fragment;
        else if (fragment is not null)
            relative += "#" + fragment;

        if (string.IsNullOrEmpty(relative))
            return baseUri.ToString();

        // Use System.Uri for RFC 3986 reference resolution
        var resolved = new Uri(baseUri, relative);
        return resolved.ToString();
    }
}
