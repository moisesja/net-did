namespace NetDid.Core.Model;

public sealed record DidUrlDereferencingResult
{
    /// <summary>Metadata about the dereferencing process itself.</summary>
    public required DereferencingMetadata DereferencingMetadata { get; init; }

    /// <summary>
    /// The dereferenced resource. Null when an error occurs.
    /// May be a VerificationMethod, Service, DidDocument, or raw byte[].
    /// </summary>
    public object? ContentStream { get; init; }

    /// <summary>Metadata about the content.</summary>
    public IReadOnlyDictionary<string, object>? ContentMetadata { get; init; }

    public static DidUrlDereferencingResult Error(string errorCode) => new()
    {
        DereferencingMetadata = new DereferencingMetadata { Error = errorCode }
    };

    public static DidUrlDereferencingResult Success(
        object content, string contentType, DidDocumentMetadata? metadata = null) => new()
    {
        DereferencingMetadata = new DereferencingMetadata { ContentType = contentType },
        ContentStream = content,
        ContentMetadata = metadata?.ToPropertyDictionary()
    };

    /// <summary>
    /// Service endpoint selection: returns the constructed URL for the caller to follow.
    /// </summary>
    public static DidUrlDereferencingResult ServiceEndpointRedirect(string serviceUrl) => new()
    {
        DereferencingMetadata = new DereferencingMetadata { ContentType = "text/uri-list" },
        ContentStream = serviceUrl
    };
}
