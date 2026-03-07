namespace NetDid.Core.Exceptions;

/// <summary>
/// A resolution attempt failed (network error, malformed response, DID not found).
/// </summary>
public class DidResolutionException : NetDidException
{
    public string Did { get; }
    public string ErrorCode { get; }

    public DidResolutionException(string did, string errorCode, string message, Exception? inner = null)
        : base(message, inner)
        => (Did, ErrorCode) = (did, errorCode);
}
