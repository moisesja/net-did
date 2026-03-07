namespace NetDid.Core.Exceptions;

/// <summary>
/// The DID method is not registered or supported by this resolver/method registry.
/// </summary>
public class MethodNotSupportedException : NetDidException
{
    public string MethodName { get; }

    public MethodNotSupportedException(string method)
        : base($"DID method '{method}' is not supported.")
        => MethodName = method;
}
