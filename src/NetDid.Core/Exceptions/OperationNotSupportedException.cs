namespace NetDid.Core.Exceptions;

/// <summary>
/// The requested CRUD operation is not supported by this DID method
/// (e.g., Update on did:key).
/// </summary>
public class OperationNotSupportedException : NetDidException
{
    public string MethodName { get; }
    public string Operation { get; }

    public OperationNotSupportedException(string method, string operation)
        : base($"Method '{method}' does not support '{operation}'.")
        => (MethodName, Operation) = (method, operation);
}
