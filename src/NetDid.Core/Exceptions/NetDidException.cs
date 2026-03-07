namespace NetDid.Core.Exceptions;

/// <summary>
/// Base exception for all NetDid errors.
/// </summary>
public class NetDidException : Exception
{
    public NetDidException(string message, Exception? inner = null) : base(message, inner) { }
}
