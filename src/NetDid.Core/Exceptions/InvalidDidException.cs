namespace NetDid.Core.Exceptions;

/// <summary>
/// The DID string is syntactically invalid (malformed, wrong prefix, bad encoding).
/// </summary>
public class InvalidDidException : NetDidException
{
    public string Did { get; }

    public InvalidDidException(string did, string message) : base(message)
        => Did = did;
}
