namespace NetDid.Core.Exceptions;

/// <summary>
/// A DID log chain is invalid (did:webvh hash chain break, unauthorized update key, etc.).
/// </summary>
public class LogChainValidationException : CryptoVerificationException
{
    public int FailedAtVersion { get; }

    public LogChainValidationException(int version, string message)
        : base(message)
        => FailedAtVersion = version;
}
