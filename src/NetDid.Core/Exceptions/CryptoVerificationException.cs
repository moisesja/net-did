namespace NetDid.Core.Exceptions;

/// <summary>
/// Cryptographic verification failed (invalid signature, broken hash chain, etc.).
/// </summary>
public class CryptoVerificationException : NetDidException
{
    public CryptoVerificationException(string message, Exception? inner = null)
        : base(message, inner) { }
}
