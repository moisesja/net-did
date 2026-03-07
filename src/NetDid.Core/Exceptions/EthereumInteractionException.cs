namespace NetDid.Core.Exceptions;

/// <summary>
/// An Ethereum RPC or contract interaction failed (did:ethr).
/// </summary>
public class EthereumInteractionException : NetDidException
{
    public EthereumInteractionException(string message, Exception? inner = null)
        : base(message, inner) { }
}
