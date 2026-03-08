namespace NetDid.Method.Peer;

/// <summary>
/// The numalgo variants supported by did:peer.
/// </summary>
public enum PeerNumalgo
{
    /// <summary>Inception key only. Functionally identical to did:key.</summary>
    Zero = 0,

    /// <summary>Inline keys and services encoded in the DID string.</summary>
    Two = 2,

    /// <summary>Short-form hash with optional long-form encoded document.</summary>
    Four = 4
}
