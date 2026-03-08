namespace NetDid.Method.Peer;

/// <summary>
/// The purpose of a key in a did:peer numalgo 2 DID.
/// </summary>
public enum PeerPurpose
{
    /// <summary>Verification / authentication key (prefix 'V').</summary>
    Authentication,

    /// <summary>Key agreement key (prefix 'A').</summary>
    KeyAgreement
}
