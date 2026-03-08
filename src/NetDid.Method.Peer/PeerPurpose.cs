namespace NetDid.Method.Peer;

/// <summary>
/// The purpose of a key in a did:peer numalgo 2 DID.
/// Maps to the DIF peer-DID spec purpose prefixes: A, E, V, I, D.
/// </summary>
public enum PeerPurpose
{
    /// <summary>Assertion method key (prefix 'A').</summary>
    Assertion,

    /// <summary>Key agreement / encryption key (prefix 'E').</summary>
    KeyAgreement,

    /// <summary>Verification / authentication key (prefix 'V').</summary>
    Authentication,

    /// <summary>Capability invocation key (prefix 'I').</summary>
    CapabilityInvocation,

    /// <summary>Capability delegation key (prefix 'D').</summary>
    CapabilityDelegation
}
