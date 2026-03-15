using NetDid.Core;
using NetDid.Core.Crypto;
using NetDid.Core.Model;

namespace NetDid.Method.Peer;

/// <summary>
/// Options for creating a did:peer DID.
/// </summary>
public sealed record DidPeerCreateOptions : DidCreateOptions
{
    /// <inheritdoc />
    public override string MethodName => "peer";

    /// <summary>Which numalgo variant to use.</summary>
    public required PeerNumalgo Numalgo { get; init; }

    /// <summary>Numalgo 0: key type for the inception key.</summary>
    public KeyType? InceptionKeyType { get; init; }

    /// <summary>Numalgo 0: optional existing signer to wrap instead of generating a new key.</summary>
    public ISigner? ExistingKey { get; init; }

    /// <summary>Numalgo 2: keys with their purposes.</summary>
    public IReadOnlyList<PeerKeyPurpose>? Keys { get; init; }

    /// <summary>Numalgo 2: service endpoints to encode in the DID.</summary>
    public IReadOnlyList<Service>? Services { get; init; }

    /// <summary>Numalgo 4: the input document to hash and encode.</summary>
    public DidDocument? InputDocument { get; init; }
}
