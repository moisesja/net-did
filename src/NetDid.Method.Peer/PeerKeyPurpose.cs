using NetDid.Core;

namespace NetDid.Method.Peer;

/// <summary>
/// Associates a signer (key) with its purpose in a did:peer numalgo 2 DID.
/// The public key is extracted via <see cref="ISigner.PublicKey"/>; SignAsync is not called.
/// </summary>
public sealed record PeerKeyPurpose(ISigner Key, PeerPurpose Purpose);
