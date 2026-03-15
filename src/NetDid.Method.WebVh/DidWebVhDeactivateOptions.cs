using NetDid.Core;
using NetDid.Core.Model;

namespace NetDid.Method.WebVh;

/// <summary>
/// Options for deactivating a did:webvh DID.
/// </summary>
public sealed record DidWebVhDeactivateOptions : DidDeactivateOptions
{
    /// <summary>The existing did.jsonl content (bytes).</summary>
    public required byte[] CurrentLogContent { get; init; }

    /// <summary>The Ed25519 signer for an authorized update key (HSM-safe).</summary>
    public required ISigner SigningKey { get; init; }
}
