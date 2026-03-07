using NetDid.Core.Crypto;

namespace NetDid.Core.Resolution;

/// <summary>
/// Resolves a DID URL to a verification method's key type and public key bytes.
/// Used by zcap-dotnet for ZCAP verification.
/// </summary>
public interface IVerificationMethodResolver
{
    /// <summary>
    /// Resolve a DID URL to the key type and raw public key bytes of the verification method it identifies.
    /// Returns null if the DID URL cannot be resolved or the verification method has no extractable key.
    /// </summary>
    Task<(KeyType KeyType, byte[] PublicKey)?> ResolveKeyAsync(
        string didUrl,
        CancellationToken ct = default);
}
