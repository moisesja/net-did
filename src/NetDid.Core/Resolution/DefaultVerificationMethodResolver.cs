using NetDid.Core.Crypto;
using NetDid.Core.Encoding;
using NetDid.Core.Jwk;
using NetDid.Core.Model;

namespace NetDid.Core.Resolution;

/// <summary>
/// Default implementation of <see cref="IVerificationMethodResolver"/>.
/// Dereferences a DID URL and extracts key type + public key bytes.
/// </summary>
public sealed class DefaultVerificationMethodResolver : IVerificationMethodResolver
{
    private readonly IDidUrlDereferencer _dereferencer;

    public DefaultVerificationMethodResolver(IDidUrlDereferencer dereferencer)
        => _dereferencer = dereferencer;

    public async Task<(KeyType KeyType, byte[] PublicKey)?> ResolveKeyAsync(
        string didUrl, CancellationToken ct = default)
    {
        var result = await _dereferencer.DereferenceAsync(didUrl, ct: ct);

        if (result.ContentStream is not VerificationMethod vm)
            return null;

        // Try PublicKeyMultibase first (Multikey path)
        if (vm.PublicKeyMultibase is not null)
        {
            var decoded = MultibaseEncoder.Decode(vm.PublicKeyMultibase);
            var (keyType, rawKey) = MulticodecEncoder.Decode(decoded);
            return (keyType, rawKey);
        }

        // Try PublicKeyJwk (JWK path)
        if (vm.PublicKeyJwk is not null)
        {
            var (keyType, publicKey) = JwkConverter.ExtractPublicKey(vm.PublicKeyJwk);
            return (keyType, publicKey);
        }

        // BlockchainAccountId only — no extractable key
        return null;
    }
}
