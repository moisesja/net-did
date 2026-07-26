using NetCrypto;
using NetDid.Core.Model;

namespace NetDid.Method.Ethr;

/// <summary>
/// Deactivate options for did:ethr. Deactivation is a <c>changeOwner</c> to the null address
/// (0x000…000); the DID then resolves to a stripped document with <c>deactivated: true</c>.
///
/// <para><b>This is not enforced as a lock.</b> The did:ethr spec calls it irreversible, but
/// the deployed registry's <c>identityOwner()</c> is <c>owner != 0 ? owner : identity</c> — a
/// zero owner slot resolves back to the identity address, so an EOA identity whose key still
/// exists can write again, and a later non-zero <c>DIDOwnerChanged</c> clears the
/// <c>deactivated</c> flag. Verified against real registry bytecode. Deactivation is terminal
/// only when nobody can act as the identity address; for a hard guarantee, transfer ownership
/// to a provably unusable address or destroy the identity key.</para>
/// </summary>
public sealed record DidEthrDeactivateOptions : DidDeactivateOptions
{
    /// <summary>
    /// The current identity owner's key (see <see cref="DidEthrUpdateOptions.ControllerKey"/>
    /// for why this is an <see cref="IRecoverableDigestSigner"/>).
    /// </summary>
    public required IRecoverableDigestSigner ControllerKey { get; init; }

    /// <summary>Submit as an ERC-1056 meta-transaction relayed by <see cref="Relayer"/>.</summary>
    public bool UseMetaTransaction { get; init; } = false;

    /// <summary>The funded key that signs and pays for the wrapping transaction. Required
    /// when <see cref="UseMetaTransaction"/> is true; ignored otherwise.</summary>
    public IRecoverableDigestSigner? Relayer { get; init; }
}
