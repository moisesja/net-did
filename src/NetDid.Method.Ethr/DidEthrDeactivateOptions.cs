using NetCrypto;
using NetDid.Core.Model;

namespace NetDid.Method.Ethr;

/// <summary>
/// Deactivate options for did:ethr. Deactivation is a <c>changeOwner</c> to the null
/// address (0x000…000): the identity becomes permanently uncontrollable and resolves to a
/// stripped document with <c>deactivated: true</c>. This is irreversible.
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
