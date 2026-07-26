using NetCrypto;
using NetDid.Core.Model;

namespace NetDid.Method.Ethr;

/// <summary>
/// Update options for did:ethr. Each populated collection becomes one or more on-chain
/// ERC-1056 transactions, submitted sequentially: revocations first, then additions, and
/// — always last — the owner change, because <c>changeOwner</c> revokes the current key's
/// authority over any subsequent operation.
/// </summary>
/// <remarks>
/// <see cref="ControllerKey"/> is an <see cref="IRecoverableDigestSigner"/> (NetCrypto):
/// Ethereum signatures are recoverable ECDSA over a caller-computed Keccak-256 digest, which
/// the general-purpose <see cref="ISigner"/> cannot produce (it hashes internally and returns
/// no recovery id). Any HSM/key-store signer implementing the interface works — the private
/// key never needs to be extractable.
/// </remarks>
public sealed record DidEthrUpdateOptions : DidUpdateOptions
{
    public IReadOnlyList<DidEthrServiceAttribute>? AddServices { get; init; }
    public IReadOnlyList<DidEthrServiceAttribute>? RemoveServices { get; init; }
    public IReadOnlyList<DidEthrDelegate>? AddDelegates { get; init; }
    public IReadOnlyList<DidEthrDelegate>? RevokeDelegates { get; init; }
    public string? NewOwnerAddress { get; init; }

    /// <summary>
    /// The current identity owner's key. Signs the transactions directly, or — with
    /// <see cref="UseMetaTransaction"/> — the ERC-1056 <c>0x19 0x00</c> meta-transaction
    /// payloads that <see cref="Relayer"/> submits.
    /// </summary>
    public required IRecoverableDigestSigner ControllerKey { get; init; }

    /// <summary>
    /// When true, operations are submitted as ERC-1056 meta-transactions: the controller
    /// key signs the operation payload and <see cref="Relayer"/> pays the gas — the
    /// identity owner's account needs no ETH.
    /// </summary>
    public bool UseMetaTransaction { get; init; } = false;

    /// <summary>The funded key that signs and pays for the wrapping transactions. Required
    /// when <see cref="UseMetaTransaction"/> is true; ignored otherwise.</summary>
    public IRecoverableDigestSigner? Relayer { get; init; }
}

public sealed record DidEthrDelegate
{
    public required string DelegateType { get; init; }     // "veriKey", "sigAuth"
    public required string DelegateAddress { get; init; }

    /// <summary>How long the delegation stays valid. Used by additions; ignored — and
    /// therefore optional — for revocations.</summary>
    public TimeSpan Validity { get; init; } = TimeSpan.FromDays(365);
}

public sealed record DidEthrServiceAttribute
{
    public required string ServiceType { get; init; }
    public required string ServiceEndpoint { get; init; }
    public TimeSpan Validity { get; init; } = TimeSpan.FromDays(365 * 10);
}
