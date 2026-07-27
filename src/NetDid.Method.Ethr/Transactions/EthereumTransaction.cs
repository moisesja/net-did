using System.Numerics;
using NetCrypto;

namespace NetDid.Method.Ethr.Transactions;

/// <summary>
/// An unsigned Ethereum legacy (type-0) transaction with EIP-155 replay protection.
///
/// The signing flow is split across the FR-12 boundary that NetCrypto documents on
/// <c>Secp256k1Recoverable</c>: this type produces the RLP signing payload and its
/// Keccak-256 digest; the caller signs the digest (obtaining a 64-byte compact R‖S and a
/// raw recovery id) and hands both back to <see cref="EncodeSigned"/>, which applies the
/// EIP-155 v-encoding (<c>v = 35 + 2·chainId + recoveryId</c>) and emits the raw signed
/// transaction bytes for <c>eth_sendRawTransaction</c>.
///
/// Legacy type-0 transactions are accepted by every network in <see cref="Rpc.KnownNetworks"/>
/// and by local dev nodes; typed (EIP-1559) envelopes are deliberately out of scope.
/// </summary>
internal sealed record EthereumTransaction
{
    private static readonly BigInteger Secp256k1Order = BigInteger.Parse(
        "0FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
        System.Globalization.NumberStyles.HexNumber);
    private static readonly BigInteger Secp256k1HalfOrder = Secp256k1Order / 2;

    public required ulong Nonce { get; init; }

    /// <summary>Gas price in wei. BigInteger because wei quantities overflow ulong.</summary>
    public required BigInteger GasPrice { get; init; }

    public required ulong GasLimit { get; init; }

    /// <summary>
    /// Recipient address (0x-prefixed, 20 bytes) — or <c>null</c> for a contract-creation
    /// transaction, which RLP-encodes the recipient as the empty byte string.
    /// </summary>
    public string? To { get; init; }

    /// <summary>Transferred value in wei. BigInteger because wei quantities overflow ulong.</summary>
    public BigInteger Value { get; init; } = BigInteger.Zero;

    /// <summary>ABI calldata, or contract-creation bytecode when <see cref="To"/> is null.</summary>
    public byte[] Data { get; init; } = [];

    /// <summary>EIP-155 chain id, included in the signed payload for replay protection.</summary>
    public required ulong ChainId { get; init; }

    /// <summary>
    /// The EIP-155 signing payload: <c>rlp([nonce, gasPrice, gasLimit, to, value, data, chainId, 0, 0])</c>.
    /// </summary>
    public byte[] SigningPayload()
    {
        Validate();
        return RlpEncoder.EncodeList(
        [
            .. CommonFields(),
            RlpEncoder.EncodeUnsigned(ChainId),
            RlpEncoder.EncodeUnsigned(0UL),
            RlpEncoder.EncodeUnsigned(0UL),
        ]);
    }

    /// <summary>Keccak-256 of <see cref="SigningPayload"/> — the 32-byte digest to sign.</summary>
    public byte[] SigningDigest() => Keccak256.Hash(SigningPayload());

    /// <summary>
    /// Encodes the signed transaction:
    /// <c>rlp([nonce, gasPrice, gasLimit, to, value, data, v, r, s])</c> with
    /// <c>v = 35 + 2·chainId + recoveryId</c> (EIP-155). <paramref name="signature64"/> is the
    /// 64-byte compact R‖S over <see cref="SigningDigest"/>; <paramref name="recoveryId"/> is the
    /// raw recovery id in {0,1} (values 2/3 arise only for astronomically improbable R ≥ n and
    /// are rejected, matching what EVM nodes accept).
    /// </summary>
    public byte[] EncodeSigned(ReadOnlySpan<byte> signature64, int recoveryId)
    {
        Validate();
        if (signature64.Length != 64)
            throw new ArgumentException(
                $"Compact signature must be 64 bytes, got {signature64.Length}.", nameof(signature64));
        if (recoveryId is not (0 or 1))
            throw new ArgumentOutOfRangeException(
                nameof(recoveryId), recoveryId,
                "EIP-155 v-encoding accepts recovery ids 0 or 1.");

        var r = new BigInteger(signature64[..32], isUnsigned: true, isBigEndian: true);
        var s = new BigInteger(signature64[32..], isUnsigned: true, isBigEndian: true);

        // Validate the scalars here rather than discovering it from a node rejection: the
        // signature arrives through the caller-supplied IRecoverableDigestSigner seam.
        if (r.IsZero || s.IsZero || r >= Secp256k1Order || s >= Secp256k1Order)
            throw new ArgumentException(
                "Signature scalars must be canonical values in [1, n-1].", nameof(signature64));
        if (s > Secp256k1HalfOrder)
            throw new ArgumentException(
                "Signature must be low-S (EIP-2). Use CanonicalizeSignature first — HSM " +
                "backends legitimately return the malleable twin.", nameof(signature64));
        var v = 35 + 2 * (BigInteger)ChainId + recoveryId;

        return RlpEncoder.EncodeList(
        [
            .. CommonFields(),
            RlpEncoder.EncodeUnsigned(v),
            RlpEncoder.EncodeUnsigned(r),
            RlpEncoder.EncodeUnsigned(s),
        ]);
    }

    /// <summary>
    /// Returns the EIP-2 canonical (low-S) form of a recoverable signature: when
    /// <c>s > n/2</c>, replaces it with <c>n - s</c> and flips the recovery id. The result is
    /// a valid signature over the same digest recovering to the same public key.
    ///
    /// <para>Needed because the <see cref="IRecoverableDigestSigner"/> seam is caller-supplied:
    /// PKCS#11 <c>CKM_ECDSA</c> and many HSM/KMS backends do not normalize, and rejecting their
    /// output would break exactly the HSM-backed signers the seam exists to support. (NetCrypto's
    /// own signer already returns low-S, so this is a no-op for it.)</para>
    /// </summary>
    public static (byte[] Signature64, int RecoveryId) CanonicalizeSignature(
        byte[] signature64, int recoveryId)
    {
        ArgumentNullException.ThrowIfNull(signature64);
        if (signature64.Length != 64)
            throw new ArgumentException(
                $"Compact signature must be 64 bytes, got {signature64.Length}.", nameof(signature64));
        if (recoveryId is not (0 or 1))
            return (signature64, recoveryId); // let EncodeSigned report the real problem

        var s = new BigInteger(signature64.AsSpan(32), isUnsigned: true, isBigEndian: true);
        if (s <= Secp256k1HalfOrder)
            return (signature64, recoveryId);

        var canonical = new byte[64];
        signature64.AsSpan(0, 32).CopyTo(canonical);
        var lowS = (Secp256k1Order - s).ToByteArray(isUnsigned: true, isBigEndian: true);
        lowS.CopyTo(canonical, 64 - lowS.Length);
        return (canonical, recoveryId ^ 1);
    }

    /// <summary>The transaction hash of a raw signed transaction: 0x-prefixed keccak256.</summary>
    public static string HashOf(ReadOnlySpan<byte> rawSignedTransaction)
        => "0x" + Convert.ToHexString(Keccak256.Hash(rawSignedTransaction)).ToLowerInvariant();

    private byte[][] CommonFields() =>
    [
        RlpEncoder.EncodeUnsigned(Nonce),
        RlpEncoder.EncodeUnsigned(GasPrice),
        RlpEncoder.EncodeUnsigned(GasLimit),
        RlpEncoder.EncodeBytes(To is null ? [] : ParseAddress(To)),
        RlpEncoder.EncodeUnsigned(Value),
        RlpEncoder.EncodeBytes(Data),
    ];

    private void Validate()
    {
        if (GasPrice.Sign < 0)
            throw new ArgumentOutOfRangeException(nameof(GasPrice), GasPrice, "GasPrice must be non-negative.");
        if (Value.Sign < 0)
            throw new ArgumentOutOfRangeException(nameof(Value), Value, "Value must be non-negative.");
        if (Data is null)
            throw new ArgumentNullException(nameof(Data));
        if (To is not null)
            ParseAddress(To); // throws on malformed input
    }

    private static byte[] ParseAddress(string address)
    {
        var hex = address.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
            ? address[2..] : address;
        byte[] bytes;
        try
        {
            bytes = Convert.FromHexString(hex);
        }
        catch (FormatException ex)
        {
            throw new ArgumentException($"'{address}' is not valid hex.", nameof(address), ex);
        }
        if (bytes.Length != 20)
            throw new ArgumentException(
                $"Ethereum addresses are 20 bytes; got {bytes.Length}.", nameof(address));
        return bytes;
    }
}
