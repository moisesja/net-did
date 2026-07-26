using System.Numerics;
using NetCrypto;
using NetDid.Core.Exceptions;
using NetDid.Method.Ethr.Crypto;
using NetDid.Method.Ethr.Rpc;

namespace NetDid.Method.Ethr.Transactions;

/// <summary>
/// The did:ethr write pipeline: nonce → gas → EIP-155 sign (through
/// <see cref="IRecoverableDigestSigner"/> — the NetCrypto seam, so HSM/key-store-held
/// keys work) → <c>eth_sendRawTransaction</c> → receipt confirmation. One transaction
/// per call, strictly sequential; the caller owns operation ordering and the overall
/// deadline token.
/// </summary>
internal static class TransactionPipeline
{
    private static readonly TimeSpan ReceiptPollInterval = TimeSpan.FromMilliseconds(500);

    // eth_estimateGas can undershoot when a later state change (same batch) grows costs;
    // real wallets pad the estimate. +25% with a hard cap keeps a hostile node from
    // requesting an absurd limit.
    private const ulong GasHeadroomPercent = 25;
    private const ulong MaxGasLimit = 3_000_000;

    /// <summary>Derives the signer's Ethereum address, validating the key type up front (NFR-3 style).</summary>
    public static string AddressOf(IRecoverableDigestSigner signer, string paramName)
    {
        ArgumentNullException.ThrowIfNull(signer, paramName);
        if (signer.KeyType != KeyType.Secp256k1)
            throw new ArgumentException(
                $"did:ethr transactions require a Secp256k1 signer; got {signer.KeyType}.", paramName);
        var publicKey = signer.PublicKey.ToArray();
        if (publicKey.Length != 33)
            throw new ArgumentException(
                $"Expected a 33-byte compressed secp256k1 public key; got {publicKey.Length} bytes.",
                paramName);
        return EthereumAddress.FromCompressedPublicKey(publicKey).ToLowerInvariant();
    }

    /// <summary>
    /// Signs and submits one transaction, then waits for its receipt. Throws
    /// <see cref="EthereumInteractionException"/> if the node rejects the transaction or
    /// the receipt reports a revert. Cancellation (<paramref name="ct"/> is typically the
    /// caller token linked with the method's write deadline) propagates as
    /// <see cref="OperationCanceledException"/> — the method layer maps a deadline firing
    /// to a descriptive failure; note a broadcast transaction may still land afterwards.
    /// </summary>
    public static async Task<EthereumTransactionReceipt> SubmitAndConfirmAsync(
        IEthereumRpcClient rpc,
        IRecoverableDigestSigner signer,
        string? to,
        byte[] data,
        ulong chainId,
        BigInteger? value = null,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(rpc);
        ArgumentNullException.ThrowIfNull(data);

        var sender = AddressOf(signer, nameof(signer));
        var dataHex = "0x" + Convert.ToHexString(data).ToLowerInvariant();

        var nonce = await rpc.GetTransactionCountAsync(sender, ct);
        var gasPrice = await rpc.GetGasPriceAsync(ct);

        ulong gasEstimate;
        try
        {
            gasEstimate = await rpc.EstimateGasAsync(sender, to, dataHex, ct);
        }
        catch (EthereumInteractionException ex)
        {
            // Nodes reject the estimate when the call would revert — surface that as the
            // pre-flight failure it is, before anything is signed or broadcast.
            throw new EthereumInteractionException(
                $"did:ethr transaction from {sender} would fail (gas estimation rejected): {ex.Message}", ex);
        }
        var gasLimit = Math.Min(gasEstimate + gasEstimate * GasHeadroomPercent / 100, MaxGasLimit);

        var transaction = new EthereumTransaction
        {
            Nonce    = nonce,
            GasPrice = gasPrice,
            GasLimit = gasLimit,
            To       = to,
            Value    = value ?? BigInteger.Zero,
            Data     = data,
            ChainId  = chainId,
        };

        var signature = await signer.SignDigestAsync(transaction.SigningDigest(), ct);
        var raw = transaction.EncodeSigned(signature.Signature64, signature.RecoveryId);
        var transactionHash = await rpc.SendRawTransactionAsync(raw, ct);

        while (true)
        {
            if (await rpc.GetTransactionReceiptAsync(transactionHash, ct) is { } receipt)
            {
                if (!receipt.Succeeded)
                    throw new EthereumInteractionException(
                        $"did:ethr transaction {transactionHash} reverted on-chain " +
                        "(the registry rejected the operation).");
                return receipt;
            }

            await Task.Delay(ReceiptPollInterval, ct);
        }
    }
}
