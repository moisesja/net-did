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

    /// <summary>
    /// Ceiling applied when the caller has no <see cref="EthereumNetworkConfig"/> to consult
    /// (currently <see cref="Deployment.Erc1056Registry.DeployAsync"/>, which takes a bare
    /// client). Same rationale as <see cref="EthereumNetworkConfig.MaxGasPriceWei"/>.
    /// </summary>
    public const ulong DefaultMaxGasPriceWei = 5_000UL * 1_000_000_000UL;

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
        ulong maxGasPriceWei = DefaultMaxGasPriceWei,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(rpc);
        ArgumentNullException.ThrowIfNull(data);

        var sender = AddressOf(signer, nameof(signer));
        var dataHex = "0x" + Convert.ToHexString(data).ToLowerInvariant();

        var nonce = await rpc.GetTransactionCountAsync(sender, ct);

        // The node is untrusted and its gas price becomes a fee THIS key authorizes. Without a
        // ceiling a hostile endpoint can report a price that drains the signer to the block
        // producer while every operation still reports success. Reject before signing.
        var gasPrice = await rpc.GetGasPriceAsync(ct);
        if (gasPrice > maxGasPriceWei)
            throw new EthereumInteractionException(
                $"The RPC endpoint reported a gas price of {gasPrice} wei, above the configured " +
                $"ceiling of {maxGasPriceWei} wei. Nothing was signed or broadcast. Raise " +
                $"{nameof(EthereumNetworkConfig)}.{nameof(EthereumNetworkConfig.MaxGasPriceWei)} " +
                "only if this chain's fees are legitimately this high.");

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

                // For a contract creation the deployed address is DETERMINISTIC —
                // keccak256(rlp([sender, nonce]))[12..]. Never take the node's word for it:
                // a forged contractAddress would become the caller's registry trust anchor.
                if (to is null)
                {
                    var expected = ContractCreationAddress(sender, nonce);
                    if (!string.Equals(receipt.ContractAddress, expected, StringComparison.OrdinalIgnoreCase))
                        throw new EthereumInteractionException(
                            $"The RPC endpoint reported contract address " +
                            $"'{receipt.ContractAddress ?? "(none)"}' for transaction {transactionHash}, " +
                            $"but CREATE from {sender} at nonce {nonce} deterministically yields " +
                            $"{expected}. Refusing to trust the reported address.");
                }

                return receipt;
            }

            await Task.Delay(ReceiptPollInterval, ct);
        }
    }

    /// <summary>
    /// The deterministic CREATE address for a contract deployed by <paramref name="sender"/>
    /// at <paramref name="nonce"/>: <c>keccak256(rlp([sender, nonce]))[12..]</c>.
    /// </summary>
    public static string ContractCreationAddress(string sender, ulong nonce)
    {
        var senderHex = sender.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
            ? sender[2..] : sender;
        var encoded = RlpEncoder.EncodeList(
        [
            RlpEncoder.EncodeBytes(Convert.FromHexString(senderHex)),
            RlpEncoder.EncodeUnsigned(nonce),
        ]);
        return "0x" + Convert.ToHexString(Keccak256.Hash(encoded)[12..]).ToLowerInvariant();
    }
}
