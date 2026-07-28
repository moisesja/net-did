using System.Numerics;
using System.Security.Cryptography;
using NetCrypto;
using NetDid.Core.Exceptions;
using NetDid.Method.Ethr.Crypto;
using NetDid.Method.Ethr.Rpc;

namespace NetDid.Method.Ethr.Transactions;

/// <summary>
/// Pipeline-owned transaction state. This is deliberately a typed side channel rather than
/// reserved <see cref="Exception.Data"/> keys: RPC clients are injectable and their exceptions
/// are untrusted, so dependency-controlled metadata must never be promoted to confirmed
/// transaction evidence.
/// </summary>
internal sealed class TransactionAttemptEvidence
{
    public string? ConfirmedHash { get; private set; }
    public string? InFlightHash { get; private set; }

    public void MarkInFlight(string locallyComputedHash)
    {
        EnsureCanonicalLocalHash(locallyComputedHash);
        if (ConfirmedHash is null)
            InFlightHash = locallyComputedHash;
    }

    public void MarkConfirmed(string locallyComputedHash)
    {
        EnsureCanonicalLocalHash(locallyComputedHash);
        ConfirmedHash = locallyComputedHash;
        InFlightHash = null;
    }

    private static void EnsureCanonicalLocalHash(string hash)
    {
        if (hash.Length != 66 || !hash.StartsWith("0x", StringComparison.Ordinal)
            || hash.AsSpan(2).ContainsAnyExcept("0123456789abcdef"))
            throw new InvalidOperationException(
                "Transaction evidence must be a canonical locally computed Ethereum hash.");
    }
}

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

    /// <summary>
    /// Default ceiling on the TOTAL fee a single transaction may authorize
    /// (<c>gasPrice × gasLimit</c>). Same rationale as
    /// <see cref="EthereumNetworkConfig.MaxTransactionFeeWei"/>.
    /// </summary>
    public static readonly BigInteger DefaultMaxTransactionFeeWei =
        BigInteger.Pow(10, 17); // 0.1 ETH — ~30x a congested-mainnet registry write

    /// <summary>
    /// Recovers the Ethereum address that produced <paramref name="signature64"/> over
    /// <paramref name="digest32"/>, validating length and scalars first. Used for BOTH the
    /// outer transaction signature and the inner ERC-1056 meta-transaction signature — the
    /// latter is spent by a relayer, so a signature that cannot be attributed to the
    /// controller must be caught before any gas is paid.
    /// </summary>
    public static string RecoverSigner(
        byte[] digest32, byte[] signature64, int recoveryId, string subject)
    {
        ArgumentNullException.ThrowIfNull(signature64);
        if (signature64.Length != 64)
            throw new EthereumInteractionException(
                $"{subject} must be 64 bytes, got {signature64.Length}. Nothing was broadcast.");

        try
        {
            return EthereumAddress.FromCompressedPublicKey(
                Secp256k1Recoverable.RecoverPublicKey(
                    digest32, signature64, recoveryId, compressed: true))
                .ToLowerInvariant();
        }
        catch (Exception ex) when (ex is ArgumentException or ArgumentOutOfRangeException
                                   or CryptographicException)
        {
            throw new EthereumInteractionException(
                $"{subject} does not recover a public key ({ex.Message}). Nothing was broadcast.",
                ex);
        }
    }

    /// <summary>Derives the signer's Ethereum address, validating the key type up front (NFR-3 style).</summary>
    public static string AddressOf(IRecoverableDigestSigner signer, string paramName)
    {
        ArgumentNullException.ThrowIfNull(signer, paramName);
        if (signer.KeyType != KeyType.Secp256k1)
            throw new ArgumentException(
                $"did:ethr transactions require a Secp256k1 signer; got {signer.KeyType}.", paramName);

        // Normalize, don't demand: uncompressed SEC1 (65-byte 0x04‖X‖Y) is the common
        // HSM/KMS representation, and Create already accepts it. Requiring the compressed
        // form here would have made "any signer implementing the interface works" false for
        // exactly the HSM-backed keys the seam exists to support. NormalizeToCompressed also
        // validates the point is on the curve.
        byte[] compressed;
        try
        {
            compressed = KeyTypeExtensions.NormalizeToCompressed(
                KeyType.Secp256k1, signer.PublicKey.ToArray());
        }
        catch (ArgumentException ex)
        {
            throw new ArgumentException(
                $"The signer's public key is not a valid secp256k1 point: {ex.Message}",
                paramName, ex);
        }
        return EthereumAddress.FromCompressedPublicKey(compressed).ToLowerInvariant();
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
        TransactionAttemptEvidence attemptEvidence,
        BigInteger? value = null,
        ulong maxGasPriceWei = DefaultMaxGasPriceWei,
        BigInteger? maxTransactionFeeWei = null,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(rpc);
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(attemptEvidence);
        var feeCeiling = maxTransactionFeeWei ?? DefaultMaxTransactionFeeWei;

        var sender = AddressOf(signer, nameof(signer));
        var dataHex = "0x" + Convert.ToHexString(data).ToLowerInvariant();

        var nonce = await rpc.GetTransactionCountAsync(sender, ct).WaitAsyncObserved(ct);

        // The node is untrusted and its gas price becomes a fee THIS key authorizes. Without a
        // ceiling a hostile endpoint can report a price that drains the signer to the block
        // producer while every operation still reports success. Reject before signing.
        var gasPrice = await rpc.GetGasPriceAsync(ct).WaitAsyncObserved(ct);
        if (gasPrice > maxGasPriceWei)
            throw new EthereumInteractionException(
                $"The RPC endpoint reported a gas price of {gasPrice} wei, above the configured " +
                $"ceiling of {maxGasPriceWei} wei. Nothing was signed or broadcast. Raise " +
                $"{nameof(EthereumNetworkConfig)}.{nameof(EthereumNetworkConfig.MaxGasPriceWei)} " +
                "only if this chain's fees are legitimately this high.");

        ulong gasEstimate;
        try
        {
            gasEstimate = await rpc.EstimateGasAsync(sender, to, dataHex, ct).WaitAsyncObserved(ct);
        }
        catch (EthereumInteractionException ex)
        {
            // Nodes reject the estimate when the call would revert — surface that as the
            // pre-flight failure it is, before anything is signed or broadcast.
            throw new EthereumInteractionException(
                $"did:ethr transaction from {sender} would fail because gas estimation was " +
                "rejected. Nothing was signed or broadcast.", ex);
        }
        // Fail closed rather than under-provision. Silently clamping a larger estimate down to
        // the cap signs a transaction that is GUARANTEED to run out of gas — burning the whole
        // limit and surfacing as "the registry rejected the operation", which is simply false.
        var gasLimit = gasEstimate + gasEstimate * GasHeadroomPercent / 100;
        if (gasEstimate > MaxGasLimit || gasLimit > MaxGasLimit)
            throw new EthereumInteractionException(
                $"The transaction needs an estimated {gasEstimate} gas ({gasLimit} with headroom), " +
                $"above this library's {MaxGasLimit} ceiling for a single did:ethr transaction. " +
                "Nothing was signed or broadcast. Split the update into smaller operations, or " +
                "reduce the size of the attribute/service values being written.");

        // Price and limit are BOTH node-controlled, so bounding them separately still allows
        // their product — the actual money — to reach the product of the two ceilings. Bound
        // the spend itself: this is the number a caller would actually reason about.
        var maxFee = (BigInteger)gasPrice * gasLimit;
        if (maxFee > feeCeiling)
            throw new EthereumInteractionException(
                $"This transaction would authorize up to {maxFee} wei in fees " +
                $"({gasPrice} wei/gas × {gasLimit} gas), above the configured ceiling of " +
                $"{feeCeiling} wei. Nothing was signed or broadcast. Raise " +
                $"{nameof(EthereumNetworkConfig)}.{nameof(EthereumNetworkConfig.MaxTransactionFeeWei)} " +
                "only if this chain's fees are legitimately this high.");

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

        // Freeze ONE digest and derive everything from it: re-deriving the payload after the
        // await would let a caller-supplied signer mutate Data between signing and encoding.
        var signingDigest = transaction.SigningDigest();
        var signature = await signer.SignDigestAsync(signingDigest, ct).WaitAsyncObserved(ct);

        // The IRecoverableDigestSigner seam is caller-supplied (HSM, KMS, remote service).
        // Verify what came back actually authorizes THIS transaction as THIS sender before
        // broadcasting: a malformed or foreign signature otherwise burns a reverting
        // transaction, and an advertised-but-unused public key would pass the owner
        // pre-flight while signing with something else.
        var recovered = RecoverSigner(
            signingDigest, signature.Signature64, signature.RecoveryId, "The signer");
        if (!string.Equals(recovered, sender, StringComparison.Ordinal))
            throw new EthereumInteractionException(
                $"The signer's signature recovers to {recovered}, not to the address its " +
                $"public key advertises ({sender}). Nothing was broadcast.");

        // PKCS#11 CKM_ECDSA and many HSM/KMS backends do not low-S normalize. The malleable
        // twin is a VALID signature over the same digest recovering to the same key, so
        // canonicalize it (s' = n - s, flip the recovery id) rather than rejecting a
        // legitimate signer — rejecting would have made the "HSM keys work" claim false.
        var (canonical, canonicalRecoveryId) =
            EthereumTransaction.CanonicalizeSignature(signature.Signature64, signature.RecoveryId);
        var raw = transaction.EncodeSigned(canonical, canonicalRecoveryId);

        // The transaction hash is keccak256(raw) — we can and must compute it ourselves.
        // Accepting the node's echo verbatim let a hostile endpoint write an arbitrary value
        // into the caller's audit record (DidUpdateResult.Artifacts["transactions"]).
        var expectedHash = EthereumTransaction.HashOf(raw);
        // Once the call begins, a transport failure is ambiguous: the request may have reached
        // the node even if no response reaches us. Record the deterministic local hash before
        // invoking the untrusted transport, then promote it only after a matching receipt.
        ct.ThrowIfCancellationRequested();
        attemptEvidence.MarkInFlight(expectedHash);
        var reportedHash = await rpc.SendRawTransactionAsync(raw, ct).WaitAsyncObserved(ct);
        // WaitAsync deliberately returns an already-completed task even if its token was
        // canceled. Re-check explicitly before trusting the response or beginning more work.
        ct.ThrowIfCancellationRequested();
        if (!string.Equals(reportedHash, expectedHash, StringComparison.OrdinalIgnoreCase))
        {
            // A response proves the node consumed the request, but not that the transaction was
            // mined. Keep the locally computed hash explicitly IN-FLIGHT until a receipt proves
            // confirmation; treating mempool acceptance as "landed" is a false postcondition.
            var mismatch = new EthereumInteractionException(
                $"The RPC endpoint reported transaction hash {reportedHash}, but the broadcast " +
                $"bytes hash to {expectedHash}. The transaction was accepted and may confirm " +
                "under its true hash.");
            throw mismatch;
        }
        var transactionHash = expectedHash;

        while (true)
        {
            if (await rpc.GetTransactionReceiptAsync(transactionHash, ct).WaitAsyncObserved(ct)
                is { } receipt)
            {
                // The injectable interface is a trust boundary. The default client validates
                // this too, but the pipeline itself must bind confirmation to the exact locally
                // computed transaction it requested.
                if (!string.Equals(
                        receipt.TransactionHash, transactionHash,
                        StringComparison.OrdinalIgnoreCase))
                    throw new EthereumInteractionException(
                        $"The RPC endpoint returned a receipt for transaction " +
                        $"{receipt.TransactionHash}, but the submitted bytes hash to " +
                        $"{transactionHash}. No matching receipt was observed.");

                attemptEvidence.MarkConfirmed(transactionHash);

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

                // Normalize the evidence-bearing field to the canonical locally computed hash.
                return receipt with { TransactionHash = transactionHash };
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
