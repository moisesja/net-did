using NetCrypto;
using NetDid.Core.Exceptions;
using NetDid.Method.Ethr.Rpc;
using NetDid.Method.Ethr.Transactions;

namespace NetDid.Method.Ethr.Deployment;

/// <summary>
/// The ERC-1056 <c>EthereumDIDRegistry</c> contract, vendored for deployment to
/// private / consortium / development EVM chains.
///
/// <para>
/// On public networks the registry is <b>already deployed</b> at the well-known addresses
/// in <see cref="Rpc.KnownNetworks"/> — nothing to deploy. This type exists for every
/// other EVM chain: deploy the registry once, then use the resulting address in an
/// <see cref="Rpc.EthereumNetworkConfig"/>.
/// </para>
///
/// <para><b>Provenance.</b> The embedded creation bytecode is copied verbatim from the
/// official npm artifacts (MIT-licensed, uport-project/ethr-did-registry):</para>
/// <list type="bullet">
///   <item><description><b>Modern</b> — <c>ethr-did-registry@1.3.0</c>,
///   <c>artifacts/contracts/EthereumDIDRegistry.sol/EthereumDIDRegistry.json → bytecode</c>
///   (Hardhat artifact, solc 0.8.6 source generation; the contract behind the
///   <c>0x03d5003b…</c> deployments, <c>LegacyNonce = false</c>).</description></item>
///   <item><description><b>Legacy</b> — <c>ethr-did-registry@0.0.3</c>,
///   <c>build/contracts/EthereumDIDRegistry.json → bytecode</c> (Truffle artifact,
///   solc 0.4.24; its <c>networks</c> map records the mainnet <c>0xdca7ef03…</c>
///   deployment this generation is known by, <c>LegacyNonce = true</c>).</description></item>
/// </list>
/// <para>A unit test pins the keccak256 of each embedded artifact so the bytes cannot
/// drift silently.</para>
/// </summary>
public static class Erc1056Registry
{
    private static readonly Lazy<byte[]> _modern = new(() => Load("ethr-did-registry-1.3.0.creation.hex"));
    private static readonly Lazy<byte[]> _legacy = new(() => Load("ethr-did-registry-0.0.3.creation.hex"));

    /// <summary>Creation bytecode of the modern (1.x) registry — <c>LegacyNonce = false</c>.</summary>
    public static ReadOnlyMemory<byte> ModernCreationBytecode => _modern.Value;

    /// <summary>Creation bytecode of the legacy (0.0.3) registry — <c>LegacyNonce = true</c>.</summary>
    public static ReadOnlyMemory<byte> LegacyCreationBytecode => _legacy.Value;

    /// <summary>
    /// Deploys the registry to the chain behind <paramref name="rpc"/> and returns the
    /// deployed contract address. The deployment transaction is built, EIP-155-signed
    /// (through the NetCrypto <see cref="IRecoverableDigestSigner"/> seam), and confirmed
    /// by the same pipeline the did:ethr Update path uses; <paramref name="deployerKey"/>
    /// must hold enough of the chain's native token for gas. Once submission begins, failures
    /// carry confirmed and possibly-broadcast transaction hashes through
    /// <see cref="DidEthrMethod.LandedTransactionsKey"/> and
    /// <see cref="DidEthrMethod.InFlightTransactionsKey"/>.
    /// </summary>
    /// <param name="rpc">Client for the target chain (e.g. via
    /// <see cref="DefaultEthereumRpcClientFactory.CreateDirect"/>).</param>
    /// <param name="deployerKey">A funded secp256k1 signer that pays for the deployment.</param>
    /// <param name="chainId">
    /// The EIP-155 chain id to sign for. <b>Required, and never taken from the node:</b> it is
    /// the replay binding baked into the signature, so letting the endpoint supply it would let
    /// a malicious endpoint obtain a deployment transaction signed for a different chain and
    /// forward it there. The node's own <c>eth_chainId</c> is cross-checked against this value
    /// and a disagreement aborts before anything is signed. (Writes enforce the same rule via
    /// <see cref="EthereumNetworkConfig.ChainId"/>.)
    /// </param>
    /// <param name="legacy">Deploy the legacy (0.0.3, <c>LegacyNonce = true</c>) generation
    /// instead of the modern 1.x contract. Almost always leave <c>false</c>; the legacy
    /// build exists for compatibility testing.</param>
    /// <param name="feeCeiling">
    /// Optional network configuration whose <see cref="EthereumNetworkConfig.MaxGasPriceWei"/>
    /// and <see cref="EthereumNetworkConfig.MaxTransactionFeeWei"/> bound what this deployment
    /// may spend. Omit to use the library defaults. Pass the same config you will resolve and
    /// write with, so one process cannot enforce a ceiling on updates while ignoring it here.
    /// </param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>The 0x-prefixed address for <see cref="EthereumNetworkConfig.RegistryAddress"/>.</returns>
    public static async Task<string> DeployAsync(
        IEthereumRpcClient rpc,
        IRecoverableDigestSigner deployerKey,
        ulong chainId,
        bool legacy = false,
        EthereumNetworkConfig? feeCeiling = null,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(rpc);
        ArgumentNullException.ThrowIfNull(deployerKey);

        ulong reportedChainId;
        try
        {
            reportedChainId = await rpc.GetChainIdAsync(ct).WaitAsync(ct);
        }
        catch (Exception ex)
        {
            throw DidEthrMethod.SanitizeUntrustedTransactionEvidence(ex);
        }
        if (reportedChainId != chainId)
            throw new EthereumInteractionException(
                $"The RPC endpoint reports chain id {reportedChainId}, but the deployment was " +
                $"requested for chain {chainId}. Nothing was signed: signing against the " +
                "endpoint's claim would let it obtain a transaction valid on a chain you did " +
                "not choose.");

        var bytecode = legacy ? LegacyCreationBytecode : ModernCreationBytecode;

        // The pipeline verifies the reported contract address against the deterministic
        // CREATE address before returning, so a node cannot nominate an attacker-controlled
        // contract as the caller's registry trust anchor.
        var attemptEvidence = new TransactionAttemptEvidence();
        EthereumTransactionReceipt receipt;
        try
        {
            receipt = await TransactionPipeline.SubmitAndConfirmAsync(
                rpc, deployerKey, to: null, bytecode.ToArray(), chainId, attemptEvidence,
                maxGasPriceWei: feeCeiling?.MaxGasPriceWei ?? TransactionPipeline.DefaultMaxGasPriceWei,
                maxTransactionFeeWei: feeCeiling?.MaxTransactionFeeWei,
                ct: ct);
        }
        catch (Exception ex)
        {
            if (attemptEvidence.ConfirmedHash is { } confirmed)
                throw DidEthrMethod.AttachTransactionEvidence(ex, [confirmed]);
            if (attemptEvidence.InFlightHash is { } inFlight)
                throw DidEthrMethod.AttachTransactionEvidence(ex, [], [inFlight]);
            throw DidEthrMethod.SanitizeUntrustedTransactionEvidence(ex);
        }

        return receipt.ContractAddress
            ?? throw new EthereumInteractionException(
                "The registry deployment was mined but the receipt reports no contract address.");
    }

    private static byte[] Load(string resourceName)
    {
        var assembly = typeof(Erc1056Registry).Assembly;
        var fullName = $"NetDid.Method.Ethr.Deployment.{resourceName}";
        using var stream = assembly.GetManifestResourceStream(fullName)
            ?? throw new InvalidOperationException($"Embedded resource '{fullName}' is missing.");
        using var reader = new StreamReader(stream);
        return Convert.FromHexString(reader.ReadToEnd().Trim());
    }
}
