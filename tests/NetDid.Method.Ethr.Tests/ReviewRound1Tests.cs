using System.Numerics;
using FluentAssertions;
using NetCrypto;
using NetDid.Core.Exceptions;
using NetDid.Method.Ethr.Crypto;
using NetDid.Method.Ethr.Deployment;
using NetDid.Method.Ethr.Emulator;
using NetDid.Method.Ethr.Erc1056;
using NetDid.Method.Ethr.Rpc;
using NetDid.Method.Ethr.Transactions;
using Xunit;

namespace NetDid.Method.Ethr.Tests;

/// <summary>
/// Regression coverage for the five P1 findings in the PR #108 review. Each was reachable in
/// the merged-candidate code, and two contradicted fixes the PR description claimed; the
/// missing negative cases are exactly why they survived the earlier adversarial rounds.
/// </summary>
public class ReviewRound1Tests
{
    private const string Registry = "0x03d5003bf0e79c5f5223588f347eba39afbc3818";
    private const ulong SepoliaChainId = 11155111;

    private sealed record Actor(KeyPair KeyPair, KeyPairSigner Signer, string Address);

    private static Actor NewActor()
    {
        var pair = new DefaultKeyGenerator().Generate(KeyType.Secp256k1);
        return new Actor(
            pair,
            new KeyPairSigner(pair, new DefaultCryptoProvider()),
            EthereumAddress.FromCompressedPublicKey(pair.PublicKey).ToLowerInvariant());
    }

    private static EthereumNetworkConfig Network(
        BigInteger? maxFee = null, ulong? maxGasPrice = null)
    {
        var config = KnownNetworks.Sepolia with { RpcUrl = "http://emulated.local" };
        if (maxFee is { } fee) config = config with { MaxTransactionFeeWei = fee };
        if (maxGasPrice is { } price) config = config with { MaxGasPriceWei = price };
        return config;
    }

    private static DidEthrMethod MethodFor(IEthereumRpcClient client, EthereumNetworkConfig? network = null)
        => new(new SingleNetworkRpcFactory("sepolia", client),
               [network ?? Network()], new DefaultKeyGenerator());

    private static DidEthrServiceAttribute Svc(string type = "Hub", string url = "https://hub.example")
        => new() { ServiceType = type, ServiceEndpoint = url };

    // ── Finding 1: the configured total-fee ceiling was never passed to the pipeline ──

    [Fact]
    public async Task F1_ConfiguredFeeCeilingBelowTheDefault_IsEnforced()
    {
        // The caller lowered the ceiling; the pipeline was still using its own 0.1 ETH
        // default, so transactions were signed above the limit the caller selected.
        var chain = new EmulatedEthereumChain(Registry);
        var owner = NewActor();
        var network = Network(maxFee: 1_000);   // 1000 wei — far below any real fee
        byte[]? broadcast = null;
        var hostile = new HostileRpcClient(chain) { OnSendRawCaptured = raw => broadcast = raw };

        var act = () => MethodFor(hostile, network).UpdateAsync(
            $"did:ethr:sepolia:{owner.Address}",
            new DidEthrUpdateOptions { ControllerKey = owner.Signer, AddServices = [Svc()] });

        (await act.Should().ThrowAsync<EthereumInteractionException>())
            .WithMessage("*wei in fees*ceiling of 1000 wei*");
        broadcast.Should().BeNull("nothing may be signed above the configured ceiling");
    }

    [Fact]
    public async Task F1_ConfiguredFeeCeilingAboveTheDefault_IsHonoured()
    {
        // The mirror case: a caller who RAISES the ceiling was still rejected at the
        // library default, making the configured value doubly misleading.
        var chain = new EmulatedEthereumChain(Registry);
        var owner = NewActor();
        var network = Network(
            maxFee: BigInteger.Pow(10, 19),        // 10 ETH ceiling, far above the 0.1 default
            maxGasPrice: 5_000UL * 1_000_000_000); // 5000 gwei × ~125k gas ≈ 0.6 ETH
        var hostile = new HostileRpcClient(chain) { GasPriceOverride = 5_000UL * 1_000_000_000 };

        var result = await MethodFor(hostile, network).UpdateAsync(
            $"did:ethr:sepolia:{owner.Address}",
            new DidEthrUpdateOptions { ControllerKey = owner.Signer, AddServices = [Svc()] });

        result.DidDocument.Service.Should().ContainSingle(
            "a fee under the CONFIGURED ceiling must be allowed even though it exceeds the default");
    }

    // ── Finding 2: the broadcast-hash evidence was computed but never wired in ──

    [Fact]
    public async Task F2_ForgedHashEchoOnTheFirstOperation_StillReportsTheInFlightTransaction()
    {
        // hashes.Count == 0 at this point, so the `when (hashes.Count > 0)` filter skipped
        // the wrapper entirely and the caller learned nothing about a transaction the node
        // had already accepted — the exact unsafe-retry condition the PR claimed to close.
        var chain = new EmulatedEthereumChain(Registry);
        var owner = NewActor();
        var hostile = new HostileRpcClient(chain)
        {
            ForgeSendRawHashOnCall = 1,
        };

        var act = () => MethodFor(hostile).UpdateAsync(
            $"did:ethr:sepolia:{owner.Address}",
            new DidEthrUpdateOptions { ControllerKey = owner.Signer, AddServices = [Svc()] });

        var thrown = (await act.Should().ThrowAsync<Exception>()).Which;

        chain.CurrentBlockNumber.Should().Be(1, "the node accepted and mined the transaction");
        thrown.Data[DidEthrMethod.LandedTransactionsKey].Should().BeOfType<string[]>()
            .Which.Should().BeEmpty("the hash echo is not a receipt");
        thrown.Data[DidEthrMethod.InFlightTransactionsKey].Should().BeOfType<string[]>()
            .Which.Should().ContainSingle().Which.Should().MatchRegex("^0x[0-9a-f]{64}$");
    }

    [Fact]
    public async Task F2_ForgedHashEchoOnALaterOperation_KeepsEarlierAndCurrentTransactions()
    {
        // The wrapper reported only the earlier transactions and dropped the in-flight one.
        var chain = new EmulatedEthereumChain(Registry);
        var owner = NewActor();
        var hostile = new HostileRpcClient(chain)
        {
            ForgeSendRawHashOnCall = 2,
        };

        var act = () => MethodFor(hostile).UpdateAsync(
            $"did:ethr:sepolia:{owner.Address}",
            new DidEthrUpdateOptions
            {
                ControllerKey = owner.Signer,
                AddServices   = [Svc("A", "https://a.example"), Svc("B", "https://b.example")],
            });

        var thrown = (await act.Should().ThrowAsync<Exception>()).Which;

        chain.CurrentBlockNumber.Should().Be(2, "both transactions were accepted");
        thrown.Data[DidEthrMethod.LandedTransactionsKey].Should().BeOfType<string[]>()
            .Which.Should().ContainSingle("only the earlier transaction has a receipt");
        thrown.Data[DidEthrMethod.InFlightTransactionsKey].Should().BeOfType<string[]>()
            .Which.Should().ContainSingle("the current transaction has no observed receipt");
    }

    // ── Finding 3: the untrusted node chose the deployment's EIP-155 chain binding ──

    [Fact]
    public async Task F3_DeployAsync_ForgedNodeChainId_CannotCauseSigning()
    {
        // A node answering with another chain's id yields a deployment transaction signed
        // for THAT chain, which the endpoint can then forward there.
        var chain = new EmulatedEthereumChain(Registry, chainId: SepoliaChainId);
        chain.RecognizeDeployableRegistry(
            Erc1056Registry.ModernCreationBytecode.ToArray(), legacyNonce: false);
        var deployer = NewActor();
        byte[]? broadcast = null;
        var hostile = new HostileRpcClient(chain)
        {
            ChainIdOverride   = 1,                 // claims mainnet
            OnSendRawCaptured = raw => broadcast = raw,
        };

        var act = () => Erc1056Registry.DeployAsync(hostile, deployer.Signer, SepoliaChainId);

        (await act.Should().ThrowAsync<EthereumInteractionException>())
            .WithMessage("*chain*");
        broadcast.Should().BeNull("nothing may be signed against a contradicted chain id");
    }

    [Fact]
    public async Task F3_DeployAsync_WithTheExpectedChainId_StillWorks()
    {
        var chain = new EmulatedEthereumChain(Registry, chainId: SepoliaChainId);
        chain.RecognizeDeployableRegistry(
            Erc1056Registry.ModernCreationBytecode.ToArray(), legacyNonce: false);
        var deployer = NewActor();

        var deployed = await Erc1056Registry.DeployAsync(chain, deployer.Signer, SepoliaChainId);

        deployed.Should().Be(TransactionPipeline.ContractCreationAddress(deployer.Address, 0));
    }

    // ── Finding 4: the inner controller signature was never verified ──

    [Fact]
    public async Task F4_LyingControllerSigner_IsRejectedBeforeTheRelayerSpendsGas()
    {
        // A signer advertising the owner's public key while signing with another key passes
        // the owner pre-flight, and the relayer pays for a guaranteed registry revert.
        var chain = new EmulatedEthereumChain(Registry);
        var owner = NewActor();
        var impostor = NewActor();
        var relayer = NewActor();
        byte[]? broadcast = null;
        var hostile = new HostileRpcClient(chain) { OnSendRawCaptured = raw => broadcast = raw };

        var act = () => MethodFor(hostile).UpdateAsync(
            $"did:ethr:sepolia:{owner.Address}",
            new DidEthrUpdateOptions
            {
                // Advertises owner's key, signs with the impostor's.
                ControllerKey      = new LyingSigner(owner.Signer, impostor.Signer),
                UseMetaTransaction = true,
                Relayer            = relayer.Signer,
                AddServices        = [Svc()],
            });

        (await act.Should().ThrowAsync<EthereumInteractionException>())
            .WithMessage("*controller*signature*");
        broadcast.Should().BeNull("the relayer must not pay for a doomed transaction");
        (await chain.GetTransactionCountAsync(relayer.Address)).Should().Be(0);
    }

    [Fact]
    public async Task F4_HonestControllerSigner_StillWorksThroughTheRelayer()
    {
        var chain = new EmulatedEthereumChain(Registry);
        var owner = NewActor();
        var relayer = NewActor();

        var result = await MethodFor(chain).UpdateAsync(
            $"did:ethr:sepolia:{owner.Address}",
            new DidEthrUpdateOptions
            {
                ControllerKey      = owner.Signer,
                UseMetaTransaction = true,
                Relayer            = relayer.Signer,
                AddServices        = [Svc()],
            });

        result.DidDocument.Service.Should().ContainSingle();
    }

    // ── Finding 5: a confirmed deactivation reported Success = false ──

    [Fact]
    public async Task F5_DeactivateWithUnreadablePostWriteState_ThrowsWithEvidence_NotSuccessFalse()
    {
        // ResolveAsync maps RPC failure to an internalError RESULT rather than an exception, so
        // the catch was bypassed and a confirmed on-chain deactivation returned
        // Success = false — inviting an unnecessary, possibly unsafe retry.
        var chain = new EmulatedEthereumChain(Registry);
        var owner = NewActor();
        var writeDone = false;
        var hostile = new HostileRpcClient(chain)
        {
            // Break only the post-write read: `changed(identity)` drives resolution.
            CallOverride = (to, data) =>
                writeDone && data.StartsWith("0xf96d0f9f", StringComparison.Ordinal)
                    ? "0xdeadbeef"     // not one canonical ABI word → resolution internalError
                    : null,
            AfterReceipt = () => { writeDone = true; return Task.CompletedTask; },
        };

        var act = () => MethodFor(hostile).DeactivateAsync(
            $"did:ethr:sepolia:{owner.Address}",
            new DidEthrDeactivateOptions { ControllerKey = owner.Signer });

        var thrown = (await act.Should().ThrowAsync<EthereumInteractionException>()).Which;

        chain.CurrentBlockNumber.Should().Be(1, "the deactivation landed on-chain");
        thrown.Data[DidEthrMethod.LandedTransactionsKey].Should().BeOfType<string[]>()
            .Which.Should().ContainSingle();
    }

    [Fact]
    public async Task F5_DeactivateWithReadableState_StillReportsSuccessTruthfully()
    {
        var chain = new EmulatedEthereumChain(Registry);
        var owner = NewActor();

        var result = await MethodFor(chain).DeactivateAsync(
            $"did:ethr:sepolia:{owner.Address}",
            new DidEthrDeactivateOptions { ControllerKey = owner.Signer });

        result.Success.Should().BeTrue();
    }

    // ── Harnesses ────────────────────────────────────────────────────────────

    /// <summary>Advertises one key's public key while signing with another — a misconfigured
    /// or hostile HSM/remote signer.</summary>
    private sealed class LyingSigner(IRecoverableDigestSigner advertised, IRecoverableDigestSigner actual)
        : IRecoverableDigestSigner
    {
        public KeyType KeyType => advertised.KeyType;
        public ReadOnlyMemory<byte> PublicKey => advertised.PublicKey;

        public Task<RecoverableSignature> SignDigestAsync(
            ReadOnlyMemory<byte> digest32, CancellationToken ct = default)
            => actual.SignDigestAsync(digest32, ct);
    }

    private sealed class HostileRpcClient(EmulatedEthereumChain inner) : IEthereumRpcClient
    {
        public ulong? GasPriceOverride { get; init; }
        public ulong? ChainIdOverride { get; init; }
        /// <summary>1-based index of the eth_sendRawTransaction call whose hash echo is forged.</summary>
        public int? ForgeSendRawHashOnCall { get; init; }
        public Func<string, string, string?>? CallOverride { get; init; }
        public Action<byte[]>? OnSendRawCaptured { get; init; }
        public Func<Task>? AfterReceipt { get; init; }

        private int _sendCount;

        public Task<string> CallAsync(string to, string data, CancellationToken ct = default)
            => CallOverride?.Invoke(to, data) is { } forged
                ? Task.FromResult(forged)
                : inner.CallAsync(to, data, ct);

        public Task<IReadOnlyList<EthereumLogEntry>> GetLogsAsync(EthereumLogFilter filter, CancellationToken ct = default)
            => inner.GetLogsAsync(filter, ct);
        public Task<ulong> GetBlockNumberAsync(CancellationToken ct = default)
            => inner.GetBlockNumberAsync(ct);
        public Task<ulong> GetChainIdAsync(CancellationToken ct = default)
            => ChainIdOverride is { } id ? Task.FromResult(id) : inner.GetChainIdAsync(ct);
        public Task<ulong> GetBlockTimestampAsync(ulong blockNumber, CancellationToken ct = default)
            => inner.GetBlockTimestampAsync(blockNumber, ct);
        public Task<ulong> GetTransactionCountAsync(string address, CancellationToken ct = default)
            => inner.GetTransactionCountAsync(address, ct);
        public Task<ulong> GetGasPriceAsync(CancellationToken ct = default)
            => GasPriceOverride is { } price ? Task.FromResult(price) : inner.GetGasPriceAsync(ct);
        public Task<ulong> EstimateGasAsync(string from, string? to, string data, CancellationToken ct = default)
            => inner.EstimateGasAsync(from, to, data, ct);

        public async Task<string> SendRawTransactionAsync(byte[] signedTransaction, CancellationToken ct = default)
        {
            OnSendRawCaptured?.Invoke(signedTransaction);
            var real = await inner.SendRawTransactionAsync(signedTransaction, ct);
            return ++_sendCount == ForgeSendRawHashOnCall ? "0x" + new string('a', 64) : real;
        }

        public async Task<EthereumTransactionReceipt?> GetTransactionReceiptAsync(
            string transactionHash, CancellationToken ct = default)
        {
            var receipt = await inner.GetTransactionReceiptAsync(transactionHash, ct);
            if (AfterReceipt is not null) await AfterReceipt();
            return receipt;
        }
    }
}
