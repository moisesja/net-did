using System.Collections;
using FluentAssertions;
using NetCrypto;
using NetDid.Core.Exceptions;
using NetDid.Method.Ethr.Crypto;
using NetDid.Method.Ethr.Deployment;
using NetDid.Method.Ethr.Emulator;
using NetDid.Method.Ethr.Rpc;
using Xunit;

namespace NetDid.Method.Ethr.Tests;

/// <summary>
/// Review-round-2 regressions for issue #107. These pin the complete transaction lifecycle:
/// receipt-confirmed transactions and merely possible/in-flight broadcasts are different
/// evidence states and must survive every failure exit without being conflated.
/// </summary>
public class Issue107ReviewRound2Tests
{
    private const string Registry = "0x03d5003bf0e79c5f5223588f347eba39afbc3818";
    private sealed record Actor(KeyPair KeyPair, KeyPairSigner Signer, string Address);

    private static Actor NewActor()
    {
        var pair = new DefaultKeyGenerator().Generate(KeyType.Secp256k1);
        return new Actor(
            pair,
            new KeyPairSigner(pair, new DefaultCryptoProvider()),
            EthereumAddress.FromCompressedPublicKey(pair.PublicKey).ToLowerInvariant());
    }

    private static DidEthrMethod MethodFor(IEthereumRpcClient client)
        => new(
            new SingleNetworkRpcFactory("sepolia", client),
            [KnownNetworks.Sepolia with { RpcUrl = "http://emulated.local" }],
            new DefaultKeyGenerator());

    private static DidEthrServiceAttribute Svc(
        string type = "Hub", string endpoint = "https://hub.example")
        => new() { ServiceType = type, ServiceEndpoint = endpoint };

    [Fact]
    public async Task Issue107_SendResponseFailsAfterAcceptance_ReportsOnlyInFlightHash()
    {
        var chain = new EmulatedEthereumChain(Registry);
        var owner = NewActor();
        var hostile = new LifecycleRpcClient(chain) { ThrowAfterAcceptedSendOnCall = 1 };

        var act = () => MethodFor(hostile).UpdateAsync(
            $"did:ethr:sepolia:{owner.Address}",
            new DidEthrUpdateOptions { ControllerKey = owner.Signer, AddServices = [Svc()] });

        var thrown = (await act.Should().ThrowAsync<HttpRequestException>()).Which;

        chain.CurrentBlockNumber.Should().Be(1, "the node accepted and mined the bytes");
        Confirmed(thrown).Should().BeEmpty("no receipt was observed");
        InFlight(thrown).Should().ContainSingle().Which.Should().MatchRegex("^0x[0-9a-f]{64}$");
    }

    [Fact]
    public async Task Issue107_ReceiptReadFailsAfterAcceptance_ReportsOnlyInFlightHash()
    {
        var chain = new EmulatedEthereumChain(Registry);
        var owner = NewActor();
        var hostile = new LifecycleRpcClient(chain) { ThrowOnReceipt = true };

        var act = () => MethodFor(hostile).UpdateAsync(
            $"did:ethr:sepolia:{owner.Address}",
            new DidEthrUpdateOptions { ControllerKey = owner.Signer, AddServices = [Svc()] });

        var thrown = (await act.Should().ThrowAsync<HttpRequestException>()).Which;

        chain.CurrentBlockNumber.Should().Be(1);
        Confirmed(thrown).Should().BeEmpty();
        InFlight(thrown).Should().ContainSingle();
    }

    [Fact]
    public async Task Issue107_CallerCancellationWhileReceiptPending_PreservesTypeAndInFlightHash()
    {
        var chain = new EmulatedEthereumChain(Registry);
        var owner = NewActor();
        using var cts = new CancellationTokenSource();
        var hostile = new LifecycleRpcClient(chain)
        {
            BeforeReceipt = () => cts.Cancel(),
            AlwaysPending = true,
        };

        var act = () => MethodFor(hostile).UpdateAsync(
            $"did:ethr:sepolia:{owner.Address}",
            new DidEthrUpdateOptions { ControllerKey = owner.Signer, AddServices = [Svc()] },
            cts.Token);

        var thrown = (await act.Should().ThrowAsync<OperationCanceledException>()).Which;

        Confirmed(thrown).Should().BeEmpty();
        InFlight(thrown).Should().ContainSingle();
    }

    [Fact]
    public async Task Issue107_InternalDeadlineWhileReceiptPending_ReportsInFlightHash()
    {
        var chain = new EmulatedEthereumChain(Registry);
        var owner = NewActor();
        var hostile = new LifecycleRpcClient(chain) { AlwaysPending = true };
        var method = MethodFor(hostile);
        method.WriteDeadline = TimeSpan.FromMilliseconds(25);

        var act = () => method.UpdateAsync(
            $"did:ethr:sepolia:{owner.Address}",
            new DidEthrUpdateOptions { ControllerKey = owner.Signer, AddServices = [Svc()] });

        var thrown = (await act.Should().ThrowAsync<EthereumInteractionException>()).Which;

        thrown.Message.Should().Contain("deadline");
        Confirmed(thrown).Should().BeEmpty();
        InFlight(thrown).Should().ContainSingle();
    }

    [Fact]
    public async Task Issue107_ForgedHashEchoOnFirstOperation_IsInFlightNotConfirmed()
    {
        var chain = new EmulatedEthereumChain(Registry);
        var owner = NewActor();
        var hostile = new LifecycleRpcClient(chain) { ForgeHashOnCall = 1 };

        var act = () => MethodFor(hostile).UpdateAsync(
            $"did:ethr:sepolia:{owner.Address}",
            new DidEthrUpdateOptions { ControllerKey = owner.Signer, AddServices = [Svc()] });

        var thrown = (await act.Should().ThrowAsync<EthereumInteractionException>()).Which;

        Confirmed(thrown).Should().BeEmpty(
            "eth_sendRawTransaction acceptance is not receipt confirmation");
        InFlight(thrown).Should().ContainSingle();
    }

    [Fact]
    public async Task Issue107_FailureOnOperationN_SeparatesConfirmedAndInFlightHashes()
    {
        var chain = new EmulatedEthereumChain(Registry);
        var owner = NewActor();
        var hostile = new LifecycleRpcClient(chain) { ThrowAfterAcceptedSendOnCall = 2 };

        var act = () => MethodFor(hostile).UpdateAsync(
            $"did:ethr:sepolia:{owner.Address}",
            new DidEthrUpdateOptions
            {
                ControllerKey = owner.Signer,
                AddServices =
                [
                    Svc("A", "https://a.example"),
                    Svc("B", "https://b.example"),
                ],
            });

        var thrown = (await act.Should().ThrowAsync<EthereumInteractionException>()).Which;

        chain.CurrentBlockNumber.Should().Be(2);
        Confirmed(thrown).Should().ContainSingle("operation 1 has a successful receipt");
        InFlight(thrown).Should().ContainSingle("operation 2 has no observed receipt");
    }

    [Fact]
    public async Task Issue107_RevertedReceipt_IsConfirmedAndNotInFlight()
    {
        var chain = new EmulatedEthereumChain(Registry);
        var owner = NewActor();
        var attacker = NewActor();
        var forgedOwnerWord = "0x" + new string('0', 24) + attacker.Address[2..];
        var hostile = new LifecycleRpcClient(chain)
        {
            CallOverride = (_, data) =>
                data.StartsWith("0x8733d4e8", StringComparison.Ordinal)
                    ? forgedOwnerWord
                    : null,
        };

        var act = () => MethodFor(hostile).UpdateAsync(
            $"did:ethr:sepolia:{owner.Address}",
            new DidEthrUpdateOptions { ControllerKey = attacker.Signer, AddServices = [Svc()] });

        var thrown = (await act.Should().ThrowAsync<EthereumInteractionException>()).Which;

        thrown.Message.Should().Contain("reverted on-chain");
        Confirmed(thrown).Should().ContainSingle(
            "a reverted transaction still has a receipt and consumed a nonce/gas");
        InFlight(thrown).Should().BeEmpty();
    }

    [Fact]
    public async Task Issue107_PreBroadcastFailure_DoesNotFabricateTransactionEvidence()
    {
        var chain = new EmulatedEthereumChain(Registry);
        var owner = NewActor();
        var hostile = new LifecycleRpcClient(chain) { GasPriceOverride = ulong.MaxValue };

        var act = () => MethodFor(hostile).UpdateAsync(
            $"did:ethr:sepolia:{owner.Address}",
            new DidEthrUpdateOptions { ControllerKey = owner.Signer, AddServices = [Svc()] });

        var thrown = (await act.Should().ThrowAsync<EthereumInteractionException>()).Which;

        thrown.Data.Contains(DidEthrMethod.LandedTransactionsKey).Should().BeFalse();
        thrown.Data.Contains(DidEthrMethod.InFlightTransactionsKey).Should().BeFalse(
            "nothing was signed or offered to eth_sendRawTransaction");
    }

    [Fact]
    public async Task Issue107_UntrustedExceptionMetadata_CannotForgeTransactionEvidence()
    {
        var chain = new EmulatedEthereumChain(Registry);
        var owner = NewActor();
        var hostile = new LifecycleRpcClient(chain) { ForgeEvidenceOnReceiptFailure = true };

        var act = () => MethodFor(hostile).UpdateAsync(
            $"did:ethr:sepolia:{owner.Address}",
            new DidEthrUpdateOptions { ControllerKey = owner.Signer, AddServices = [Svc()] });

        var thrown = (await act.Should().ThrowAsync<HttpRequestException>()).Which;

        chain.CurrentBlockNumber.Should().Be(1);
        Confirmed(thrown).Should().BeEmpty(
            "dependency-controlled Exception.Data is not confirmation evidence");
        InFlight(thrown).Should().ContainSingle()
            .Which.Should().NotBe(LifecycleRpcClient.AttackerHash);
    }

    [Fact]
    public async Task Issue107_PreBroadcastExceptionMetadata_CannotForgeTransactionEvidence()
    {
        var chain = new EmulatedEthereumChain(Registry);
        var owner = NewActor();
        var hostile = new LifecycleRpcClient(chain) { ForgeEvidenceOnNonceFailure = true };

        var act = () => MethodFor(hostile).UpdateAsync(
            $"did:ethr:sepolia:{owner.Address}",
            new DidEthrUpdateOptions { ControllerKey = owner.Signer, AddServices = [Svc()] });

        var thrown = (await act.Should().ThrowAsync<HttpRequestException>()).Which;

        chain.CurrentBlockNumber.Should().Be(0);
        thrown.Data.Contains(DidEthrMethod.LandedTransactionsKey).Should().BeFalse();
        thrown.Data.Contains(DidEthrMethod.InFlightTransactionsKey).Should().BeFalse();
    }

    [Fact]
    public async Task Issue107_ForgedReceiptHash_DoesNotConfirmSubmittedTransaction()
    {
        var chain = new EmulatedEthereumChain(Registry);
        var owner = NewActor();
        var hostile = new LifecycleRpcClient(chain) { ForgeReceiptHash = true };

        var act = () => MethodFor(hostile).UpdateAsync(
            $"did:ethr:sepolia:{owner.Address}",
            new DidEthrUpdateOptions { ControllerKey = owner.Signer, AddServices = [Svc()] });

        var thrown = (await act.Should().ThrowAsync<EthereumInteractionException>()).Which;

        chain.CurrentBlockNumber.Should().Be(1);
        thrown.Message.Should().Contain("No matching receipt was observed");
        Confirmed(thrown).Should().BeEmpty();
        InFlight(thrown).Should().ContainSingle()
            .Which.Should().NotBe(LifecycleRpcClient.AttackerHash);
    }

    [Fact]
    public async Task Issue107_DeadlineBoundsNonCooperativePreflightRpc()
    {
        var chain = new EmulatedEthereumChain(Registry);
        var owner = NewActor();
        var hostile = new LifecycleRpcClient(chain) { NeverCompleteOwnerCall = true };
        var method = MethodFor(hostile);
        method.WriteDeadline = TimeSpan.FromMilliseconds(25);

        var act = () => method.UpdateAsync(
            $"did:ethr:sepolia:{owner.Address}",
            new DidEthrUpdateOptions { ControllerKey = owner.Signer, AddServices = [Svc()] });

        var thrown = (await act.Should().ThrowAsync<EthereumInteractionException>()).Which;

        thrown.Message.Should().Contain("deadline");
        Confirmed(thrown).Should().BeEmpty();
        InFlight(thrown).Should().BeEmpty();
        chain.CurrentBlockNumber.Should().Be(0);
    }

    [Fact]
    public async Task Issue107_SpontaneousOperationCanceledException_IsNotCalledDeadline()
    {
        var chain = new EmulatedEthereumChain(Registry);
        var owner = NewActor();
        var hostile = new LifecycleRpcClient(chain) { CancelSendWithoutToken = true };

        var act = () => MethodFor(hostile).UpdateAsync(
            $"did:ethr:sepolia:{owner.Address}",
            new DidEthrUpdateOptions { ControllerKey = owner.Signer, AddServices = [Svc()] });

        var thrown = (await act.Should().ThrowAsync<OperationCanceledException>()).Which;

        thrown.Message.Should().Be("transport aborted independently");
        thrown.Message.Should().NotContain("deadline");
        Confirmed(thrown).Should().BeEmpty();
        InFlight(thrown).Should().ContainSingle();
    }

    [Fact]
    public async Task Issue107_ConfirmedHash_DominatesIdenticalRetryCandidate()
    {
        var chain = new EmulatedEthereumChain(Registry);
        var owner = NewActor();
        var hostile = new LifecycleRpcClient(chain)
        {
            NonceOverride = 0,
            ThrowBeforeSendOnCall = 2,
        };

        var act = () => MethodFor(hostile).UpdateAsync(
            $"did:ethr:sepolia:{owner.Address}",
            new DidEthrUpdateOptions
            {
                ControllerKey = owner.Signer,
                AddServices = [Svc(), Svc()],
            });

        var thrown = (await act.Should().ThrowAsync<EthereumInteractionException>()).Which;

        Confirmed(thrown).Should().ContainSingle();
        InFlight(thrown).Should().BeEmpty(
            "the identical locally computed hash is already receipt-confirmed");
    }

    [Fact]
    public async Task Issue107_CancellationReturningCompletedTask_DoesNotBroadcastNextOperation()
    {
        var chain = new EmulatedEthereumChain(Registry);
        var owner = NewActor();
        using var cts = new CancellationTokenSource();
        var hostile = new LifecycleRpcClient(chain)
        {
            CancelAfterAcceptedSendOnCall = 1,
            CancelAction = cts.Cancel,
        };

        var act = () => MethodFor(hostile).UpdateAsync(
            $"did:ethr:sepolia:{owner.Address}",
            new DidEthrUpdateOptions
            {
                ControllerKey = owner.Signer,
                AddServices =
                [
                    Svc("A", "https://a.example"),
                    Svc("B", "https://b.example"),
                ],
            },
            cts.Token);

        var thrown = (await act.Should().ThrowAsync<OperationCanceledException>()).Which;

        hostile.SendCount.Should().Be(1);
        chain.CurrentBlockNumber.Should().Be(1);
        Confirmed(thrown).Should().BeEmpty("the canceled send response was not processed");
        InFlight(thrown).Should().ContainSingle();
    }

    [Fact]
    public async Task Issue107_DeadlineIncludesNonCooperativePostWriteReadback()
    {
        var chain = new EmulatedEthereumChain(Registry);
        var owner = NewActor();
        var hostile = new LifecycleRpcClient(chain) { NeverCompleteOwnerCallOnCall = 2 };
        var method = MethodFor(hostile);
        method.WriteDeadline = TimeSpan.FromMilliseconds(50);

        var act = () => method.UpdateAsync(
            $"did:ethr:sepolia:{owner.Address}",
            new DidEthrUpdateOptions { ControllerKey = owner.Signer, AddServices = [Svc()] });

        var thrown = (await act.Should().ThrowAsync<EthereumInteractionException>()).Which;

        chain.CurrentBlockNumber.Should().Be(1);
        thrown.Message.Should().Contain("deadline");
        Confirmed(thrown).Should().ContainSingle(
            "the transaction was confirmed before post-write readback hung");
        InFlight(thrown).Should().BeEmpty();
    }

    [Fact]
    public async Task Issue107_DeploySendResponseFailure_PreservesInFlightHash()
    {
        var chain = new EmulatedEthereumChain(Registry);
        chain.RecognizeDeployableRegistry(
            Erc1056Registry.ModernCreationBytecode.ToArray(), legacyNonce: false);
        var deployer = NewActor();
        var hostile = new LifecycleRpcClient(chain) { ThrowAfterAcceptedSendOnCall = 1 };

        var act = () => Erc1056Registry.DeployAsync(hostile, deployer.Signer, 11155111);

        var thrown = (await act.Should().ThrowAsync<HttpRequestException>()).Which;

        chain.CurrentBlockNumber.Should().Be(1);
        Confirmed(thrown).Should().BeEmpty();
        InFlight(thrown).Should().ContainSingle();
    }

    [Fact]
    public async Task Issue107_PoisonedExceptionData_CannotDestroyPipelineOwnedEvidence()
    {
        var chain = new EmulatedEthereumChain(Registry);
        var owner = NewActor();
        var hostile = new LifecycleRpcClient(chain)
        {
            ThrowPoisonedDataAfterAcceptedSendOnCall = 1,
        };

        var act = () => MethodFor(hostile).UpdateAsync(
            $"did:ethr:sepolia:{owner.Address}",
            new DidEthrUpdateOptions { ControllerKey = owner.Signer, AddServices = [Svc()] });

        var thrown = (await act.Should().ThrowAsync<HttpRequestException>()).Which;

        chain.CurrentBlockNumber.Should().Be(1);
        thrown.InnerException.Should().BeOfType<PoisonDataException>();
        Confirmed(thrown).Should().BeEmpty();
        InFlight(thrown).Should().ContainSingle();
    }

    [Fact]
    public async Task Issue107_PoisonedExceptionMessage_CannotDestroyPipelineOwnedEvidence()
    {
        var chain = new EmulatedEthereumChain(Registry);
        var owner = NewActor();
        var hostile = new LifecycleRpcClient(chain)
        {
            ThrowPoisonedMessageAfterAcceptedSendOnCall = 1,
        };

        var act = () => MethodFor(hostile).UpdateAsync(
            $"did:ethr:sepolia:{owner.Address}",
            new DidEthrUpdateOptions { ControllerKey = owner.Signer, AddServices = [Svc()] });

        var thrown = (await act.Should().ThrowAsync<HttpRequestException>()).Which;

        chain.CurrentBlockNumber.Should().Be(1);
        thrown.Message.Should().Be("A did:ethr RPC request failed during the write.");
        thrown.InnerException.Should().BeOfType<PoisonMessageException>();
        Confirmed(thrown).Should().BeEmpty();
        InFlight(thrown).Should().ContainSingle();
    }

    private static string[] Confirmed(Exception exception)
        => Assert.IsType<string[]>(exception.Data[DidEthrMethod.LandedTransactionsKey]);

    private static string[] InFlight(Exception exception)
        => Assert.IsType<string[]>(exception.Data[DidEthrMethod.InFlightTransactionsKey]);

    private sealed class LifecycleRpcClient(EmulatedEthereumChain inner) : IEthereumRpcClient
    {
        public const string AttackerHash =
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        public int? ThrowAfterAcceptedSendOnCall { get; init; }
        public int? ThrowPoisonedDataAfterAcceptedSendOnCall { get; init; }
        public int? ThrowPoisonedMessageAfterAcceptedSendOnCall { get; init; }
        public int? ThrowBeforeSendOnCall { get; init; }
        public int? CancelAfterAcceptedSendOnCall { get; init; }
        public int? ForgeHashOnCall { get; init; }
        public bool ThrowOnReceipt { get; init; }
        public bool ForgeEvidenceOnReceiptFailure { get; init; }
        public bool ForgeEvidenceOnNonceFailure { get; init; }
        public bool ForgeReceiptHash { get; init; }
        public bool NeverCompleteOwnerCall { get; init; }
        public int? NeverCompleteOwnerCallOnCall { get; init; }
        public bool CancelSendWithoutToken { get; init; }
        public bool AlwaysPending { get; init; }
        public Action? BeforeReceipt { get; init; }
        public ulong? GasPriceOverride { get; init; }
        public ulong? NonceOverride { get; init; }
        public Func<string, string, string?>? CallOverride { get; init; }
        public Action? CancelAction { get; init; }

        private int _sendCount;
        private int _callCount;
        public int SendCount => _sendCount;

        public Task<string> CallAsync(string to, string data, CancellationToken ct = default)
            => NeverCompleteOwnerCall || ++_callCount == NeverCompleteOwnerCallOnCall
                ? new TaskCompletionSource<string>(
                    TaskCreationOptions.RunContinuationsAsynchronously).Task
                : CallOverride?.Invoke(to, data) is { } forged
                ? Task.FromResult(forged)
                : inner.CallAsync(to, data, ct);

        public Task<IReadOnlyList<EthereumLogEntry>> GetLogsAsync(
            EthereumLogFilter filter, CancellationToken ct = default)
            => inner.GetLogsAsync(filter, ct);
        public Task<ulong> GetBlockNumberAsync(CancellationToken ct = default)
            => inner.GetBlockNumberAsync(ct);
        public Task<ulong> GetChainIdAsync(CancellationToken ct = default)
            => inner.GetChainIdAsync(ct);
        public Task<ulong> GetBlockTimestampAsync(
            ulong blockNumber, CancellationToken ct = default)
            => inner.GetBlockTimestampAsync(blockNumber, ct);
        public Task<ulong> GetTransactionCountAsync(
            string address, CancellationToken ct = default)
        {
            if (ForgeEvidenceOnNonceFailure)
                throw ForgedEvidenceException("nonce lookup failed");
            return NonceOverride is { } nonce
                ? Task.FromResult(nonce)
                : inner.GetTransactionCountAsync(address, ct);
        }
        public Task<ulong> GetGasPriceAsync(CancellationToken ct = default)
            => GasPriceOverride is { } price
                ? Task.FromResult(price)
                : inner.GetGasPriceAsync(ct);
        public Task<ulong> EstimateGasAsync(
            string from, string? to, string data, CancellationToken ct = default)
            => inner.EstimateGasAsync(from, to, data, ct);

        public async Task<string> SendRawTransactionAsync(
            byte[] signedTransaction, CancellationToken ct = default)
        {
            var call = ++_sendCount;
            if (call == ThrowBeforeSendOnCall)
                throw new HttpRequestException("send failed before acceptance");
            if (CancelSendWithoutToken)
                throw new OperationCanceledException("transport aborted independently");

            var realHash = await inner.SendRawTransactionAsync(signedTransaction, ct);
            if (call == CancelAfterAcceptedSendOnCall)
                CancelAction?.Invoke();
            if (call == ThrowPoisonedDataAfterAcceptedSendOnCall)
                throw new PoisonDataException("accepted send with poisoned metadata");
            if (call == ThrowPoisonedMessageAfterAcceptedSendOnCall)
                throw new PoisonMessageException();
            if (call == ThrowAfterAcceptedSendOnCall)
                throw new HttpRequestException("connection reset after node acceptance");
            return call == ForgeHashOnCall ? AttackerHash : realHash;
        }

        public async Task<EthereumTransactionReceipt?> GetTransactionReceiptAsync(
            string transactionHash, CancellationToken ct = default)
        {
            BeforeReceipt?.Invoke();
            ct.ThrowIfCancellationRequested();
            if (ForgeEvidenceOnReceiptFailure)
                throw ForgedEvidenceException("receipt lookup failed");
            if (ThrowOnReceipt)
                throw new HttpRequestException("connection reset during receipt polling");
            if (AlwaysPending)
                return null;

            var receipt = await inner.GetTransactionReceiptAsync(transactionHash, ct);
            return ForgeReceiptHash && receipt is not null
                ? receipt with { TransactionHash = AttackerHash }
                : receipt;
        }

        private static HttpRequestException ForgedEvidenceException(string message)
        {
            var exception = new HttpRequestException(message);
            exception.Data["netdid.ethr.confirmedTransaction"] = AttackerHash;
            exception.Data["netdid.ethr.inFlightTransaction"] = AttackerHash;
            exception.Data[DidEthrMethod.LandedTransactionsKey] = new[] { AttackerHash };
            exception.Data[DidEthrMethod.InFlightTransactionsKey] = new[] { AttackerHash };
            return exception;
        }
    }

    private sealed class PoisonDataException(string message) : HttpRequestException(message)
    {
        public override IDictionary Data
            => throw new InvalidOperationException("dependency denied Exception.Data access");
    }

    private sealed class PoisonMessageException : HttpRequestException
    {
        public override string Message
            => throw new InvalidOperationException("dependency denied Exception.Message access");
    }
}
