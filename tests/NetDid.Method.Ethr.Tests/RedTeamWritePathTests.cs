using System.Numerics;
using FluentAssertions;
using NetCrypto;
using NetDid.Core.Exceptions;
using NetDid.Core.Model;
using NetDid.Method.Ethr.Crypto;
using NetDid.Method.Ethr.Deployment;
using NetDid.Method.Ethr.Emulator;
using NetDid.Method.Ethr.Erc1056;
using NetDid.Method.Ethr.Rpc;
using Xunit;

namespace NetDid.Method.Ethr.Tests;

/// <summary>
/// Adversarial regression suite (issue #107 red-team pass): trust boundaries, TOCTOU, and
/// hostile RPC nodes on the did:ethr write path. Each test was written as a working EXPLOIT
/// against the pre-review implementation and is kept here, inverted, to pin the fix — so a
/// regression re-opens a demonstrated attack, not a hypothetical one.
///
/// Findings pinned: F1 unbounded gas price (A1), F2 mid-batch evidence loss (A2a/b/c),
/// F3 authority evidence derived from intent (A3), F4 zero-address effective key (A4),
/// F5 unverified deployment address (A5), F6 non-canonical key form (A8). A6/A7/A9 record
/// attack classes that were already correctly defended.
/// </summary>
public class RedTeamWritePathTests
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

    private static EthereumNetworkConfig Network()
        => KnownNetworks.Sepolia with { RpcUrl = "http://emulated.local" };

    private static DidEthrMethod MethodFor(IEthereumRpcClient client)
        => new(new SingleNetworkRpcFactory("sepolia", client), [Network()], new DefaultKeyGenerator());

    private static DidEthrServiceAttribute Svc(string type = "Hub", string url = "https://hub.example")
        => new() { ServiceType = type, ServiceEndpoint = url };

    // ══ A1: hostile eth_gasPrice — no cap anywhere on the write path ═════════

    [Fact]
    public async Task A1_HostileGasPrice_IsRejectedBeforeAnythingIsSigned()
    {
        var chain = new EmulatedEthereumChain(Registry);
        var owner = NewActor();

        // 18.44 ETH *per gas*. A real attacker picks balance/gasUsed so the transaction
        // still succeeds and the signer is drained to the block producer.
        const ulong HostileGasPrice = ulong.MaxValue;
        byte[]? broadcast = null;
        var hostile = new HostileRpcClient(chain)
        {
            GasPriceOverride  = HostileGasPrice,
            OnSendRawCaptured = raw => broadcast = raw,
        };

        var act = () => MethodFor(hostile).UpdateAsync(
            $"did:ethr:sepolia:{owner.Address}",
            new DidEthrUpdateOptions { ControllerKey = owner.Signer, AddServices = [Svc()] });

        (await act.Should().ThrowAsync<EthereumInteractionException>())
            .WithMessage("*gas price*ceiling*");
        broadcast.Should().BeNull("nothing may be signed or broadcast at a hostile fee");
        chain.CurrentBlockNumber.Should().Be(0);
    }

    [Fact]
    public async Task A1c_HonestlyExpensiveGasPrice_IsAccepted()
    {
        // The bounds must not deny honest, merely-expensive chains: 400 gwei is a bad day on
        // mainnet, and a registry write at that price costs ~0.05 ETH — under the fee ceiling.
        var chain = new EmulatedEthereumChain(Registry);
        var owner = NewActor();
        var network = Network();
        var hostile = new HostileRpcClient(chain) { GasPriceOverride = 400UL * 1_000_000_000UL };
        var method = new DidEthrMethod(
            new SingleNetworkRpcFactory("sepolia", hostile), [network], new DefaultKeyGenerator());

        var result = await method.UpdateAsync(
            $"did:ethr:sepolia:{owner.Address}",
            new DidEthrUpdateOptions { ControllerKey = owner.Signer, AddServices = [Svc()] });

        result.DidDocument.Service.Should().ContainSingle();
    }

    [Fact]
    public async Task A1d_PriceUnderTheCeilingButFeeOverIt_IsRejected()
    {
        // Price and limit are BOTH node-controlled, so bounding them separately still permits
        // their product to reach the product of the ceilings. 5000 gwei passes the price
        // ceiling exactly, yet ~125k gas puts the authorized fee at ~0.6 ETH.
        var chain = new EmulatedEthereumChain(Registry);
        var owner = NewActor();
        var network = Network();
        var hostile = new HostileRpcClient(chain) { GasPriceOverride = network.MaxGasPriceWei };
        var method = new DidEthrMethod(
            new SingleNetworkRpcFactory("sepolia", hostile), [network], new DefaultKeyGenerator());

        var act = () => method.UpdateAsync(
            $"did:ethr:sepolia:{owner.Address}",
            new DidEthrUpdateOptions { ControllerKey = owner.Signer, AddServices = [Svc()] });

        (await act.Should().ThrowAsync<EthereumInteractionException>())
            .WithMessage("*wei in fees*ceiling*");
        chain.CurrentBlockNumber.Should().Be(0);
    }

    [Fact]
    public async Task A1b_GasEstimateAboveTheCeiling_FailsClosedInsteadOfUnderProvisioning()
    {
        // Clamping an over-ceiling estimate DOWN signs a transaction guaranteed to run out
        // of gas — burning the whole limit and surfacing as "the registry rejected the
        // operation", which is false. Fail closed instead.
        var chain = new EmulatedEthereumChain(Registry);
        var owner = NewActor();
        byte[]? broadcast = null;
        var hostile = new HostileRpcClient(chain)
        {
            GasEstimateOverride = ulong.MaxValue / 2,
            OnSendRawCaptured   = raw => broadcast = raw,
        };

        var act = () => MethodFor(hostile).UpdateAsync(
            $"did:ethr:sepolia:{owner.Address}",
            new DidEthrUpdateOptions { ControllerKey = owner.Signer, AddServices = [Svc()] });

        (await act.Should().ThrowAsync<EthereumInteractionException>())
            .WithMessage("*above this library's*ceiling*");
        broadcast.Should().BeNull();
    }

    // ══ A2: mid-batch evidence loss — the wrapper only catches ONE type ══════

    [Fact]
    public async Task A2a_MalformedNonceWordMidBatch_StillReportsWhatLanded()
    {
        // Meta-tx path. The node answers op #1 honestly, then returns a malformed
        // nonce() word for op #2 — a pure RPC-response attack.
        var chain = new EmulatedEthereumChain(Registry);
        var owner = NewActor();
        var relayer = NewActor();
        var nonceCalls = 0;
        var hostile = new HostileRpcClient(chain)
        {
            CallOverride = (to, data) =>
                data.StartsWith("0x70ae92d2", StringComparison.Ordinal) && ++nonceCalls == 2
                    ? "0x00"          // not one canonical ABI word
                    : null,
        };

        var act = () => MethodFor(hostile).UpdateAsync(
            $"did:ethr:sepolia:{owner.Address}",
            new DidEthrUpdateOptions
            {
                ControllerKey      = owner.Signer,
                UseMetaTransaction = true,
                Relayer            = relayer.Signer,
                AddServices        = [Svc("A", "https://a.example"), Svc("B", "https://b.example")],
            });

        var thrown = (await act.Should().ThrowAsync<EthereumInteractionException>()).Which;

        // Operation #1 IS on chain, and the caller is told so — in the message AND
        // structurally, so a retry cannot double-apply it.
        chain.CurrentBlockNumber.Should().Be(1);
        thrown.Message.Should().Contain("after landing 1 of 2 operations");
        thrown.Data[DidEthrMethod.LandedTransactionsKey].Should().BeOfType<string[]>()
            .Which.Should().ContainSingle().Which.Should().MatchRegex("^0x[0-9a-f]{64}$");
    }

    [Fact]
    public async Task A2b_ConnectionDropMidBatch_StillReportsWhatLanded()
    {
        // The node accepts op #1 then resets the connection. HttpRequestException is
        // exactly what DefaultEthereumRpcClient lets escape (it is never wrapped).
        var chain = new EmulatedEthereumChain(Registry);
        var owner = NewActor();
        var counts = 0;
        var hostile = new HostileRpcClient(chain)
        {
            OnTransactionCount = () =>
            {
                if (++counts == 2)
                    throw new HttpRequestException("connection reset by peer");
            },
        };

        var act = () => MethodFor(hostile).UpdateAsync(
            $"did:ethr:sepolia:{owner.Address}",
            new DidEthrUpdateOptions
            {
                ControllerKey = owner.Signer,
                AddServices   = [Svc("A", "https://a.example"), Svc("B", "https://b.example")],
            });

        var thrown = (await act.Should().ThrowAsync<EthereumInteractionException>()).Which;

        chain.CurrentBlockNumber.Should().Be(1, "operation #1 landed");
        thrown.Message.Should().Contain("after landing 1 of 2 operations");
        thrown.Data[DidEthrMethod.LandedTransactionsKey].Should().BeOfType<string[]>()
            .Which.Should().ContainSingle();
    }

    [Fact]
    public async Task A2c_CallerCancellationMidBatch_KeepsItsTypeButCarriesWhatLanded()
    {
        var chain = new EmulatedEthereumChain(Registry);
        var owner = NewActor();
        using var cts = new CancellationTokenSource();
        var counts = 0;
        var hostile = new HostileRpcClient(chain)
        {
            OnTransactionCount = () => { if (++counts == 2) cts.Cancel(); },
        };

        var act = () => MethodFor(hostile).UpdateAsync(
            $"did:ethr:sepolia:{owner.Address}",
            new DidEthrUpdateOptions
            {
                ControllerKey = owner.Signer,
                AddServices   = [Svc("A", "https://a.example"), Svc("B", "https://b.example")],
            }, cts.Token);

        // Caller cancellation must stay cancellation (callers branch on the type)…
        var thrown = (await act.Should().ThrowAsync<OperationCanceledException>()).Which;

        // …but must not silently discard what already landed.
        chain.CurrentBlockNumber.Should().Be(1, "operation #1 landed before the cancel");
        thrown.Data[DidEthrMethod.LandedTransactionsKey].Should().BeOfType<string[]>()
            .Which.Should().ContainSingle();
    }

    // ══ A3: post-update authority evidence vs. the chain ════════════════════

    [Fact]
    public async Task A3_OwnerHijackedAfterTheLastOperation_AuthorityEvidenceFollowsTheChain()
    {
        var chain = new EmulatedEthereumChain(Registry);
        var owner = NewActor();
        var attacker = NewActor();
        var did = $"did:ethr:sepolia:{owner.Address}";

        // A racing third party (here: a leaked-key wallet, or an MEV-ordered tx) takes the
        // identity right after our operation confirms and before the read-back resolve.
        var hijacked = false;
        var hostile = new HostileRpcClient(chain)
        {
            AfterReceipt = async () =>
            {
                if (hijacked) return;
                hijacked = true;
                await SendDirectAsync(chain, owner,
                    Erc1056TransactionBuilder.ChangeOwner(owner.Address, attacker.Address)
                        .DirectCalldata);
            },
        };

        var result = await MethodFor(hostile).UpdateAsync(did, new DidEthrUpdateOptions
        {
            ControllerKey = owner.Signer,
            AddServices   = [Svc()],
        });

        // The document the SAME result carries already shows the attacker in control…
        var controllerVm = result.DidDocument.VerificationMethod!
            .Single(v => v.Id.EndsWith("#controller", StringComparison.Ordinal));
        controllerVm.BlockchainAccountId!.ToLowerInvariant()
            .Should().Contain(attacker.Address[2..]);

        // …and the authority evidence agrees, because it is READ BACK from the registry
        // rather than inferred from what we submitted.
        result.AuthorizationChange.Should().Be(AuthorizationChangeStatus.Changed);
        result.UpdateKeyChange.Should().Be(AuthorizationChangeStatus.Changed);
        result.EffectiveUpdateKeys.Should().Equal(attacker.Address);
        // RevealedUpdateKeys stays the key that actually authorized this update.
        result.RevealedUpdateKeys.Should().Equal(owner.Address);
    }

    [Fact]
    public async Task A4_UpdateToTheZeroOwner_ReportsTheIdentityAsTheRemainingAuthority()
    {
        var chain = new EmulatedEthereumChain(Registry);
        var owner = NewActor();
        var did = $"did:ethr:sepolia:{owner.Address}";

        var result = await MethodFor(chain).UpdateAsync(did, new DidEthrUpdateOptions
        {
            ControllerKey   = owner.Signer,
            NewOwnerAddress = "0x0000000000000000000000000000000000000000",
        });

        // The resolver reports the DID as deactivated — that flag is EVENT-based (the last
        // DIDOwnerChanged went to 0x0)…
        (await MethodFor(chain).ResolveAsync(did)).DocumentMetadata!.Deactivated.Should().BeTrue();

        // …but the registry's identityOwner() is `owner != 0 ? owner : identity`, so a zero
        // owner slot returns control to the IDENTITY. The authority evidence must say so:
        // claiming an empty set here would tell a caller nobody can write, while the
        // identity's own key still can (verified against real bytecode in
        // DeactivationRealityTests). Deactivation is a resolution property, not a lock.
        result.EffectiveUpdateKeys.Should().Equal(owner.Address);
        result.AuthorizationChange.Should().Be(AuthorizationChangeStatus.Unchanged,
            "the identity key retains write authority");
    }

    // ══ A5: DeployAsync trusts the node for the registry address ═════════════

    [Fact]
    public async Task A5_DeployAsync_RejectsANodeForgedContractAddress()
    {
        var chain = new EmulatedEthereumChain(Registry);
        chain.RecognizeDeployableRegistry(
            Erc1056Registry.ModernCreationBytecode.ToArray(), legacyNonce: false);
        var deployer = NewActor();
        const string AttackerRegistry = "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

        var hostile = new HostileRpcClient(chain) { ContractAddressOverride = AttackerRegistry };

        // A forged contractAddress would become the caller's registry trust anchor for
        // every subsequent did:ethr read and write. CREATE is deterministic, so we can
        // and do check it locally instead of believing the node.
        await FluentActions.Awaiting(() => Erc1056Registry.DeployAsync(hostile, deployer.Signer, SepoliaChainId))
            .Should().ThrowAsync<EthereumInteractionException>()
            .WithMessage($"*{AttackerRegistry}*deterministically yields*");
    }

    [Fact]
    public async Task A5b_DeployAsync_ReturnsTheDeterministicCreateAddress()
    {
        var chain = new EmulatedEthereumChain(Registry);
        chain.RecognizeDeployableRegistry(
            Erc1056Registry.ModernCreationBytecode.ToArray(), legacyNonce: false);
        var deployer = NewActor();

        var deployed = await Erc1056Registry.DeployAsync(chain, deployer.Signer, SepoliaChainId);

        deployed.Should().Be(
            Transactions.TransactionPipeline.ContractCreationAddress(deployer.Address, 0));
        // …and a registry really is there.
        (await chain.CallAsync(deployed, Erc1056Calls.IdentityOwner(deployer.Address)))
            .Should().EndWith(deployer.Address[2..]);
    }

    // ══ A8: EffectiveUpdateKeys is not normalised to the method's canonical form ══

    [Fact]
    public async Task A8_UnprefixedNewOwner_IsReportedInCanonicalForm()
    {
        var chain = new EmulatedEthereumChain(Registry);
        var owner = NewActor();
        var newOwner = NewActor();

        var result = await MethodFor(chain).UpdateAsync(
            $"did:ethr:sepolia:{owner.Address}",
            new DidEthrUpdateOptions
            {
                ControllerKey   = owner.Signer,
                NewOwnerAddress = newOwner.Address[2..],   // accepted by the builder
            });

        // Both key sets are reported in the method's canonical form (lowercase, 0x-prefixed)
        // because both are derived — never echoed from caller input — so a caller doing the
        // mandated exclusive set-equality matches the key that really holds authority.
        result.RevealedUpdateKeys.Should().Equal(owner.Address);
        result.EffectiveUpdateKeys.Should().Equal(newOwner.Address);
        result.EffectiveUpdateKeys!.Single().Should().StartWith("0x");
    }

    // ══ A9: hostile identityOwner lie — does the pre-flight grant anything? ══

    [Fact]
    public async Task A9_NodeLiesThatTheAttackerIsOwner_PreFlightPasses_ButTheRegistryStillRefuses()
    {
        var chain = new EmulatedEthereumChain(Registry);
        var owner = NewActor();
        var attacker = NewActor();
        var forgedOwnerWord = "0x" + new string('0', 24) + attacker.Address[2..];

        var hostile = new HostileRpcClient(chain)
        {
            CallOverride = (_, data) =>
                data.StartsWith("0x8733d4e8", StringComparison.Ordinal) ? forgedOwnerWord : null,
        };

        var act = () => MethodFor(hostile).UpdateAsync(
            $"did:ethr:sepolia:{owner.Address}",
            new DidEthrUpdateOptions { ControllerKey = attacker.Signer, AddServices = [Svc()] });

        // The advisory pre-flight is bypassed, but the contract is the enforcement point:
        // the transaction is broadcast and reverts. Fail-closed — no authority is granted.
        (await act.Should().ThrowAsync<EthereumInteractionException>())
            .WithMessage("*reverted on-chain*");
        (await MethodFor(chain).ResolveAsync($"did:ethr:sepolia:{owner.Address}"))
            .DidDocument!.Service.Should().BeNull();
    }

    // ══ A6/A7: attacks the implementation DOES defend (recorded as refuted) ══

    [Fact]
    public async Task A6_UnstableCallerCollection_IsSnapshottedExactlyOnce()
    {
        var chain = new EmulatedEthereumChain(Registry);
        var owner = NewActor();
        var unstable = new ShapeShiftingList(
            first: Svc("Honest", "https://honest.example"),
            later: Svc("Evil", "https://evil.example"));

        var result = await MethodFor(chain).UpdateAsync(
            $"did:ethr:sepolia:{owner.Address}",
            new DidEthrUpdateOptions { ControllerKey = owner.Signer, AddServices = unstable });

        unstable.Enumerations.Should().Be(1);
        result.DidDocument.Service!.Single().Type.Should().Be("Honest");
    }

    [Fact]
    public async Task A7_AttributeValueMutatedBeforeSigning_DoesNotChangeSignedBytes()
    {
        var chain = new EmulatedEthereumChain(Registry);
        var owner = NewActor();
        var value = Enumerable.Range(1, 32).Select(i => (byte)i).ToArray();
        var original = Convert.ToHexString(value).ToLowerInvariant();

        byte[]? broadcast = null;
        var hostile = new HostileRpcClient(chain)
        {
            // eth_estimateGas runs after the operation is built and before it is signed.
            OnEstimateGas     = () => Array.Fill(value, (byte)0xff),
            OnSendRawCaptured = raw => broadcast = raw,
        };

        await MethodFor(hostile).UpdateAsync(
            $"did:ethr:sepolia:{owner.Address}",
            new DidEthrUpdateOptions
            {
                ControllerKey = owner.Signer,
                AddAttributes =
                [
                    new DidEthrAttribute { Name = "did/pub/Ed25519/veriKey/base64", Value = value },
                ],
            });

        var signedHex = Convert.ToHexString(broadcast!).ToLowerInvariant();
        signedHex.Should().Contain(original);
        signedHex.Should().NotContain(new string('f', 64));
    }

    // ══ Helpers ═════════════════════════════════════════════════════════════

    private static async Task SendDirectAsync(
        EmulatedEthereumChain chain, Actor sender, string calldataHex)
    {
        var tx = new Transactions.EthereumTransaction
        {
            Nonce    = await chain.GetTransactionCountAsync(sender.Address),
            GasPrice = 1_000_000_000,
            GasLimit = 100_000,
            To       = Registry,
            Data     = Convert.FromHexString(calldataHex[2..]),
            ChainId  = SepoliaChainId,
        };
        var signature = await sender.Signer.SignDigestAsync(tx.SigningDigest());
        await chain.SendRawTransactionAsync(tx.EncodeSigned(signature.Signature64, signature.RecoveryId));
    }

    private sealed class ShapeShiftingList(DidEthrServiceAttribute first, DidEthrServiceAttribute later)
        : IReadOnlyList<DidEthrServiceAttribute>
    {
        public int Enumerations { get; private set; }
        public int Count => 1;
        public DidEthrServiceAttribute this[int index] => Enumerations == 0 ? first : later;

        public IEnumerator<DidEthrServiceAttribute> GetEnumerator()
        {
            var item = Enumerations++ == 0 ? first : later;
            yield return item;
        }

        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator()
            => GetEnumerator();
    }

    /// <summary>Hostile RPC decorator: every hook models something a node can do.</summary>
    private sealed class HostileRpcClient(EmulatedEthereumChain inner) : IEthereumRpcClient
    {
        public ulong? GasPriceOverride { get; init; }
        public ulong? GasEstimateOverride { get; init; }
        public string? ContractAddressOverride { get; init; }
        public Func<string, string, string?>? CallOverride { get; init; }
        public Action? OnTransactionCount { get; init; }
        public Action? OnEstimateGas { get; init; }
        public Action<byte[]>? OnSendRawCaptured { get; init; }
        public Func<Task>? AfterReceipt { get; init; }

        public Task<string> CallAsync(string to, string data, CancellationToken ct = default)
            => CallOverride?.Invoke(to, data) is { } forged
                ? Task.FromResult(forged)
                : inner.CallAsync(to, data, ct);

        public Task<IReadOnlyList<EthereumLogEntry>> GetLogsAsync(EthereumLogFilter filter, CancellationToken ct = default)
            => inner.GetLogsAsync(filter, ct);
        public Task<ulong> GetBlockNumberAsync(CancellationToken ct = default)
            => inner.GetBlockNumberAsync(ct);
        public Task<ulong> GetChainIdAsync(CancellationToken ct = default)
            => inner.GetChainIdAsync(ct);
        public Task<ulong> GetBlockTimestampAsync(ulong blockNumber, CancellationToken ct = default)
            => inner.GetBlockTimestampAsync(blockNumber, ct);

        public Task<ulong> GetTransactionCountAsync(string address, CancellationToken ct = default)
        {
            OnTransactionCount?.Invoke();
            ct.ThrowIfCancellationRequested();
            return inner.GetTransactionCountAsync(address, ct);
        }

        public Task<ulong> GetGasPriceAsync(CancellationToken ct = default)
            => GasPriceOverride is { } price ? Task.FromResult(price) : inner.GetGasPriceAsync(ct);

        public Task<ulong> EstimateGasAsync(string from, string? to, string data, CancellationToken ct = default)
        {
            OnEstimateGas?.Invoke();
            return GasEstimateOverride is { } gas
                ? Task.FromResult(gas)
                : inner.EstimateGasAsync(from, to, data, ct);
        }

        public Task<string> SendRawTransactionAsync(byte[] signedTransaction, CancellationToken ct = default)
        {
            OnSendRawCaptured?.Invoke(signedTransaction);
            return inner.SendRawTransactionAsync(signedTransaction, ct);
        }

        public async Task<EthereumTransactionReceipt?> GetTransactionReceiptAsync(
            string transactionHash, CancellationToken ct = default)
        {
            var receipt = await inner.GetTransactionReceiptAsync(transactionHash, ct);
            if (receipt is null) return null;
            if (ContractAddressOverride is { } forged)
                receipt = receipt with { ContractAddress = forged };
            if (AfterReceipt is not null)
                await AfterReceipt();
            return receipt;
        }
    }
}
