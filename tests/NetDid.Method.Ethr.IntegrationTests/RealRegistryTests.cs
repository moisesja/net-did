using System.Numerics;
using System.Text;
using FluentAssertions;
using NetCrypto;
using NetDid.Core.Exceptions;
using NetDid.Method.Ethr;
using NetDid.Method.Ethr.Crypto;
using NetDid.Method.Ethr.Deployment;
using NetDid.Method.Ethr.Erc1056;
using NetDid.Method.Ethr.Rpc;
using NetDid.Method.Ethr.Transactions;
using Xunit;

namespace NetDid.Method.Ethr.IntegrationTests;

/// <summary>
/// The real-EVM oracle (issue #107): Anvil executes the ACTUAL EthereumDIDRegistry
/// bytecode of both deployed generations, so these tests prove — against a real node and
/// real contracts — that our RLP encoding, EIP-155 signatures, ABI calldata, deployment
/// bytecode, meta-transaction preimages, and legacy-nonce handling are correct, and that
/// the resolver reconstructs documents from genuine on-chain logs.
///
/// Opt-in: NETDID_ETHR_INTEGRATION=1 (requires Docker). See AnvilFixture.
/// </summary>
[Collection("anvil")]
public class RealRegistryTests(AnvilFixture anvil)
{
    private sealed record Actor(byte[] PrivateKey, byte[] PublicKey, string Address);

    private static Actor ActorFromKey(byte[] privateKey)
    {
        using var pair = new DefaultKeyGenerator().FromPrivateKey(KeyType.Secp256k1, privateKey);
        return new Actor(
            privateKey,
            pair.PublicKey,
            EthereumAddress.FromCompressedPublicKey(pair.PublicKey).ToLowerInvariant());
    }

    private static Actor FreshActor()
    {
        using var pair = new DefaultKeyGenerator().Generate(KeyType.Secp256k1);
        return new Actor(
            pair.PrivateKey,
            pair.PublicKey,
            EthereumAddress.FromCompressedPublicKey(pair.PublicKey).ToLowerInvariant());
    }

    private Actor Funder => ActorFromKey(AnvilFixture.FunderKey);

    // ── Low-level pipeline helpers (the DidEthrMethod write API sits on the same path) ──

    private async Task<EthereumTransactionReceipt> SendAndConfirmAsync(
        Actor sender, string? to, string dataHex, BigInteger? value = null)
    {
        var client = anvil.Client;
        var data = dataHex.Length > 2 ? Convert.FromHexString(dataHex[2..]) : [];
        var tx = new EthereumTransaction
        {
            Nonce    = await client.GetTransactionCountAsync(sender.Address),
            GasPrice = await client.GetGasPriceAsync(),
            GasLimit = await client.EstimateGasAsync(sender.Address, to, dataHex),
            To       = to,
            Value    = value ?? BigInteger.Zero,
            Data     = data,
            ChainId  = AnvilFixture.ChainId,
        };
        var (signature, recoveryId) = Secp256k1Recoverable.Sign(sender.PrivateKey, tx.SigningDigest());
        var hash = await client.SendRawTransactionAsync(tx.EncodeSigned(signature, recoveryId));

        for (var attempt = 0; attempt < 40; attempt++)
        {
            if (await client.GetTransactionReceiptAsync(hash) is { } receipt)
                return receipt;
            await Task.Delay(250);
        }
        throw new TimeoutException($"Transaction {hash} was not mined.");
    }

    /// <summary>Sends a transaction expected to REVERT (estimateGas would reject it up front).</summary>
    private async Task<EthereumTransactionReceipt> SendExpectingRevertAsync(
        Actor sender, string to, string dataHex)
    {
        var client = anvil.Client;
        var tx = new EthereumTransaction
        {
            Nonce    = await client.GetTransactionCountAsync(sender.Address),
            GasPrice = await client.GetGasPriceAsync(),
            GasLimit = 500_000,
            To       = to,
            Data     = Convert.FromHexString(dataHex[2..]),
            ChainId  = AnvilFixture.ChainId,
        };
        var (signature, recoveryId) = Secp256k1Recoverable.Sign(sender.PrivateKey, tx.SigningDigest());
        var hash = await client.SendRawTransactionAsync(tx.EncodeSigned(signature, recoveryId));

        for (var attempt = 0; attempt < 40; attempt++)
        {
            if (await client.GetTransactionReceiptAsync(hash) is { } receipt)
                return receipt;
            await Task.Delay(250);
        }
        throw new TimeoutException($"Transaction {hash} was not mined.");
    }

    private Task<string> DeployRegistryAsync(bool legacy = false)
        => Erc1056Registry.DeployAsync(
            anvil.Client,
            new KeyPairSigner(
                new DefaultKeyGenerator().FromPrivateKey(KeyType.Secp256k1, AnvilFixture.FunderKey),
                new DefaultCryptoProvider()),
            legacy);

    private DidEthrMethod MethodFor(string registryAddress)
    {
        var network = new EthereumNetworkConfig
        {
            Name            = "anvil",
            RpcUrl          = anvil.RpcUrl,
            ChainId         = "0x7a69", // 31337
            RegistryAddress = registryAddress,
        };
        return new DidEthrMethod(
            DefaultEthereumRpcClientFactory.CreateDirect([network]), [network],
            new DefaultKeyGenerator());
    }

    private async Task<BigInteger> ContractNonceAsync(string registry, string account)
    {
        var result = await anvil.Client.CallAsync(
            registry, Erc1056TransactionBuilder.NonceCalldata(account));
        return new BigInteger(Convert.FromHexString(result[2..]), isUnsigned: true, isBigEndian: true);
    }

    private static string MetaCalldata(Actor signer, string identity, Erc1056Operation op, BigInteger nonce, string registry)
    {
        var digest = Erc1056TransactionBuilder.MetaTransactionDigest(registry, nonce, identity, op);
        var (signature, recoveryId) = Secp256k1Recoverable.Sign(signer.PrivateKey, digest);
        return op.SignedCalldata((byte)(27 + recoveryId), signature[..32], signature[32..]);
    }

    // ── Deployment + reads ───────────────────────────────────────────────────

    [EthrIntegrationFact]
    public async Task ModernRegistry_Deploys_AndServesImplicitOwnership()
    {
        var registry = await DeployRegistryAsync();
        var identity = FreshActor();

        var owner = await anvil.Client.CallAsync(registry, Erc1056Calls.IdentityOwner(identity.Address));
        owner.Should().EndWith(identity.Address[2..], "an untouched identity owns itself");

        var resolved = await MethodFor(registry).ResolveAsync($"did:ethr:anvil:{identity.Address}");
        resolved.ResolutionMetadata.Error.Should().BeNull();
        resolved.DidDocument!.VerificationMethod.Should().ContainSingle()
            .Which.BlockchainAccountId.Should().Be(
                $"eip155:31337:{EthereumAddress.FromCompressedPublicKey(identity.PublicKey)}");
    }

    // ── Direct writes round-trip through the real chain and our resolver ─────

    [EthrIntegrationFact]
    public async Task DirectWrites_OnRealBytecode_RoundTripThroughTheResolver()
    {
        var registry = await DeployRegistryAsync();
        var owner = Funder;
        var delegateActor = FreshActor();
        var did = $"did:ethr:anvil:{owner.Address}";
        var method = MethodFor(registry);
        var endpoint = Encoding.UTF8.GetBytes("https://hub.example.com/messages");

        (await SendAndConfirmAsync(owner, registry, Erc1056TransactionBuilder
                .SetAttribute(owner.Address, "did/svc/MessagingService", endpoint, 86_400)
                .DirectCalldata))
            .Succeeded.Should().BeTrue();
        (await SendAndConfirmAsync(owner, registry, Erc1056TransactionBuilder
                .AddDelegate(owner.Address, "sigAuth", delegateActor.Address, 86_400)
                .DirectCalldata))
            .Succeeded.Should().BeTrue();

        var resolved = await method.ResolveAsync(did);
        resolved.ResolutionMetadata.Error.Should().BeNull();
        resolved.DidDocument!.VerificationMethod!.Should().HaveCount(2);
        resolved.DidDocument.Service.Should().ContainSingle()
            .Which.Type.Should().Be("MessagingService");
        resolved.DidDocument.Authentication!.Should().HaveCount(2);

        (await SendAndConfirmAsync(owner, registry, Erc1056TransactionBuilder
                .RevokeDelegate(owner.Address, "sigAuth", delegateActor.Address)
                .DirectCalldata))
            .Succeeded.Should().BeTrue();

        // ERC-1056 revocation sets validTo = the revocation block's timestamp, and the
        // (JS-compatible) resolver keeps an entry while validTo >= now — so on a live
        // chain the revocation takes effect the NEXT wall-clock second. Step past it.
        await Task.Delay(TimeSpan.FromSeconds(2));

        (await method.ResolveAsync(did)).DidDocument!.VerificationMethod!.Should().HaveCount(1);
    }

    [EthrIntegrationFact]
    public async Task ValueTransfer_FundsAFreshController_WhoCanThenWrite()
    {
        var registry = await DeployRegistryAsync();
        var freshOwner = FreshActor();

        (await SendAndConfirmAsync(Funder, freshOwner.Address, "0x",
                value: BigInteger.Pow(10, 18)))
            .Succeeded.Should().BeTrue("a plain value transfer through our pipeline must land");

        (await SendAndConfirmAsync(freshOwner, registry, Erc1056TransactionBuilder
                .SetAttribute(freshOwner.Address, "did/svc/Inbox",
                    Encoding.UTF8.GetBytes("https://inbox.example"), 3_600)
                .DirectCalldata))
            .Succeeded.Should().BeTrue("the freshly funded key must be able to pay for its own writes");
    }

    // ── Meta-transactions against the real contracts ─────────────────────────

    [EthrIntegrationFact]
    public async Task MetaChangeOwner_OnModernBytecode_Succeeds_AndReplayIsRejected()
    {
        var registry = await DeployRegistryAsync();
        var identity = FreshActor(); // never funded: the relayer pays
        var newOwner = FreshActor();

        var op = Erc1056TransactionBuilder.ChangeOwner(identity.Address, newOwner.Address);
        var nonce = await ContractNonceAsync(registry, identity.Address);
        nonce.Should().Be(0);
        var calldata = MetaCalldata(identity, identity.Address, op, nonce, registry);

        (await SendAndConfirmAsync(Funder, registry, calldata))
            .Succeeded.Should().BeTrue("the real contract must accept our 0x19 0x00 preimage signature");

        (await ContractNonceAsync(registry, identity.Address)).Should().Be(1,
            "the modern contract increments nonce[signer]");

        var resolved = await MethodFor(registry).ResolveAsync($"did:ethr:anvil:{identity.Address}");
        resolved.DidDocument!.VerificationMethod!
            .Single(v => v.Id.EndsWith("#controller"))
            .BlockchainAccountId!.ToLowerInvariant().Should().Contain(newOwner.Address[2..]);

        // Replay of the identical signed calldata must revert on the moved nonce.
        (await SendExpectingRevertAsync(Funder, registry, calldata))
            .Succeeded.Should().BeFalse("replaying a meta-transaction must fail on the real contract");
    }

    [EthrIntegrationFact]
    public async Task LegacyBytecode_AttributeMetaTx_RequiresTheIdentityNonce()
    {
        // The LegacyNonce divergence proven against the REAL v0.0.3 bytecode:
        // changeOwnerSigned increments nonce[identity]; a later setAttributeSigned
        // preimage must be built over nonce[identity], not nonce[signer].
        var registry = await DeployRegistryAsync(legacy: true);
        var identity = FreshActor();
        var newOwner = FreshActor();
        var endpoint = Encoding.UTF8.GetBytes("https://legacy.example.com");

        var changeOwner = Erc1056TransactionBuilder.ChangeOwner(identity.Address, newOwner.Address);
        (await SendAndConfirmAsync(Funder, registry,
                MetaCalldata(identity, identity.Address, changeOwner, nonce: 0, registry)))
            .Succeeded.Should().BeTrue();

        (await ContractNonceAsync(registry, identity.Address)).Should().Be(1,
            "the legacy contract increments nonce[identity], not nonce[signer]");
        (await ContractNonceAsync(registry, newOwner.Address)).Should().Be(0);

        var setAttribute = Erc1056TransactionBuilder.SetAttribute(
            identity.Address, "did/svc/Hub", endpoint, 86_400);

        // The modern nonce choice (nonce[newOwner] = 0) must revert on legacy bytecode…
        (await SendExpectingRevertAsync(Funder, registry,
                MetaCalldata(newOwner, identity.Address, setAttribute, nonce: 0, registry)))
            .Succeeded.Should().BeFalse("legacy attribute preimages read nonce[identity]");

        // …and the legacy choice (nonce[identity] = 1) must succeed.
        (await SendAndConfirmAsync(Funder, registry,
                MetaCalldata(newOwner, identity.Address, setAttribute, nonce: 1, registry)))
            .Succeeded.Should().BeTrue();

        var resolved = await MethodFor(registry).ResolveAsync($"did:ethr:anvil:{identity.Address}");
        resolved.DidDocument!.Service.Should().ContainSingle()
            .Which.Type.Should().Be("Hub");
    }

    // ── The public API, end to end on a real chain ───────────────────────────

    [EthrIntegrationFact]
    public async Task PublicApi_FullLifecycle_OnRealBytecode()
    {
        var registry = await DeployRegistryAsync();
        var method = MethodFor(registry);
        var crypto = new DefaultCryptoProvider();
        var keyGen = new DefaultKeyGenerator();

        // Controller = a fresh key funded through our own pipeline; relayer = dev account.
        using var ownerPair = keyGen.Generate(KeyType.Secp256k1);
        using var ownerSigner = new KeyPairSigner(ownerPair, crypto, ownsKeyPair: false);
        var ownerAddress = EthereumAddress.FromCompressedPublicKey(ownerPair.PublicKey).ToLowerInvariant();
        using var relayerPair = keyGen.FromPrivateKey(KeyType.Secp256k1, AnvilFixture.SecondKey);
        using var relayerSigner = new KeyPairSigner(relayerPair, crypto, ownsKeyPair: false);
        (await SendAndConfirmAsync(Funder, ownerAddress, "0x", BigInteger.Pow(10, 18)))
            .Succeeded.Should().BeTrue();

        var did = $"did:ethr:anvil:{ownerAddress}";
        var delegateActor = FreshActor();

        // Update 1 (direct): add a service + a sigAuth delegate.
        var updated = await method.UpdateAsync(did, new DidEthrUpdateOptions
        {
            ControllerKey = ownerSigner,
            AddServices   =
            [
                new DidEthrServiceAttribute
                {
                    ServiceType = "MessagingService", ServiceEndpoint = "https://hub.example/messages",
                },
            ],
            AddDelegates =
            [
                new DidEthrDelegate
                {
                    DelegateType = "sigAuth", DelegateAddress = delegateActor.Address,
                    Validity = TimeSpan.FromDays(30),
                },
            ],
        });
        updated.DidDocument.VerificationMethod!.Should().HaveCount(2);
        updated.DidDocument.Service.Should().ContainSingle();

        // Update 2 (meta-tx): the relayer pays; the controller key only signs payloads.
        var metaUpdated = await method.UpdateAsync(did, new DidEthrUpdateOptions
        {
            ControllerKey      = ownerSigner,
            UseMetaTransaction = true,
            Relayer            = relayerSigner,
            RemoveServices     =
            [
                new DidEthrServiceAttribute
                {
                    ServiceType = "MessagingService", ServiceEndpoint = "https://hub.example/messages",
                },
            ],
        });
        metaUpdated.DidDocument.Service.Should().BeNull();

        // Deactivate (direct): owner → 0x0, permanently.
        var deactivated = await method.DeactivateAsync(did, new DidEthrDeactivateOptions
        {
            ControllerKey = ownerSigner,
        });
        deactivated.Success.Should().BeTrue();

        var resolved = await method.ResolveAsync(did);
        resolved.DocumentMetadata!.Deactivated.Should().BeTrue();
        resolved.DidDocument!.VerificationMethod.Should().BeNull();

        // Historical resolution still shows the pre-deactivation state: the version
        // before the deactivation block (the resolver reports the deactivating block
        // as the current versionId).
        var beforeDeactivation = await method.ResolveAsync(did, new DidEthrResolveOptions
        {
            VersionId = (ulong.Parse(resolved.DocumentMetadata.VersionId!) - 1)
                .ToString(System.Globalization.CultureInfo.InvariantCulture),
        });
        beforeDeactivation.DidDocument!.VerificationMethod!.Should().HaveCount(2);
    }

    // NOTE — no wrong-chain-id / high-S negative tests here, deliberately: Anvil is a
    // permissive dev node and ACCEPTS both (verified empirically against v1.7.1), while
    // mainnet consensus (EIP-155 replay protection, EIP-2 low-S) rejects them. Those
    // rules are enforced strictly by the emulator (EmulatedEthereumChainTests), which
    // models consensus-grade validation rather than dev-node leniency.
}
