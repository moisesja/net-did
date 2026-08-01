using System.Numerics;
using System.Text;
using FluentAssertions;
using NetCrypto;
using NetDid.Core.Exceptions;
using NetDid.Method.Ethr.Crypto;
using NetDid.Method.Ethr.Emulator;
using NetDid.Method.Ethr.Erc1056;
using NetDid.Method.Ethr.Rpc;
using NetDid.Method.Ethr.Transactions;
using Xunit;

namespace NetDid.Method.Ethr.Tests;

/// <summary>
/// Drives the emulator with REAL signed transactions (built by EthereumTransaction +
/// Secp256k1Recoverable — the pipeline pinned against the EIP-155 vector) and reads the
/// results back through the REAL did:ethr resolver. Authorization inside the emulator
/// comes from ecrecover, so a test passes only when the whole loop — calldata, RLP,
/// signing, contract semantics, event encoding, resolution — is consistent.
/// </summary>
public class EmulatedEthereumChainTests
{
    private const string Registry = "0x03d5003bf0e79c5f5223588f347eba39afbc3818";
    private const ulong ChainId = 11155111;

    private static readonly EthereumNetworkConfig Network = KnownNetworks.Sepolia with
    {
        RpcUrl = "http://emulated.local",
    };

    private sealed record Actor(KeyPair Key, byte[] PrivateKey, string Address);

    private static Actor NewActor()
    {
        var key = new DefaultKeyGenerator().Generate(KeyType.Secp256k1);
        return new Actor(
            key,
            key.PrivateKey,
            EthereumAddress.FromCompressedPublicKey(key.PublicKey).ToLowerInvariant());
    }

    private static DidEthrMethod MethodFor(EmulatedEthereumChain chain)
        => new(new SingleNetworkRpcFactory("sepolia", chain), [Network], new DefaultKeyGenerator());

    private static async Task<string> SendAsync(
        EmulatedEthereumChain chain, Actor sender, string? to, string dataHex,
        ulong? nonce = null, BigInteger? value = null)
    {
        var tx = new EthereumTransaction
        {
            Nonce    = nonce ?? await chain.GetTransactionCountAsync(sender.Address),
            GasPrice = 1_000_000_000,
            GasLimit = 100_000,
            To       = to,
            Value    = value ?? BigInteger.Zero,
            Data     = dataHex.Length > 2 ? Convert.FromHexString(dataHex[2..]) : [],
            ChainId  = ChainId,
        };
        var (signature, recoveryId) = Secp256k1Recoverable.Sign(sender.PrivateKey, tx.SigningDigest());
        return await chain.SendRawTransactionAsync(tx.EncodeSigned(signature, recoveryId));
    }

    private static string MetaCalldata(
        EmulatedEthereumChain chain, Actor signer, string identity, Erc1056Operation op,
        BigInteger nonce)
    {
        var digest = Erc1056TransactionBuilder.MetaTransactionDigest(Registry, nonce, identity, op);
        var (signature, recoveryId) = Secp256k1Recoverable.Sign(signer.PrivateKey, digest);
        return op.SignedCalldata((byte)(27 + recoveryId), signature[..32], signature[32..]);
    }

    // ── Direct (msg.sender-authorized) operations ────────────────────────────

    [Fact]
    public async Task DirectChangeOwner_ByTheOwner_UpdatesResolvedController()
    {
        var chain = new EmulatedEthereumChain(Registry);
        var owner = NewActor();
        var newOwner = NewActor();

        var hash = await SendAsync(chain, owner, Registry,
            Erc1056TransactionBuilder.ChangeOwner(owner.Address, newOwner.Address).DirectCalldata);

        (await chain.GetTransactionReceiptAsync(hash))!.Succeeded.Should().BeTrue();

        var resolved = await MethodFor(chain).ResolveAsync($"did:ethr:sepolia:{owner.Address}");
        resolved.ResolutionMetadata.Error.Should().BeNull();
        resolved.DidDocument!.VerificationMethod!
            .Single(v => v.Id.EndsWith("#controller"))
            .BlockchainAccountId!.ToLowerInvariant().Should().Contain(newOwner.Address[2..]);
    }

    [Fact]
    public async Task DirectChangeOwner_ByAStranger_RevertsAndChangesNothing()
    {
        var chain = new EmulatedEthereumChain(Registry);
        var owner = NewActor();
        var attacker = NewActor();

        var hash = await SendAsync(chain, attacker, Registry,
            Erc1056TransactionBuilder.ChangeOwner(owner.Address, attacker.Address).DirectCalldata);

        var receipt = (await chain.GetTransactionReceiptAsync(hash))!;
        receipt.Succeeded.Should().BeFalse("bad_actor must revert, not silently succeed");

        // The revert consumed the attacker's account nonce (like a real chain)…
        (await chain.GetTransactionCountAsync(attacker.Address)).Should().Be(1);
        // …and the identity still resolves to its implicit owner.
        var resolved = await MethodFor(chain).ResolveAsync($"did:ethr:sepolia:{owner.Address}");
        resolved.DidDocument!.VerificationMethod!
            .Single(v => v.Id.EndsWith("#controller"))
            .BlockchainAccountId!.ToLowerInvariant().Should().Contain(owner.Address[2..]);
    }

    [Fact]
    public async Task AddThenRevokeDelegate_AppearsThenDisappears()
    {
        var chain = new EmulatedEthereumChain(Registry);
        var owner = NewActor();
        var delegateActor = NewActor();
        var did = $"did:ethr:sepolia:{owner.Address}";
        var method = MethodFor(chain);

        await SendAsync(chain, owner, Registry, Erc1056TransactionBuilder
            .AddDelegate(owner.Address, "sigAuth", delegateActor.Address, validitySeconds: 86_400)
            .DirectCalldata);

        var afterAdd = await method.ResolveAsync(did);
        afterAdd.DidDocument!.VerificationMethod!.Should().HaveCount(2);
        afterAdd.DidDocument.Authentication!.Should().HaveCount(2);

        await SendAsync(chain, owner, Registry, Erc1056TransactionBuilder
            .RevokeDelegate(owner.Address, "sigAuth", delegateActor.Address)
            .DirectCalldata);

        var afterRevoke = await method.ResolveAsync(did);
        afterRevoke.DidDocument!.VerificationMethod!.Should().HaveCount(1,
            "a revoked delegate's validTo is the revocation block timestamp, which has passed");
    }

    [Fact]
    public async Task SetThenRevokeServiceAttribute_AppearsThenDisappears()
    {
        var chain = new EmulatedEthereumChain(Registry);
        var owner = NewActor();
        var did = $"did:ethr:sepolia:{owner.Address}";
        var method = MethodFor(chain);
        var endpoint = Encoding.UTF8.GetBytes("https://hub.example.com/messages");

        await SendAsync(chain, owner, Registry, Erc1056TransactionBuilder
            .SetAttribute(owner.Address, "did/svc/MessagingService", endpoint, 86_400)
            .DirectCalldata);

        var afterSet = await method.ResolveAsync(did);
        afterSet.DidDocument!.Service.Should().ContainSingle()
            .Which.Type.Should().Be("MessagingService");

        await SendAsync(chain, owner, Registry, Erc1056TransactionBuilder
            .RevokeAttribute(owner.Address, "did/svc/MessagingService", endpoint)
            .DirectCalldata);

        (await method.ResolveAsync(did)).DidDocument!.Service.Should().BeNull();
    }

    [Fact]
    public async Task VersionedResolution_AcrossWrites_PartitionsHistory()
    {
        var chain = new EmulatedEthereumChain(Registry);
        var owner = NewActor();
        var delegateActor = NewActor();
        var did = $"did:ethr:sepolia:{owner.Address}";
        var method = MethodFor(chain);

        await SendAsync(chain, owner, Registry, Erc1056TransactionBuilder
            .AddDelegate(owner.Address, "veriKey", delegateActor.Address, 86_400).DirectCalldata);
        var firstWriteBlock = chain.CurrentBlockNumber;
        await SendAsync(chain, owner, Registry, Erc1056TransactionBuilder
            .SetAttribute(owner.Address, "did/svc/Hub", Encoding.UTF8.GetBytes("https://hub"), 86_400)
            .DirectCalldata);

        var atFirst = await method.ResolveAsync(did,
            new DidEthrResolveOptions { VersionId = firstWriteBlock.ToString() });
        atFirst.DidDocument!.VerificationMethod!.Should().HaveCount(2);
        atFirst.DidDocument.Service.Should().BeNull();
        atFirst.DocumentMetadata!.NextVersionId.Should().Be((firstWriteBlock + 1).ToString());

        var latest = await method.ResolveAsync(did);
        latest.DidDocument!.Service.Should().ContainSingle();
        latest.DocumentMetadata!.VersionId.Should().Be((firstWriteBlock + 1).ToString());
    }

    [Fact]
    public async Task Issue117_MetadataTimestamps_MatchEmulatedBlockTimes()
    {
        // Differential pin for issue #117: updated/nextUpdate must equal the emulator's
        // actual block times — current resolution carries updated only; a historical
        // query carries nextUpdate beside nextVersionId in the reference resolver's
        // ISO 8601 UTC whole-second form.
        var chain = new EmulatedEthereumChain(Registry);
        var owner = NewActor();
        var delegateActor = NewActor();
        var did = $"did:ethr:sepolia:{owner.Address}";
        var method = MethodFor(chain);

        await SendAsync(chain, owner, Registry, Erc1056TransactionBuilder
            .AddDelegate(owner.Address, "veriKey", delegateActor.Address, 86_400).DirectCalldata);
        var firstWriteBlock = chain.CurrentBlockNumber;
        await SendAsync(chain, owner, Registry, Erc1056TransactionBuilder
            .SetAttribute(owner.Address, "did/svc/Hub", Encoding.UTF8.GetBytes("https://hub"), 86_400)
            .DirectCalldata);
        var secondWriteBlock = chain.CurrentBlockNumber;

        var firstTime = DateTimeOffset.FromUnixTimeSeconds(
            (long)await chain.GetBlockTimestampAsync(firstWriteBlock));
        var secondTime = DateTimeOffset.FromUnixTimeSeconds(
            (long)await chain.GetBlockTimestampAsync(secondWriteBlock));

        var historical = await method.ResolveAsync(did,
            new DidEthrResolveOptions { VersionId = firstWriteBlock.ToString() });
        historical.DocumentMetadata!.Updated.Should().Be(firstTime);
        historical.DocumentMetadata.NextUpdate.Should()
            .Be(secondTime.UtcDateTime.ToString(
                "yyyy'-'MM'-'dd'T'HH':'mm':'ss'Z'",
                System.Globalization.CultureInfo.InvariantCulture));

        var latest = await method.ResolveAsync(did);
        latest.DocumentMetadata!.Updated.Should().Be(secondTime);
        latest.DocumentMetadata.NextUpdate.Should().BeNull();
    }

    // ── Meta-transactions ────────────────────────────────────────────────────

    [Fact]
    public async Task MetaChangeOwner_SignedByOwner_SubmittedByRelayer_Succeeds()
    {
        var chain = new EmulatedEthereumChain(Registry);
        var owner = NewActor();
        var relayer = NewActor();
        var newOwner = NewActor();

        var op = Erc1056TransactionBuilder.ChangeOwner(owner.Address, newOwner.Address);
        var calldata = MetaCalldata(chain, owner, owner.Address, op, nonce: 0);

        var hash = await SendAsync(chain, relayer, Registry, calldata);

        (await chain.GetTransactionReceiptAsync(hash))!.Succeeded.Should().BeTrue();
        var resolved = await MethodFor(chain).ResolveAsync($"did:ethr:sepolia:{owner.Address}");
        resolved.DidDocument!.VerificationMethod!
            .Single(v => v.Id.EndsWith("#controller"))
            .BlockchainAccountId!.ToLowerInvariant().Should().Contain(newOwner.Address[2..]);

        // The contract meta-nonce advanced for the signer (modern generation).
        var nonceResult = await chain.CallAsync(
            Registry, Erc1056TransactionBuilder.NonceCalldata(owner.Address));
        Convert.ToUInt64(nonceResult[2..], 16).Should().Be(1);
    }

    [Fact]
    public async Task MetaTransaction_Replay_IsRejectedByTheNonce()
    {
        var chain = new EmulatedEthereumChain(Registry);
        var owner = NewActor();
        var relayer = NewActor();
        var delegateActor = NewActor();

        var op = Erc1056TransactionBuilder.AddDelegate(
            owner.Address, "sigAuth", delegateActor.Address, 86_400);
        var calldata = MetaCalldata(chain, owner, owner.Address, op, nonce: 0);

        (await chain.GetTransactionReceiptAsync(
            await SendAsync(chain, relayer, Registry, calldata)))!
            .Succeeded.Should().BeTrue();

        // Same signed payload again: the contract nonce moved, digest no longer matches.
        (await chain.GetTransactionReceiptAsync(
            await SendAsync(chain, relayer, Registry, calldata)))!
            .Succeeded.Should().BeFalse("replaying a meta-transaction must fail on the nonce");
    }

    [Fact]
    public async Task MetaTransaction_SignedByNonOwner_Reverts()
    {
        var chain = new EmulatedEthereumChain(Registry);
        var owner = NewActor();
        var attacker = NewActor();
        var relayer = NewActor();

        var op = Erc1056TransactionBuilder.ChangeOwner(owner.Address, attacker.Address);
        var calldata = MetaCalldata(chain, attacker, owner.Address, op, nonce: 0);

        (await chain.GetTransactionReceiptAsync(
            await SendAsync(chain, relayer, Registry, calldata)))!
            .Succeeded.Should().BeFalse("only the identity owner's signature authorizes a meta-tx");
    }

    [Fact]
    public async Task LegacyGeneration_AttributeMetaTx_ReadsTheIdentityNonce()
    {
        // Legacy quirk (v0.0.3): every meta-op increments nonce[identity]; attribute
        // preimages READ nonce[identity], owner/delegate preimages read nonce[owner].
        // After changeOwnerSigned, those diverge: nonce[identity] = 1, nonce[newOwner] = 0.
        var chain = new EmulatedEthereumChain(Registry, legacyNonce: true);
        var identity = NewActor();
        var newOwner = NewActor();
        var relayer = NewActor();
        var endpoint = Encoding.UTF8.GetBytes("https://legacy.example.com");

        var changeOwner = Erc1056TransactionBuilder.ChangeOwner(identity.Address, newOwner.Address);
        (await chain.GetTransactionReceiptAsync(await SendAsync(chain, relayer, Registry,
            MetaCalldata(chain, identity, identity.Address, changeOwner, nonce: 0))))!
            .Succeeded.Should().BeTrue();

        var setAttribute = Erc1056TransactionBuilder.SetAttribute(
            identity.Address, "did/svc/Hub", endpoint, 86_400);

        // The modern nonce choice (nonce[newOwner] = 0) must FAIL on a legacy registry…
        (await chain.GetTransactionReceiptAsync(await SendAsync(chain, relayer, Registry,
            MetaCalldata(chain, newOwner, identity.Address, setAttribute, nonce: 0))))!
            .Succeeded.Should().BeFalse("legacy attribute preimages read nonce[identity], not nonce[signer]");

        // …and the legacy choice (nonce[identity] = 1) must succeed.
        (await chain.GetTransactionReceiptAsync(await SendAsync(chain, relayer, Registry,
            MetaCalldata(chain, newOwner, identity.Address, setAttribute, nonce: 1))))!
            .Succeeded.Should().BeTrue();
    }

    [Fact]
    public async Task ModernGeneration_AttributeMetaTx_ReadsTheOwnerNonce()
    {
        var chain = new EmulatedEthereumChain(Registry, legacyNonce: false);
        var identity = NewActor();
        var newOwner = NewActor();
        var relayer = NewActor();

        var changeOwner = Erc1056TransactionBuilder.ChangeOwner(identity.Address, newOwner.Address);
        (await chain.GetTransactionReceiptAsync(await SendAsync(chain, relayer, Registry,
            MetaCalldata(chain, identity, identity.Address, changeOwner, nonce: 0))))!
            .Succeeded.Should().BeTrue();

        // Modern: nonce[identityOwner] = nonce[newOwner] = 0 (the increment went to the old signer).
        var setAttribute = Erc1056TransactionBuilder.SetAttribute(
            identity.Address, "did/svc/Hub", Encoding.UTF8.GetBytes("https://hub"), 86_400);
        (await chain.GetTransactionReceiptAsync(await SendAsync(chain, relayer, Registry,
            MetaCalldata(chain, newOwner, identity.Address, setAttribute, nonce: 0))))!
            .Succeeded.Should().BeTrue();
    }

    // ── Transaction validation (family-(c) hostile inputs) ───────────────────

    [Fact]
    public async Task WrongChainId_IsRejected()
    {
        var chain = new EmulatedEthereumChain(Registry, chainId: ChainId);
        var owner = NewActor();
        var tx = new EthereumTransaction
        {
            Nonce = 0, GasPrice = 1, GasLimit = 21_000,
            To = Registry, ChainId = 1, // mainnet-signed
        };
        var (signature, recoveryId) = Secp256k1Recoverable.Sign(owner.PrivateKey, tx.SigningDigest());

        await chain.Invoking(c => c.SendRawTransactionAsync(tx.EncodeSigned(signature, recoveryId)))
            .Should().ThrowAsync<EthereumInteractionException>().WithMessage("*chain*");
    }

    [Fact]
    public async Task ReusedAccountNonce_IsRejected()
    {
        var chain = new EmulatedEthereumChain(Registry);
        var owner = NewActor();
        var other = NewActor();

        await SendAsync(chain, owner, other.Address, "0x", nonce: 0);

        await chain.Invoking(async c =>
        {
            var tx = new EthereumTransaction
            {
                Nonce = 0, GasPrice = 1, GasLimit = 21_000, To = other.Address, ChainId = ChainId,
            };
            var (sig, recid) = Secp256k1Recoverable.Sign(owner.PrivateKey, tx.SigningDigest());
            await c.SendRawTransactionAsync(tx.EncodeSigned(sig, recid));
        }).Should().ThrowAsync<EthereumInteractionException>()
            .WithMessage("*does not match account nonce*");
    }

    [Fact]
    public async Task HighSSignature_IsRejected()
    {
        // Malleate a valid signature into its high-S twin: s' = n − s, flipped recovery id.
        // A structurally-valid-but-non-canonical input (fuzz family c) must be rejected.
        var curveOrder = BigInteger.Parse(
            "0FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
            System.Globalization.NumberStyles.HexNumber);
        var chain = new EmulatedEthereumChain(Registry);
        var owner = NewActor();
        var tx = new EthereumTransaction
        {
            Nonce = 0, GasPrice = 1, GasLimit = 21_000, To = Registry, ChainId = ChainId,
            Data = Convert.FromHexString(Erc1056TransactionBuilder
                .ChangeOwner(owner.Address, owner.Address).DirectCalldata[2..]),
        };
        var (signature, recoveryId) = Secp256k1Recoverable.Sign(owner.PrivateKey, tx.SigningDigest());

        var s = new BigInteger(signature[32..], isUnsigned: true, isBigEndian: true);
        var highS = curveOrder - s;
        var malleated = new byte[64];
        signature[..32].CopyTo(malleated, 0);
        var highSBytes = highS.ToByteArray(isUnsigned: true, isBigEndian: true);
        highSBytes.CopyTo(malleated, 64 - highSBytes.Length);

        // EncodeSigned now refuses to build the transaction at all — the malleable twin
        // never reaches the wire. (The emulator's own consensus check still backstops it;
        // see EncodeSigned_HighS_IsRejected for the library-level pin.)
        ((Action)(() => tx.EncodeSigned(malleated, recoveryId ^ 1)))
            .Should().Throw<ArgumentException>().WithMessage("*low-S*");
        await Task.CompletedTask;
    }

    [Fact]
    public async Task ValueTransfer_MovesBalances_AndRequiresFunds()
    {
        var chain = new EmulatedEthereumChain(Registry);
        var rich = NewActor();
        var poor = NewActor();
        chain.FundAccount(rich.Address, BigInteger.Pow(10, 18));

        await SendAsync(chain, rich, poor.Address, "0x", value: BigInteger.Pow(10, 17));

        chain.BalanceOf(poor.Address).Should().Be(BigInteger.Pow(10, 17));

        await chain.Invoking(async c =>
                await SendAsync(chain, poor, rich.Address, "0x", value: BigInteger.Pow(10, 18)))
            .Should().ThrowAsync<EthereumInteractionException>().WithMessage("*Insufficient funds*");
    }

    // ── Contract creation ────────────────────────────────────────────────────

    [Fact]
    public async Task RecognizedRegistryBytecode_DeploysToACreateAddress_AndServesCalls()
    {
        var chain = new EmulatedEthereumChain(Registry);
        var deployer = NewActor();
        var bytecode = Convert.FromHexString("60806040");
        chain.RecognizeDeployableRegistry(bytecode, legacyNonce: false);

        var hash = await SendAsync(chain, deployer, to: null,
            "0x" + Convert.ToHexString(bytecode).ToLowerInvariant());

        var receipt = (await chain.GetTransactionReceiptAsync(hash))!;
        receipt.Succeeded.Should().BeTrue();
        receipt.ContractAddress.Should().NotBeNull().And.HaveLength(42);

        // The fresh registry answers identityOwner with the implicit owner.
        var owner = await chain.CallAsync(
            receipt.ContractAddress!,
            Erc1056Calls.IdentityOwner(deployer.Address));
        owner.Should().EndWith(deployer.Address[2..]);
    }

    [Fact]
    public async Task UnrecognizedCreationBytecode_FailsTheDeployment()
    {
        var chain = new EmulatedEthereumChain(Registry);
        var deployer = NewActor();

        var hash = await SendAsync(chain, deployer, to: null, "0xdeadbeef");

        (await chain.GetTransactionReceiptAsync(hash))!.Succeeded.Should().BeFalse(
            "the emulator cannot execute arbitrary EVM bytecode and must say so, not pretend");
    }
}
