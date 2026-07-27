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
/// The did:ethr Update/Deactivate write path (issue #107), driven through the emulator:
/// every transaction below is genuinely RLP-encoded, EIP-155-signed via the NetCrypto
/// <see cref="IRecoverableDigestSigner"/> seam, sender-recovered with real ecrecover, and
/// executed against the transcribed ERC-1056 semantics. The negative-state matrix was
/// designed before the implementation (tasks/lessons.md).
/// </summary>
public class DidEthrWriteTests
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

    private static EthereumNetworkConfig Network(bool legacyNonce = false)
        => KnownNetworks.Sepolia with { RpcUrl = "http://emulated.local", LegacyNonce = legacyNonce };

    private static DidEthrMethod MethodFor(IEthereumRpcClient client, bool legacyNonce = false)
        => new(new SingleNetworkRpcFactory("sepolia", client), [Network(legacyNonce)],
            new DefaultKeyGenerator());

    // ── Update: direct path ──────────────────────────────────────────────────

    [Fact]
    public async Task Update_AddServiceAndDelegate_LandsOnChainAndResolves()
    {
        var chain = new EmulatedEthereumChain(Registry);
        var owner = NewActor();
        var delegateActor = NewActor();
        var method = MethodFor(chain);
        var did = $"did:ethr:sepolia:{owner.Address}";

        var result = await method.UpdateAsync(did, new DidEthrUpdateOptions
        {
            ControllerKey = owner.Signer,
            AddServices   =
            [
                new DidEthrServiceAttribute
                {
                    ServiceType     = "MessagingService",
                    ServiceEndpoint = "https://hub.example.com/messages",
                },
            ],
            AddDelegates =
            [
                new DidEthrDelegate
                {
                    DelegateType    = "sigAuth",
                    DelegateAddress = delegateActor.Address,
                    Validity        = TimeSpan.FromDays(30),
                },
            ],
        });

        result.DidDocument.VerificationMethod!.Should().HaveCount(2);
        result.DidDocument.Service.Should().ContainSingle()
            .Which.Type.Should().Be("MessagingService");
        result.AuthorizationChange.Should().Be(AuthorizationChangeStatus.Unchanged,
            "delegates and services never gain did:ethr update authority");
        result.UpdateKeyChange.Should().Be(AuthorizationChangeStatus.Unchanged);
        result.RevealedUpdateKeys.Should().Equal(owner.Address);
        result.EffectiveUpdateKeys.Should().Equal(owner.Address);

        var hashes = (IReadOnlyList<string>)result.Artifacts!["transactions"];
        hashes.Should().HaveCount(2);
        foreach (var hash in hashes)
            (await chain.GetTransactionReceiptAsync(hash))!.Succeeded.Should().BeTrue();

        // The write is on-chain, not just in the returned document.
        (await method.ResolveAsync(did)).DidDocument!.Service.Should().ContainSingle();
    }

    [Fact]
    public async Task Update_RemoveServiceAndRevokeDelegate_DropThemFromTheDocument()
    {
        var chain = new EmulatedEthereumChain(Registry);
        var owner = NewActor();
        var delegateActor = NewActor();
        var method = MethodFor(chain);
        var did = $"did:ethr:sepolia:{owner.Address}";
        var service = new DidEthrServiceAttribute
        {
            ServiceType     = "MessagingService",
            ServiceEndpoint = "https://hub.example.com/messages",
        };

        await method.UpdateAsync(did, new DidEthrUpdateOptions
        {
            ControllerKey = owner.Signer,
            AddServices   = [service],
            AddDelegates  =
            [
                new DidEthrDelegate
                {
                    DelegateType = "veriKey", DelegateAddress = delegateActor.Address,
                    Validity = TimeSpan.FromDays(30),
                },
            ],
        });

        var result = await method.UpdateAsync(did, new DidEthrUpdateOptions
        {
            ControllerKey   = owner.Signer,
            RemoveServices  = [service],
            RevokeDelegates =
            [
                // Validity is irrelevant for a revocation and stays at its default.
                new DidEthrDelegate { DelegateType = "veriKey", DelegateAddress = delegateActor.Address },
            ],
        });

        result.DidDocument.Service.Should().BeNull();
        result.DidDocument.VerificationMethod!.Should().HaveCount(1);
    }

    [Fact]
    public async Task Update_ChangeOwner_RunsLast_AndReportsTheNewAuthority()
    {
        var chain = new EmulatedEthereumChain(Registry);
        var owner = NewActor();
        var newOwner = NewActor();
        var delegateActor = NewActor();
        var method = MethodFor(chain);
        var did = $"did:ethr:sepolia:{owner.Address}";

        var result = await method.UpdateAsync(did, new DidEthrUpdateOptions
        {
            ControllerKey   = owner.Signer,
            NewOwnerAddress = newOwner.Address,
            AddDelegates    =
            [
                new DidEthrDelegate
                {
                    DelegateType = "sigAuth", DelegateAddress = delegateActor.Address,
                    Validity = TimeSpan.FromDays(30),
                },
            ],
        });

        // Both landed — possible only because the owner change was submitted LAST
        // (the old key loses authority the moment changeOwner executes).
        result.DidDocument.VerificationMethod!.Should().HaveCount(2);
        result.DidDocument.VerificationMethod!
            .Single(v => v.Id.EndsWith("#controller"))
            .BlockchainAccountId!.ToLowerInvariant().Should().Contain(newOwner.Address[2..]);
        result.AuthorizationChange.Should().Be(AuthorizationChangeStatus.Changed);
        result.UpdateKeyChange.Should().Be(AuthorizationChangeStatus.Changed);
        result.RevealedUpdateKeys.Should().Equal(owner.Address);
        result.EffectiveUpdateKeys.Should().Equal(newOwner.Address);

        // The old key has genuinely lost update authority.
        await method.Invoking(m => m.UpdateAsync(did, new DidEthrUpdateOptions
            {
                ControllerKey = owner.Signer,
                AddServices   =
                [
                    new DidEthrServiceAttribute
                    {
                        ServiceType = "X", ServiceEndpoint = "https://x.example",
                    },
                ],
            }))
            .Should().ThrowAsync<EthereumInteractionException>()
            .WithMessage("*is not the current owner*");
    }

    [Fact]
    public async Task Update_RawAttribute_PublishesFullKeyMaterial()
    {
        // The did/pub/… attribute path (PRD §8.5): unlike the implicit
        // blockchainAccountId VM, this publishes extractable key bytes.
        var chain = new EmulatedEthereumChain(Registry);
        var owner = NewActor();
        using var edKey = new DefaultKeyGenerator().Generate(KeyType.Ed25519);
        var method = MethodFor(chain);
        var did = $"did:ethr:sepolia:{owner.Address}";
        var attribute = new DidEthrAttribute
        {
            Name  = "did/pub/Ed25519/veriKey/base64",
            Value = edKey.PublicKey,
        };

        var result = await method.UpdateAsync(did, new DidEthrUpdateOptions
        {
            ControllerKey = owner.Signer,
            AddAttributes = [attribute],
        });

        var vm = result.DidDocument.VerificationMethod!.Should().HaveCount(2).And.Subject
            .Single(v => v.Type == "Ed25519VerificationKey2020");
        vm.PublicKeyMultibase.Should().NotBeNull();

        var removed = await method.UpdateAsync(did, new DidEthrUpdateOptions
        {
            ControllerKey    = owner.Signer,
            RemoveAttributes = [attribute],
        });
        removed.DidDocument.VerificationMethod!.Should().HaveCount(1);
    }

    // ── Update: meta-transaction path ────────────────────────────────────────

    [Fact]
    public async Task Update_MetaTransaction_RelayerPays_ControllerNeverFunded()
    {
        var chain = new EmulatedEthereumChain(Registry);
        var owner = NewActor();
        var relayer = NewActor();
        var method = MethodFor(chain);
        var did = $"did:ethr:sepolia:{owner.Address}";

        var result = await method.UpdateAsync(did, new DidEthrUpdateOptions
        {
            ControllerKey      = owner.Signer,
            UseMetaTransaction = true,
            Relayer            = relayer.Signer,
            AddServices        =
            [
                new DidEthrServiceAttribute
                {
                    ServiceType = "Hub", ServiceEndpoint = "https://hub.example",
                },
            ],
        });

        result.DidDocument.Service.Should().ContainSingle();

        // The relayer's account carried the transaction; the controller's did nothing.
        (await chain.GetTransactionCountAsync(relayer.Address)).Should().Be(1);
        (await chain.GetTransactionCountAsync(owner.Address)).Should().Be(0);

        // And the contract meta-nonce advanced for the controller (modern generation).
        var nonceWord = await chain.CallAsync(
            Registry, Erc1056TransactionBuilder.NonceCalldata(owner.Address));
        Convert.ToUInt64(nonceWord[2..], 16).Should().Be(1);
    }

    [Fact]
    public async Task Update_MetaTransaction_OnLegacyChain_UsesTheIdentityNonceForAttributes()
    {
        var chain = new EmulatedEthereumChain(Registry, legacyNonce: true);
        var identity = NewActor();
        var newOwner = NewActor();
        var relayer = NewActor();
        var method = MethodFor(chain, legacyNonce: true);
        var did = $"did:ethr:sepolia:{identity.Address}";

        // Meta owner change while owner == identity: nonce[identity] 0 → 1 on this generation.
        await method.UpdateAsync(did, new DidEthrUpdateOptions
        {
            ControllerKey      = identity.Signer,
            UseMetaTransaction = true,
            Relayer            = relayer.Signer,
            NewOwnerAddress    = newOwner.Address,
        });

        // Meta ATTRIBUTE op signed by the NEW owner. On the legacy generation the preimage
        // must be built over nonce[identity] (= 1), not nonce[signer] (= 0); the emulator's
        // transcribed contract enforces exactly that, so success proves the right nonce key.
        // Attribute ops stay single-use here because the slot they read is the slot
        // checkSignature increments.
        var result = await method.UpdateAsync(did, new DidEthrUpdateOptions
        {
            ControllerKey      = newOwner.Signer,
            UseMetaTransaction = true,
            Relayer            = relayer.Signer,
            AddServices        =
            [
                new DidEthrServiceAttribute
                {
                    ServiceType = "Hub", ServiceEndpoint = "https://legacy.example",
                },
            ],
        });

        result.DidDocument.Service.Should().ContainSingle();
    }

    [Fact]
    public async Task Update_MetaTransaction_OnLegacyChain_RefusesOwnerAndDelegateOpsAfterATransfer()
    {
        // The legacy registry increments nonce[identity] but its changeOwner/addDelegate/
        // revokeDelegate preimages READ nonce[identityOwner]. Once those diverge the preimage
        // nonce never moves, so the signed calldata replays FOREVER — demonstrated against
        // real v0.0.3 bytecode. Refuse to mint such a signature.
        var chain = new EmulatedEthereumChain(Registry, legacyNonce: true);
        var identity = NewActor();
        var newOwner = NewActor();
        var relayer = NewActor();
        var delegateActor = NewActor();
        var method = MethodFor(chain, legacyNonce: true);
        var did = $"did:ethr:sepolia:{identity.Address}";

        await method.UpdateAsync(did, new DidEthrUpdateOptions
        {
            ControllerKey      = identity.Signer,
            UseMetaTransaction = true,
            Relayer            = relayer.Signer,
            NewOwnerAddress    = newOwner.Address,
        });

        await method.Invoking(m => m.UpdateAsync(did, new DidEthrUpdateOptions
            {
                ControllerKey      = newOwner.Signer,
                UseMetaTransaction = true,
                Relayer            = relayer.Signer,
                AddDelegates       =
                [
                    new DidEthrDelegate
                    {
                        DelegateType = "sigAuth", DelegateAddress = delegateActor.Address,
                        Validity = TimeSpan.FromMinutes(1),
                    },
                ],
            }))
            .Should().ThrowAsync<EthereumInteractionException>()
            .WithMessage("*replayable indefinitely*");

        // The same operation submitted DIRECTLY is unaffected — no signature to replay.
        var direct = await method.UpdateAsync(did, new DidEthrUpdateOptions
        {
            ControllerKey = newOwner.Signer,
            AddDelegates  =
            [
                new DidEthrDelegate
                {
                    DelegateType = "sigAuth", DelegateAddress = delegateActor.Address,
                    Validity = TimeSpan.FromDays(1),
                },
            ],
        });
        direct.DidDocument.VerificationMethod!.Should().HaveCount(2);
    }

    // ── Deactivate ───────────────────────────────────────────────────────────

    [Fact]
    public async Task Deactivate_Direct_ResolvesAsDeactivated()
    {
        var chain = new EmulatedEthereumChain(Registry);
        var owner = NewActor();
        var method = MethodFor(chain);
        var did = $"did:ethr:sepolia:{owner.Address}";

        var result = await method.DeactivateAsync(did, new DidEthrDeactivateOptions
        {
            ControllerKey = owner.Signer,
        });

        result.Success.Should().BeTrue();
        ((IReadOnlyList<string>)result.Artifacts!["transactions"]).Should().HaveCount(1);

        var resolved = await method.ResolveAsync(did);
        resolved.DocumentMetadata!.Deactivated.Should().BeTrue();
        resolved.DidDocument!.VerificationMethod.Should().BeNull("the document is stripped");
    }

    [Fact]
    public async Task Deactivate_MetaTransaction_ViaRelayer()
    {
        var chain = new EmulatedEthereumChain(Registry);
        var owner = NewActor();
        var relayer = NewActor();
        var method = MethodFor(chain);
        var did = $"did:ethr:sepolia:{owner.Address}";

        var result = await method.DeactivateAsync(did, new DidEthrDeactivateOptions
        {
            ControllerKey      = owner.Signer,
            UseMetaTransaction = true,
            Relayer            = relayer.Signer,
        });

        result.Success.Should().BeTrue();
        (await method.ResolveAsync(did)).DocumentMetadata!.Deactivated.Should().BeTrue();
    }

    // ── Negative matrix ──────────────────────────────────────────────────────

    [Fact]
    public async Task Update_WithNoOperations_ThrowsBeforeAnyRpc()
    {
        var chain = new EmulatedEthereumChain(Registry);
        var owner = NewActor();

        await MethodFor(chain)
            .Invoking(m => m.UpdateAsync($"did:ethr:sepolia:{owner.Address}",
                new DidEthrUpdateOptions { ControllerKey = owner.Signer }))
            .Should().ThrowAsync<ArgumentException>()
            .WithMessage("*at least one operation*");

        chain.CurrentBlockNumber.Should().Be(0, "nothing may be broadcast");
    }

    [Fact]
    public async Task Update_ByNonOwner_FailsPreFlight_BroadcastingNothing()
    {
        var chain = new EmulatedEthereumChain(Registry);
        var owner = NewActor();
        var attacker = NewActor();

        await MethodFor(chain)
            .Invoking(m => m.UpdateAsync($"did:ethr:sepolia:{owner.Address}",
                new DidEthrUpdateOptions
                {
                    ControllerKey = attacker.Signer,
                    AddServices   =
                    [
                        new DidEthrServiceAttribute
                        {
                            ServiceType = "X", ServiceEndpoint = "https://x.example",
                        },
                    ],
                }))
            .Should().ThrowAsync<EthereumInteractionException>()
            .WithMessage("*is not the current owner*");

        chain.CurrentBlockNumber.Should().Be(0, "the pre-flight must fail before any broadcast");
        (await chain.GetTransactionCountAsync(attacker.Address)).Should().Be(0);
    }

    [Fact]
    public async Task Update_MetaTransactionWithoutRelayer_Throws()
    {
        var chain = new EmulatedEthereumChain(Registry);
        var owner = NewActor();

        await MethodFor(chain)
            .Invoking(m => m.UpdateAsync($"did:ethr:sepolia:{owner.Address}",
                new DidEthrUpdateOptions
                {
                    ControllerKey      = owner.Signer,
                    UseMetaTransaction = true,
                    AddServices        =
                    [
                        new DidEthrServiceAttribute
                        {
                            ServiceType = "X", ServiceEndpoint = "https://x.example",
                        },
                    ],
                }))
            .Should().ThrowAsync<ArgumentException>()
            .WithMessage("*Relayer*");
    }

    [Fact]
    public async Task Update_WithNonSecp256k1Key_Throws()
    {
        var chain = new EmulatedEthereumChain(Registry);
        var owner = NewActor();
        using var edKey = new DefaultKeyGenerator().Generate(KeyType.Ed25519);
        using var edSigner = new KeyPairSigner(edKey, new DefaultCryptoProvider());

        await MethodFor(chain)
            .Invoking(m => m.UpdateAsync($"did:ethr:sepolia:{owner.Address}",
                new DidEthrUpdateOptions
                {
                    ControllerKey = edSigner,
                    AddServices   =
                    [
                        new DidEthrServiceAttribute
                        {
                            ServiceType = "X", ServiceEndpoint = "https://x.example",
                        },
                    ],
                }))
            .Should().ThrowAsync<ArgumentException>()
            .WithMessage("*Secp256k1*");
    }

    [Fact]
    public async Task Update_WithNonPositiveValidity_ThrowsBeforeAnyRpc()
    {
        var chain = new EmulatedEthereumChain(Registry);
        var owner = NewActor();

        await MethodFor(chain)
            .Invoking(m => m.UpdateAsync($"did:ethr:sepolia:{owner.Address}",
                new DidEthrUpdateOptions
                {
                    ControllerKey = owner.Signer,
                    AddDelegates  =
                    [
                        new DidEthrDelegate
                        {
                            DelegateType = "sigAuth", DelegateAddress = owner.Address,
                            Validity = TimeSpan.Zero,
                        },
                    ],
                }))
            .Should().ThrowAsync<ArgumentException>()
            .WithMessage("*Validity must be positive*");

        chain.CurrentBlockNumber.Should().Be(0);
    }

    [Fact]
    public async Task Update_MidBatchRevert_ReportsLandedOperations()
    {
        // Hostile world change between operations: after the first transaction lands,
        // the owner is hijacked out-of-band, so the second reverts. The failure must
        // name what landed and what did not — no silent partial success.
        var chain = new EmulatedEthereumChain(Registry);
        var owner = NewActor();
        var attacker = NewActor();
        var delegateActor = NewActor();
        var did = $"did:ethr:sepolia:{owner.Address}";

        var sends = 0;
        var hijacking = new InterceptingRpcClient(chain)
        {
            BeforeSendRawTransaction = async () =>
            {
                if (++sends == 2)
                {
                    // The "world" moves the identity to the attacker between our txs
                    // (signed by the still-current owner, exactly like a racing wallet).
                    await SendDirectAsync(chain, owner,
                        Erc1056TransactionBuilder.ChangeOwner(owner.Address, attacker.Address)
                            .DirectCalldata);
                }
            },
        };

        var act = () => MethodFor(hijacking).UpdateAsync(did, new DidEthrUpdateOptions
        {
            ControllerKey = owner.Signer,
            AddServices   =
            [
                new DidEthrServiceAttribute
                {
                    ServiceType = "Hub", ServiceEndpoint = "https://hub.example",
                },
            ],
            AddDelegates =
            [
                new DidEthrDelegate
                {
                    DelegateType = "sigAuth", DelegateAddress = delegateActor.Address,
                    Validity = TimeSpan.FromDays(1),
                },
            ],
        });

        (await act.Should().ThrowAsync<EthereumInteractionException>())
            .WithMessage("*after landing 1 of 2 operations*");
    }

    [Fact]
    public async Task Update_ReceiptNeverArrives_FailsOnTheWriteDeadline()
    {
        var chain = new EmulatedEthereumChain(Registry);
        var owner = NewActor();
        var blackHole = new InterceptingRpcClient(chain) { SwallowReceipts = true };
        var method = MethodFor(blackHole);
        method.WriteDeadline = TimeSpan.FromSeconds(2);

        var act = () => method.UpdateAsync($"did:ethr:sepolia:{owner.Address}",
            new DidEthrUpdateOptions
            {
                ControllerKey = owner.Signer,
                AddServices   =
                [
                    new DidEthrServiceAttribute
                    {
                        ServiceType = "X", ServiceEndpoint = "https://x.example",
                    },
                ],
            });

        (await act.Should().ThrowAsync<EthereumInteractionException>())
            .WithMessage("*write deadline*may still confirm later*");
    }

    [Fact]
    public async Task Update_CallerCancellation_PropagatesAsCancellation()
    {
        var chain = new EmulatedEthereumChain(Registry);
        var owner = NewActor();
        var blackHole = new InterceptingRpcClient(chain) { SwallowReceipts = true };
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(600));

        await MethodFor(blackHole)
            .Invoking(m => m.UpdateAsync($"did:ethr:sepolia:{owner.Address}",
                new DidEthrUpdateOptions
                {
                    ControllerKey = owner.Signer,
                    AddServices   =
                    [
                        new DidEthrServiceAttribute
                        {
                            ServiceType = "X", ServiceEndpoint = "https://x.example",
                        },
                    ],
                }, cts.Token))
            .Should().ThrowAsync<OperationCanceledException>();
    }

    // ── DeployAsync against the emulator ─────────────────────────────────────

    [Fact]
    public async Task DeployAsync_OnARecognizingChain_YieldsAWorkingRegistry()
    {
        var chain = new EmulatedEthereumChain(Registry);
        chain.RecognizeDeployableRegistry(
            Erc1056Registry.ModernCreationBytecode.ToArray(), legacyNonce: false);
        var deployer = NewActor();

        var deployed = await Erc1056Registry.DeployAsync(chain, deployer.Signer, chainId: 11155111);

        deployed.Should().StartWith("0x").And.HaveLength(42);
        var owner = await chain.CallAsync(deployed, Erc1056Calls.IdentityOwner(deployer.Address));
        owner.Should().EndWith(deployer.Address[2..]);
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

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
            ChainId  = 11155111,
        };
        var signature = await sender.Signer.SignDigestAsync(tx.SigningDigest());
        await chain.SendRawTransactionAsync(
            tx.EncodeSigned(signature.Signature64, signature.RecoveryId));
    }

    /// <summary>Pass-through RPC decorator with hostile hooks for failure-mode tests.</summary>
    private sealed class InterceptingRpcClient(EmulatedEthereumChain inner) : IEthereumRpcClient
    {
        public Func<Task>? BeforeSendRawTransaction { get; init; }
        public bool SwallowReceipts { get; init; }

        public Task<string> CallAsync(string to, string data, CancellationToken ct = default)
            => inner.CallAsync(to, data, ct);
        public Task<IReadOnlyList<EthereumLogEntry>> GetLogsAsync(EthereumLogFilter filter, CancellationToken ct = default)
            => inner.GetLogsAsync(filter, ct);
        public Task<ulong> GetBlockNumberAsync(CancellationToken ct = default)
            => inner.GetBlockNumberAsync(ct);
        public Task<ulong> GetChainIdAsync(CancellationToken ct = default)
            => inner.GetChainIdAsync(ct);
        public Task<ulong> GetBlockTimestampAsync(ulong blockNumber, CancellationToken ct = default)
            => inner.GetBlockTimestampAsync(blockNumber, ct);
        public Task<ulong> GetTransactionCountAsync(string address, CancellationToken ct = default)
            => inner.GetTransactionCountAsync(address, ct);
        public Task<ulong> GetGasPriceAsync(CancellationToken ct = default)
            => inner.GetGasPriceAsync(ct);
        public Task<ulong> EstimateGasAsync(string from, string? to, string data, CancellationToken ct = default)
            => inner.EstimateGasAsync(from, to, data, ct);

        public async Task<string> SendRawTransactionAsync(byte[] signedTransaction, CancellationToken ct = default)
        {
            if (BeforeSendRawTransaction is not null)
                await BeforeSendRawTransaction();
            return await inner.SendRawTransactionAsync(signedTransaction, ct);
        }

        public Task<EthereumTransactionReceipt?> GetTransactionReceiptAsync(string transactionHash, CancellationToken ct = default)
            => SwallowReceipts
                ? Task.FromResult<EthereumTransactionReceipt?>(null)
                : inner.GetTransactionReceiptAsync(transactionHash, ct);
    }
}
