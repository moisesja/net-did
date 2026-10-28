using AwesomeAssertions;
using NetCrypto;
using NetDid.Method.Ethr.Crypto;
using NetDid.Method.Ethr.Emulator;
using NetDid.Method.Ethr.Erc1056;
using NetDid.Method.Ethr.Rpc;
using NetDid.Method.Ethr.Transactions;
using Xunit;

namespace NetDid.Method.Ethr.Tests;

/// <summary>
/// A single Update must never make a DID permanently unresolvable. The key-material path
/// was fixed once (RedTeamWritePathTests.B1); this sweeps the OTHER values that reach the
/// document builder from an attribute — service endpoints, non-UTF-8 bytes, and every
/// remaining <c>did/pub</c> algorithm — because a partial fix here is indistinguishable
/// from a working one until the exact untested input shows up on-chain. Values NetDid refuses
/// to publish are written straight to the registry, as any other ERC-1056 tool could (issue #145).
/// </summary>
public class BrickProbeTests
{
    private const string Registry = "0x03d5003bf0e79c5f5223588f347eba39afbc3818";

    private const ulong ChainId = 11155111;

    private static (KeyPairSigner Signer, string Address) NewActor()
    {
        var pair = new DefaultKeyGenerator().Generate(KeyType.Secp256k1);
        return (new KeyPairSigner(pair, new DefaultCryptoProvider()),
                EthereumAddress.FromCompressedPublicKey(pair.PublicKey).ToLowerInvariant());
    }

    private static (KeyPair Key, string Address) NewRawActor()
    {
        var pair = new DefaultKeyGenerator().Generate(KeyType.Secp256k1);
        return (pair, EthereumAddress.FromCompressedPublicKey(pair.PublicKey).ToLowerInvariant());
    }

    private static DidEthrMethod MethodFor(IEthereumRpcClient client)
        => new(new SingleNetworkRpcFactory("sepolia", client),
               [KnownNetworks.Sepolia with { RpcUrl = "http://emulated.local" }],
               new DefaultKeyGenerator());

    private static async Task<DidEthrMethod> WriteAttributeAsync(
        EmulatedEthereumChain chain, KeyPairSigner signer, string did, string name, byte[] value)
    {
        var method = MethodFor(chain);
        await method.UpdateAsync(did, new DidEthrUpdateOptions
        {
            ControllerKey = signer,
            AddAttributes = [new DidEthrAttribute { Name = name, Value = value }],
        });
        return method;
    }

    // A direct setAttribute from the identity's owner, bypassing NetDid's Update validation.
    private static async Task<DidEthrMethod> PublishRawAttributeAsync(
        EmulatedEthereumChain chain, KeyPair owner, string address, string name, byte[] value)
    {
        await SendCalldataAsync(chain, owner, address,
            Erc1056TransactionBuilder.SetAttribute(address, name, value, 86_400).DirectCalldata);
        return MethodFor(chain);
    }

    private static async Task SendCalldataAsync(
        EmulatedEthereumChain chain, KeyPair owner, string address, string calldata)
    {
        var tx = new EthereumTransaction
        {
            Nonce    = await chain.GetTransactionCountAsync(address),
            GasPrice = 1_000_000_000,
            GasLimit = 100_000,
            To       = Registry,
            Data     = Convert.FromHexString(calldata[2..]),
            ChainId  = ChainId,
        };
        var (signature, recoveryId) = Secp256k1Recoverable.Sign(owner.PrivateKey, tx.SigningDigest());
        var hash = await chain.SendRawTransactionAsync(tx.EncodeSigned(signature, recoveryId));
        (await chain.GetTransactionReceiptAsync(hash))!.Succeeded.Should().BeTrue();
    }

    // Replaces the bytes32 label in the calldata with the same label whose byte at `index` is
    // 0xFF, which is never valid UTF-8 (another ERC-1056 tool can write any bytes32).
    private static string WithInvalidUtf8Label(string calldata, string label, int index)
    {
        var bytes = System.Text.Encoding.ASCII.GetBytes(label);
        var original = Convert.ToHexString(bytes).ToLowerInvariant();
        bytes[index] = 0xff;
        calldata.Should().Contain(original);
        return calldata.Replace(original, Convert.ToHexString(bytes).ToLowerInvariant());
    }

    [Theory]
    [InlineData("")]                    // empty endpoint
    [InlineData("   ")]                 // whitespace only
    [InlineData("not a uri at all")]    // unparseable
    [InlineData("http://[bad")]         // malformed authority
    public async Task ServiceEndpoint_Malformed_DoesNotBrickTheDid(string endpoint)
    {
        var chain = new EmulatedEthereumChain(Registry);
        var (owner, address) = NewRawActor();
        var did = $"did:ethr:sepolia:{address}";

        var method = await PublishRawAttributeAsync(
            chain, owner, address, "did/svc/Hub", System.Text.Encoding.UTF8.GetBytes(endpoint));

        var resolved = await method.ResolveAsync(did);
        resolved.ResolutionMetadata.Error.Should().BeNull(
            $"a malformed service endpoint ('{endpoint}') must not erase the DID");
        resolved.DidDocument.Should().NotBeNull();
    }

    [Fact]
    public async Task ServiceEndpoint_NonUtf8Bytes_DoesNotBrickTheDid()
    {
        var chain = new EmulatedEthereumChain(Registry);
        var (owner, address) = NewRawActor();
        var did = $"did:ethr:sepolia:{address}";

        var method = await PublishRawAttributeAsync(
            chain, owner, address, "did/svc/Hub", [0xff, 0xfe, 0xfd]);

        (await method.ResolveAsync(did)).ResolutionMetadata.Error.Should().BeNull();
    }

    [Theory]
    [InlineData("did/pub/Ed25519/veriKey/base64")]
    [InlineData("did/pub/X25519/enc/base64")]
    [InlineData("did/pub/Multikey/veriKey/base64")]
    [InlineData("did/pub/Secp256k1/veriKey/hex")]
    public async Task EveryPubAlgorithm_WithAnUndecodableValue_DoesNotBrickTheDid(string name)
    {
        var chain = new EmulatedEthereumChain(Registry);
        var (signer, address) = NewActor();
        var did = $"did:ethr:sepolia:{address}";

        var method = await WriteAttributeAsync(chain, signer, did, name, [1]);

        var resolved = await method.ResolveAsync(did);
        resolved.ResolutionMetadata.Error.Should().BeNull($"'{name}' with a 1-byte value");
        resolved.DidDocument.Should().NotBeNull();
    }

    // Adversarial pass on the final pass (F3): ethr-did-resolver decodes bytes32 names and
    // delegate types as strict UTF-8 and filters out an event it cannot decode: the event is
    // not counted, changes nothing, and does not move versionId (its previousChange still links
    // the history). NetDid decoded such labels as ASCII ('?') and counted them.
    [Fact]
    public async Task Issue145_UndecodableLabels_AreFilteredOutOfTheHistory()
    {
        var chain = new EmulatedEthereumChain(Registry);
        var (owner, address) = NewRawActor();
        var (_, delegateAddress) = NewRawActor();
        var did = $"did:ethr:sepolia:{address}";
        var endpoint = System.Text.Encoding.UTF8.GetBytes("https://hub.example");
        var addDelegate = Erc1056TransactionBuilder.AddDelegate(address, "veriKey", delegateAddress, 86_400).DirectCalldata;
        var setService = Erc1056TransactionBuilder.SetAttribute(address, "did/svc/Hub", endpoint, 86_400).DirectCalldata;

        await SendCalldataAsync(chain, owner, address, WithInvalidUtf8Label(addDelegate, "veriKey", 2));
        await SendCalldataAsync(chain, owner, address, WithInvalidUtf8Label(setService, "did/svc/Hub", 9));
        await SendCalldataAsync(chain, owner, address, addDelegate);
        await SendCalldataAsync(chain, owner, address, setService);
        var method = MethodFor(chain);
        var before = await method.ResolveAsync(did);
        await SendCalldataAsync(chain, owner, address, WithInvalidUtf8Label(setService, "did/svc/Hub", 9));
        var after = await method.ResolveAsync(did);

        after.ResolutionMetadata.Error.Should().BeNull();
        after.DidDocument!.Service.Should().ContainSingle().Which.Id.Should().Be(did + "#service-1");
        after.DidDocument.VerificationMethod!.Select(vm => vm.Id).Should().Contain(did + "#delegate-1")
            .And.NotContain(did + "#delegate-2");
        after.DocumentMetadata!.VersionId.Should().Be(before.DocumentMetadata!.VersionId);
        after.DocumentMetadata.Updated.Should().Be(before.DocumentMetadata.Updated);
    }
}
