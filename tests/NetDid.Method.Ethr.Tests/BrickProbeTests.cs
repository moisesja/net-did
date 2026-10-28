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
        var op = Erc1056TransactionBuilder.SetAttribute(address, name, value, 86_400);
        var tx = new EthereumTransaction
        {
            Nonce    = await chain.GetTransactionCountAsync(address),
            GasPrice = 1_000_000_000,
            GasLimit = 100_000,
            To       = Registry,
            Data     = Convert.FromHexString(op.DirectCalldata[2..]),
            ChainId  = ChainId,
        };
        var (signature, recoveryId) = Secp256k1Recoverable.Sign(owner.PrivateKey, tx.SigningDigest());
        var hash = await chain.SendRawTransactionAsync(tx.EncodeSigned(signature, recoveryId));
        (await chain.GetTransactionReceiptAsync(hash))!.Succeeded.Should().BeTrue();
        return MethodFor(chain);
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
}
