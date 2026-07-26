using FluentAssertions;
using NetCrypto;
using NetDid.Method.Ethr;
using NetDid.Method.Ethr.Crypto;
using NetDid.Method.Ethr.Deployment;
using NetDid.Method.Ethr.Erc1056;
using NetDid.Method.Ethr.Rpc;
using Xunit;

namespace NetDid.Method.Ethr.IntegrationTests;

[Collection("anvil")]
public class DeactivationRealityTests(AnvilFixture anvil)
{
    [EthrIntegrationFact]
    public async Task ZeroOwner_ReturnsControlToAnEoaIdentity_OnRealBytecode()
    {
        var crypto = new DefaultCryptoProvider();
        var keyGen = new DefaultKeyGenerator();
        using var funderPair = keyGen.FromPrivateKey(KeyType.Secp256k1, AnvilFixture.FunderKey);
        using var funder = new KeyPairSigner(funderPair, crypto, ownsKeyPair: false);

        var registry = await Erc1056Registry.DeployAsync(anvil.Client, funder);
        var identityAddress = EthereumAddress.FromCompressedPublicKey(funderPair.PublicKey).ToLowerInvariant();

        var network = new EthereumNetworkConfig
        {
            Name = "anvil", RpcUrl = anvil.RpcUrl, ChainId = "0x7a69", RegistryAddress = registry,
        };
        var method = new DidEthrMethod(
            DefaultEthereumRpcClientFactory.CreateDirect([network]), [network], keyGen);
        var did = $"did:ethr:anvil:{identityAddress}";

        var deactivated = await method.DeactivateAsync(did,
            new DidEthrDeactivateOptions { ControllerKey = funder });
        deactivated.Success.Should().BeTrue();
        (await method.ResolveAsync(did)).DocumentMetadata!.Deactivated.Should().BeTrue();

        // THE CLAIM UNDER TEST: is the identity now permanently uncontrollable?
        var ownerAfter = await anvil.Client.CallAsync(
            registry, Erc1056Calls.IdentityOwner(identityAddress));
        var ownerAddress = "0x" + ownerAfter[^40..];

        // The contract's identityOwner() is `owner != 0 ? owner : identity` — zeroing the
        // owner slot hands control BACK to the identity address itself.
        ownerAddress.Should().Be(identityAddress,
            "the deployed registry returns the identity when the owner slot is zero");

        // …so the identity key can write again, and even un-deactivate the DID.
        var resurrected = await method.UpdateAsync(did, new DidEthrUpdateOptions
        {
            ControllerKey   = funder,
            NewOwnerAddress = identityAddress,
        });
        resurrected.Should().NotBeNull();
        (await method.ResolveAsync(did)).DocumentMetadata!.Deactivated
            .Should().NotBe(true, "the DID is no longer deactivated");
    }
}
