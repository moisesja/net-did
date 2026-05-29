using FluentAssertions;
using NetDid.Method.Ethr.Crypto;
using NetDid.Method.Ethr.Erc1056;
using NetDid.Method.Ethr.Resolution;
using Xunit;

namespace NetDid.Method.Ethr.Tests;

/// <summary>
/// Tests for EthrDocumentBuilder — the core DID Document construction logic.
/// All tests use in-memory event lists; no RPC calls.
/// </summary>
public class EthrDocumentBuilderTests
{
    private const string Did        = "did:ethr:sepolia:0x001d3f1ef827552ae1114027bd3ecf1f086ba0f9";
    private const string Address    = "0x001d3f1ef827552ae1114027bd3ecf1f086ba0f9";
    private const string ChainId    = "11155111"; // sepolia
    private static readonly DateTimeOffset Now = DateTimeOffset.UtcNow;

    private static EthrIdentifier MakeIdentifier(bool isPublicKey = false, byte[]? pubKey = null)
        => new("sepolia", Address, isPublicKey, pubKey);

    // ── Default document (no events) ─────────────────────────────────────────

    [Fact]
    public void Build_NoEvents_ProducesDefaultDocument()
    {
        var doc = EthrDocumentBuilder.Build(Did, MakeIdentifier(), ChainId, [], Now, false);

        doc.Id.Value.Should().Be(Did);
        doc.VerificationMethod.Should().HaveCount(1);
        doc.VerificationMethod![0].Id.Should().Be($"{Did}#controller");
        doc.VerificationMethod[0].Type.Should().Be("EcdsaSecp256k1RecoveryMethod2020");
        doc.VerificationMethod[0].BlockchainAccountId.Should()
            .Be($"eip155:{ChainId}:0x001d3F1ef827552Ae1114027BD3ECF1f086bA0F9");
        doc.Authentication.Should().ContainSingle()
            .Which.Reference.Should().Be($"{Did}#controller");
        doc.AssertionMethod.Should().ContainSingle()
            .Which.Reference.Should().Be($"{Did}#controller");
        doc.Service.Should().BeNullOrEmpty();
    }

    // ── Owner changed ─────────────────────────────────────────────────────────

    [Fact]
    public void Build_OwnerChanged_ControllerVmReflectsNewOwner()
    {
        var newOwner         = "0xdbf03b407c01e7cd3cbea99509d93f8dddc8c6fb";
        var newOwnerChecksum  = "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB";
        var events = new List<Erc1056Event>
        {
            new OwnerChangedEvent(Address, newOwner, 0, 100)
        };

        var doc = EthrDocumentBuilder.Build(Did, MakeIdentifier(), ChainId, events, Now, false);

        doc.VerificationMethod!
            .Single(v => v.Id.EndsWith("#controller"))
            .BlockchainAccountId.Should().Contain(newOwnerChecksum);
    }

    // ── Deactivated ───────────────────────────────────────────────────────────

    [Fact]
    public void Build_ZeroAddressOwner_ReturnsDeactivatedDocument()
    {
        var events = new List<Erc1056Event>
        {
            new OwnerChangedEvent(Address, "0x0000000000000000000000000000000000000000", 0, 50)
        };

        var doc = EthrDocumentBuilder.Build(Did, MakeIdentifier(), ChainId, events, Now, isDeactivated: true);

        doc.VerificationMethod.Should().BeNullOrEmpty();
        doc.Authentication.Should().BeNullOrEmpty();
        doc.AssertionMethod.Should().BeNullOrEmpty();
    }

    // ── veriKey delegate ──────────────────────────────────────────────────────

    [Fact]
    public void Build_VeriKeyDelegate_AppearsInAssertionMethod()
    {
        var delegate20 = "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed";
        var future = (ulong)(Now.ToUnixTimeSeconds() + 3600);
        var events = new List<Erc1056Event>
        {
            new DelegateChangedEvent(Address, "veriKey", delegate20, future, 0, 10)
        };

        var doc = EthrDocumentBuilder.Build(Did, MakeIdentifier(), ChainId, events, Now, false);

        doc.AssertionMethod.Should().Contain(e => e.Reference != null && e.Reference.Contains("#delegate-1"));
        doc.Authentication.Should().NotContain(e => e.Reference != null && e.Reference.Contains("#delegate-1"));
    }

    // ── sigAuth delegate ──────────────────────────────────────────────────────

    [Fact]
    public void Build_SigAuthDelegate_AppearsInAuthenticationAndAssertionMethod()
    {
        var delegate20 = "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed";
        var future = (ulong)(Now.ToUnixTimeSeconds() + 3600);
        var events = new List<Erc1056Event>
        {
            new DelegateChangedEvent(Address, "sigAuth", delegate20, future, 0, 10)
        };

        var doc = EthrDocumentBuilder.Build(Did, MakeIdentifier(), ChainId, events, Now, false);

        // sigAuth -> both authentication AND assertionMethod (matches JS resolver fall-through)
        doc.Authentication.Should().Contain(e => e.Reference != null && e.Reference.Contains("#delegate-1"));
        doc.AssertionMethod.Should().Contain(e => e.Reference != null && e.Reference.Contains("#delegate-1"));
    }

    // ── Expired delegate excluded ─────────────────────────────────────────────

    [Fact]
    public void Build_ExpiredDelegate_IsExcluded()
    {
        var delegate20 = "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed";
        var past = (ulong)(Now.ToUnixTimeSeconds() - 1);
        var events = new List<Erc1056Event>
        {
            new DelegateChangedEvent(Address, "veriKey", delegate20, past, 0, 10)
        };

        var doc = EthrDocumentBuilder.Build(Did, MakeIdentifier(), ChainId, events, Now, false);

        doc.VerificationMethod.Should().HaveCount(1, "only #controller remains");
        doc.AssertionMethod.Should().HaveCount(1, "only #controller reference remains");
    }

    // ── Service attribute ─────────────────────────────────────────────────────

    [Fact]
    public void Build_ServiceAttribute_AppearsInServiceList()
    {
        var url = "https://agent.example.com/api";
        var future = (ulong)(Now.ToUnixTimeSeconds() + 3600);
        var events = new List<Erc1056Event>
        {
            new AttributeChangedEvent(Address, "did/svc/AgentService",
                System.Text.Encoding.UTF8.GetBytes(url), future, 0, 20)
        };

        var doc = EthrDocumentBuilder.Build(Did, MakeIdentifier(), ChainId, events, Now, false);

        doc.Service.Should().ContainSingle();
        doc.Service![0].Type.Should().Be("AgentService");
        doc.Service[0].ServiceEndpoint.Uri.Should().Be(url);
    }

    // ── Secp256k1 key attribute ───────────────────────────────────────────────

    [Fact]
    public void Build_Secp256k1Attribute_ProducesEcdsaVerificationKey()
    {
        // Use a valid compressed secp256k1 public key (33 bytes)
        var pubKeyBytes = Convert.FromHexString(
            "026e145ccef1033dea239875dd00dfb4fee6e3348b84985c92f103444683bae07b");
        var future = (ulong)(Now.ToUnixTimeSeconds() + 3600);
        var events = new List<Erc1056Event>
        {
            new AttributeChangedEvent(Address, "did/pub/Secp256k1/veriKey/hex",
                pubKeyBytes, future, 0, 20)
        };

        var doc = EthrDocumentBuilder.Build(Did, MakeIdentifier(), ChainId, events, Now, false);

        var vm = doc.VerificationMethod!.FirstOrDefault(v => v.Id.Contains("#delegate-"));
        vm.Should().NotBeNull();
        vm!.Type.Should().Be("EcdsaSecp256k1VerificationKey2019");
        vm.PublicKeyJwk.Should().NotBeNull();
    }

    // ── Ed25519 key attribute ─────────────────────────────────────────────────

    [Fact]
    public void Build_Ed25519Attribute_ProducesEd25519VerificationKey()
    {
        var pubKeyBytes = new byte[32];
        new Random(42).NextBytes(pubKeyBytes);
        var future = (ulong)(Now.ToUnixTimeSeconds() + 3600);
        var events = new List<Erc1056Event>
        {
            new AttributeChangedEvent(Address, "did/pub/Ed25519/veriKey/base64",
                pubKeyBytes, future, 0, 20)
        };

        var doc = EthrDocumentBuilder.Build(Did, MakeIdentifier(), ChainId, events, Now, false);

        var vm = doc.VerificationMethod!.FirstOrDefault(v => v.Id.Contains("#delegate-"));
        vm.Should().NotBeNull();
        vm!.Type.Should().Be("Ed25519VerificationKey2020");
        vm.PublicKeyMultibase.Should().StartWith("z");
    }

    // ── Public-key identifier: #controllerKey VM ─────────────────────────────

    [Fact]
    public void Build_PublicKeyIdentifier_NoOwnerChange_AddsControllerKeyVm()
    {
        var pubKeyBytes = Convert.FromHexString(
            "026e145ccef1033dea239875dd00dfb4fee6e3348b84985c92f103444683bae07b");
        var derivedAddr = EthereumAddress.FromCompressedPublicKey(pubKeyBytes).ToLowerInvariant();
        var identifier = new EthrIdentifier("sepolia", derivedAddr, true, pubKeyBytes);
        var did2 = $"did:ethr:sepolia:{Convert.ToHexString(pubKeyBytes).ToLowerInvariant()}";

        var doc = EthrDocumentBuilder.Build(did2, identifier, ChainId, [], Now, false);

        doc.VerificationMethod.Should().HaveCount(2);
        doc.VerificationMethod!.Should().Contain(v => v.Id.EndsWith("#controllerKey"));
        var ckVm = doc.VerificationMethod!.Single(v => v.Id.EndsWith("#controllerKey"));
        ckVm.Type.Should().Be("EcdsaSecp256k1VerificationKey2019");
        ckVm.PublicKeyJwk.Should().NotBeNull();
    }

    // ── @context includes secp256k1-recovery always ───────────────────────────

    [Fact]
    public void Build_NoEvents_ContextIncludesSecp256k1RecoveryContext()
    {
        var doc = EthrDocumentBuilder.Build(Did, MakeIdentifier(), ChainId, [], Now, false);
        doc.Context.Should().NotBeNull();
        doc.Context!.Should().Contain("https://www.w3.org/ns/did/v1");
        doc.Context.Should().Contain(c =>
            c.ToString()!.Contains("secp256k1recovery"));
    }
}
