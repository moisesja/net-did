using FluentAssertions;
using Microsoft.IdentityModel.Tokens;
using NetDid.Core.Model;

namespace NetDid.Core.Tests.Model;

public class DidDocumentBuilderTests
{
    private const string TestDid = "did:example:123";

    [Fact]
    public void Build_MinimalDocument_SetsIdAndDefaultController()
    {
        var doc = new DidDocumentBuilder(TestDid).Build();

        doc.Id.Value.Should().Be(TestDid);
        doc.Controller.Should().ContainSingle().Which.Value.Should().Be(TestDid);
    }

    [Fact]
    public void Build_WithExplicitController_OverridesDefault()
    {
        var controller = new Did("did:example:controller");
        var doc = new DidDocumentBuilder(TestDid)
            .WithController(controller)
            .Build();

        doc.Controller.Should().ContainSingle().Which.Should().Be(controller);
    }

    [Fact]
    public void Build_WithMultipleControllers()
    {
        var doc = new DidDocumentBuilder(TestDid)
            .WithController(new Did("did:example:a"), new Did("did:example:b"))
            .Build();

        doc.Controller.Should().HaveCount(2);
    }

    [Fact]
    public void Build_WithAlsoKnownAs()
    {
        var doc = new DidDocumentBuilder(TestDid)
            .AddAlsoKnownAs("https://example.com/user")
            .AddAlsoKnownAs("did:web:example.com")
            .Build();

        doc.AlsoKnownAs.Should().BeEquivalentTo(["https://example.com/user", "did:web:example.com"]);
    }

    [Fact]
    public void Build_WithVerificationMethod_Multikey()
    {
        var doc = new DidDocumentBuilder(TestDid)
            .AddVerificationMethod(vm => vm
                .WithId("#key-1")
                .WithType("Multikey")
                .WithMultibasePublicKey("z6MkTestKey"))
            .Build();

        doc.VerificationMethod.Should().ContainSingle();
        var vm = doc.VerificationMethod![0];
        vm.Id.Should().Be("#key-1");
        vm.Type.Should().Be("Multikey");
        vm.Controller.Value.Should().Be(TestDid);
        vm.PublicKeyMultibase.Should().Be("z6MkTestKey");
    }

    [Fact]
    public void Build_WithVerificationMethod_JWK()
    {
        var jwk = new JsonWebKey { Kty = "OKP", Crv = "Ed25519", X = "testX" };

        var doc = new DidDocumentBuilder(TestDid)
            .AddVerificationMethod(vm => vm
                .WithId("#key-1")
                .WithType("JsonWebKey2020")
                .WithPublicKeyJwk(jwk))
            .Build();

        var vm = doc.VerificationMethod![0];
        vm.Type.Should().Be("JsonWebKey2020");
        vm.PublicKeyJwk.Should().BeSameAs(jwk);
    }

    [Fact]
    public void Build_WithVerificationMethod_ExplicitController()
    {
        var controller = new Did("did:example:other");

        var doc = new DidDocumentBuilder(TestDid)
            .AddVerificationMethod(vm => vm
                .WithId("#key-1")
                .WithType("Multikey")
                .WithController(controller)
                .WithMultibasePublicKey("z6MkTestKey"))
            .Build();

        doc.VerificationMethod![0].Controller.Should().Be(controller);
    }

    [Fact]
    public void Build_WithAuthenticationReference()
    {
        var doc = new DidDocumentBuilder(TestDid)
            .AddVerificationMethod(vm => vm
                .WithId("#key-1")
                .WithType("Multikey")
                .WithMultibasePublicKey("z6MkTestKey"))
            .AddAuthentication("#key-1")
            .Build();

        doc.Authentication.Should().ContainSingle();
        doc.Authentication![0].IsReference.Should().BeTrue();
        doc.Authentication[0].Reference.Should().Be("#key-1");
    }

    [Fact]
    public void Build_WithAuthenticationEmbedded()
    {
        var doc = new DidDocumentBuilder(TestDid)
            .AddAuthentication(vm => vm
                .WithId("#auth-key")
                .WithType("Multikey")
                .WithMultibasePublicKey("z6MkTestKey"))
            .Build();

        doc.Authentication.Should().ContainSingle();
        doc.Authentication![0].IsReference.Should().BeFalse();
        doc.Authentication[0].EmbeddedMethod!.Id.Should().Be("#auth-key");
    }

    [Fact]
    public void Build_WithAssertionMethod()
    {
        var doc = new DidDocumentBuilder(TestDid)
            .AddAssertionMethod("#key-1")
            .Build();

        doc.AssertionMethod.Should().ContainSingle();
    }

    [Fact]
    public void Build_WithKeyAgreement()
    {
        var doc = new DidDocumentBuilder(TestDid)
            .AddKeyAgreement("#key-1")
            .Build();

        doc.KeyAgreement.Should().ContainSingle();
    }

    [Fact]
    public void Build_WithCapabilityInvocation()
    {
        var doc = new DidDocumentBuilder(TestDid)
            .AddCapabilityInvocation("#key-1")
            .Build();

        doc.CapabilityInvocation.Should().ContainSingle();
    }

    [Fact]
    public void Build_WithCapabilityDelegation()
    {
        var doc = new DidDocumentBuilder(TestDid)
            .AddCapabilityDelegation("#key-1")
            .Build();

        doc.CapabilityDelegation.Should().ContainSingle();
    }

    [Fact]
    public void Build_WithService()
    {
        var doc = new DidDocumentBuilder(TestDid)
            .AddService(svc => svc
                .WithId("#messaging")
                .WithType("DIDCommMessaging")
                .WithEndpoint("https://example.com/messaging"))
            .Build();

        doc.Service.Should().ContainSingle();
        var svc = doc.Service![0];
        svc.Id.Should().Be("#messaging");
        svc.Type.Should().Be("DIDCommMessaging");
        svc.ServiceEndpoint.Uri.Should().Be("https://example.com/messaging");
    }

    [Fact]
    public void Build_WithServiceEndpointValue()
    {
        var endpoint = ServiceEndpointValue.FromUri("https://example.com/api");

        var doc = new DidDocumentBuilder(TestDid)
            .AddService(svc => svc
                .WithId("#api")
                .WithType("ApiEndpoint")
                .WithEndpoint(endpoint))
            .Build();

        doc.Service![0].ServiceEndpoint.Should().BeSameAs(endpoint);
    }

    [Fact]
    public void Build_ComplexDocument()
    {
        var doc = new DidDocumentBuilder(TestDid)
            .AddAlsoKnownAs("https://example.com/user")
            .AddVerificationMethod(vm => vm
                .WithId("#key-1")
                .WithType("Multikey")
                .WithMultibasePublicKey("z6MkSigningKey"))
            .AddVerificationMethod(vm => vm
                .WithId("#key-2")
                .WithType("Multikey")
                .WithMultibasePublicKey("z6LSKeyAgree"))
            .AddAuthentication("#key-1")
            .AddAssertionMethod("#key-1")
            .AddKeyAgreement("#key-2")
            .AddService(svc => svc
                .WithId("#pds")
                .WithType("PersonalDataStore")
                .WithEndpoint("https://example.com/pds"))
            .Build();

        doc.Id.Value.Should().Be(TestDid);
        doc.AlsoKnownAs.Should().ContainSingle();
        doc.VerificationMethod.Should().HaveCount(2);
        doc.Authentication.Should().ContainSingle();
        doc.AssertionMethod.Should().ContainSingle();
        doc.KeyAgreement.Should().ContainSingle();
        doc.Service.Should().ContainSingle();
    }

    [Fact]
    public void Build_EmptyCollections_AreNull()
    {
        var doc = new DidDocumentBuilder(TestDid).Build();

        doc.VerificationMethod.Should().BeNull();
        doc.Authentication.Should().BeNull();
        doc.AssertionMethod.Should().BeNull();
        doc.KeyAgreement.Should().BeNull();
        doc.CapabilityInvocation.Should().BeNull();
        doc.CapabilityDelegation.Should().BeNull();
        doc.Service.Should().BeNull();
        doc.AlsoKnownAs.Should().BeNull();
    }

    [Fact]
    public void Build_VerificationMethodWithoutId_Throws()
    {
        var act = () => new DidDocumentBuilder(TestDid)
            .AddVerificationMethod(vm => vm
                .WithType("Multikey")
                .WithMultibasePublicKey("z6MkTest"))
            .Build();

        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Build_VerificationMethodWithoutType_Throws()
    {
        var act = () => new DidDocumentBuilder(TestDid)
            .AddVerificationMethod(vm => vm
                .WithId("#key-1")
                .WithMultibasePublicKey("z6MkTest"))
            .Build();

        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Build_ServiceWithoutId_Throws()
    {
        var act = () => new DidDocumentBuilder(TestDid)
            .AddService(svc => svc
                .WithType("Test")
                .WithEndpoint("https://example.com"))
            .Build();

        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Build_ServiceWithoutType_Throws()
    {
        var act = () => new DidDocumentBuilder(TestDid)
            .AddService(svc => svc
                .WithId("#svc")
                .WithEndpoint("https://example.com"))
            .Build();

        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Build_ServiceWithoutEndpoint_Throws()
    {
        var act = () => new DidDocumentBuilder(TestDid)
            .AddService(svc => svc
                .WithId("#svc")
                .WithType("Test"))
            .Build();

        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Constructor_AcceptsDid()
    {
        var did = new Did(TestDid);
        var doc = new DidDocumentBuilder(did).Build();

        doc.Id.Should().Be(did);
    }
}
