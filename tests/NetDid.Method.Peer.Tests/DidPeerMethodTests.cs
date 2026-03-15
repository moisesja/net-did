using FluentAssertions;
using NetDid.Core;
using NetDid.Core.Crypto;
using NetDid.Core.Model;
using NetDid.Method.Peer;

namespace NetDid.Method.Peer.Tests;

public class DidPeerMethodTests
{
    private readonly DefaultKeyGenerator _keyGen = new();
    private readonly DefaultCryptoProvider _crypto = new();
    private readonly DidPeerMethod _method;

    public DidPeerMethodTests()
    {
        _method = new DidPeerMethod(_keyGen);
    }

    // --- Numalgo 0 ---

    [Fact]
    public async Task Numalgo0_CreateAndResolve_Ed25519()
    {
        var result = await _method.CreateAsync(new DidPeerCreateOptions
        {
            Numalgo = PeerNumalgo.Zero,
            InceptionKeyType = KeyType.Ed25519
        });

        result.Did.Value.Should().StartWith("did:peer:0z");
        result.DidDocument.VerificationMethod.Should().HaveCount(2); // Ed25519 + X25519
        result.DidDocument.Authentication.Should().HaveCount(1);
        result.DidDocument.KeyAgreement.Should().HaveCount(1);

        var resolved = await _method.ResolveAsync(result.Did.Value);
        resolved.DidDocument.Should().NotBeNull();
        resolved.ResolutionMetadata.Error.Should().BeNull();
        resolved.DidDocument!.Id.Value.Should().Be(result.Did.Value);
    }

    [Fact]
    public async Task Numalgo0_CreateAndResolve_P256()
    {
        var result = await _method.CreateAsync(new DidPeerCreateOptions
        {
            Numalgo = PeerNumalgo.Zero,
            InceptionKeyType = KeyType.P256
        });

        result.Did.Value.Should().StartWith("did:peer:0z");
        result.DidDocument.VerificationMethod.Should().HaveCount(1);

        var resolved = await _method.ResolveAsync(result.Did.Value);
        resolved.DidDocument.Should().NotBeNull();
        resolved.DidDocument!.VerificationMethod.Should().HaveCount(1);
    }

    [Fact]
    public async Task Numalgo0_WithExistingKey()
    {
        var keyPair = _keyGen.Generate(KeyType.Ed25519);
        var signer = new KeyPairSigner(keyPair, _crypto);

        var result = await _method.CreateAsync(new DidPeerCreateOptions
        {
            Numalgo = PeerNumalgo.Zero,
            InceptionKeyType = KeyType.Ed25519,
            ExistingKey = signer
        });

        result.Did.Value.Should().StartWith("did:peer:0z");
    }

    // --- Numalgo 2 ---

    [Fact]
    public async Task Numalgo2_CreateAndResolve_WithKeysAndService()
    {
        var authKey = _keyGen.Generate(KeyType.Ed25519);
        var agreeKey = _keyGen.Generate(KeyType.X25519);

        var result = await _method.CreateAsync(new DidPeerCreateOptions
        {
            Numalgo = PeerNumalgo.Two,
            Keys =
            [
                new PeerKeyPurpose(new KeyPairSigner(authKey, _crypto), PeerPurpose.Authentication),
                new PeerKeyPurpose(new KeyPairSigner(agreeKey, _crypto), PeerPurpose.KeyAgreement)
            ],
            Services =
            [
                new Service
                {
                    Id = "#didcomm",
                    Type = "DIDCommMessaging",
                    ServiceEndpoint = ServiceEndpointValue.FromUri("https://example.com/didcomm")
                }
            ]
        });

        result.Did.Value.Should().StartWith("did:peer:2.");
        result.Did.Value.Should().Contain(".V"); // Authentication prefix
        result.Did.Value.Should().Contain(".E"); // KeyAgreement prefix (was 'A', now 'E')
        result.DidDocument.VerificationMethod.Should().HaveCount(2);
        result.DidDocument.Authentication.Should().HaveCount(1);
        result.DidDocument.KeyAgreement.Should().HaveCount(1);
        result.DidDocument.Service.Should().HaveCount(1);

        // Resolve
        var resolved = await _method.ResolveAsync(result.Did.Value);
        resolved.DidDocument.Should().NotBeNull();
        resolved.DidDocument!.VerificationMethod.Should().HaveCount(2);
        resolved.DidDocument.Authentication.Should().HaveCount(1);
        resolved.DidDocument.KeyAgreement.Should().HaveCount(1);
        resolved.DidDocument.Service.Should().HaveCount(1);
        resolved.DidDocument.Service![0].Type.Should().Be("DIDCommMessaging");
    }

    [Fact]
    public async Task Numalgo2_ServiceEndpointPreserved()
    {
        var authKey = _keyGen.Generate(KeyType.Ed25519);

        var result = await _method.CreateAsync(new DidPeerCreateOptions
        {
            Numalgo = PeerNumalgo.Two,
            Keys =
            [
                new PeerKeyPurpose(new KeyPairSigner(authKey, _crypto), PeerPurpose.Authentication)
            ],
            Services =
            [
                new Service
                {
                    Id = "#svc",
                    Type = "DIDCommMessaging",
                    ServiceEndpoint = ServiceEndpointValue.FromUri("https://relay.example.com/endpoint")
                }
            ]
        });

        var resolved = await _method.ResolveAsync(result.Did.Value);
        var svc = resolved.DidDocument!.Service![0];
        svc.ServiceEndpoint.IsUri.Should().BeTrue();
        svc.ServiceEndpoint.Uri.Should().Be("https://relay.example.com/endpoint");
    }

    [Fact]
    public async Task Numalgo2_MultipleKeys()
    {
        var authKey1 = _keyGen.Generate(KeyType.Ed25519);
        var authKey2 = _keyGen.Generate(KeyType.P256);
        var agreeKey = _keyGen.Generate(KeyType.X25519);

        var result = await _method.CreateAsync(new DidPeerCreateOptions
        {
            Numalgo = PeerNumalgo.Two,
            Keys =
            [
                new PeerKeyPurpose(new KeyPairSigner(authKey1, _crypto), PeerPurpose.Authentication),
                new PeerKeyPurpose(new KeyPairSigner(authKey2, _crypto), PeerPurpose.Authentication),
                new PeerKeyPurpose(new KeyPairSigner(agreeKey, _crypto), PeerPurpose.KeyAgreement)
            ]
        });

        result.DidDocument.VerificationMethod.Should().HaveCount(3);
        result.DidDocument.Authentication.Should().HaveCount(2);
        result.DidDocument.KeyAgreement.Should().HaveCount(1);

        var resolved = await _method.ResolveAsync(result.Did.Value);
        resolved.DidDocument!.VerificationMethod.Should().HaveCount(3);
    }

    [Fact]
    public async Task Numalgo2_NoKeys_Throws()
    {
        var act = () => _method.CreateAsync(new DidPeerCreateOptions
        {
            Numalgo = PeerNumalgo.Two,
            Keys = []
        });

        await act.Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public async Task Numalgo2_AssertionMethod_RoundTrip()
    {
        var assertKey = _keyGen.Generate(KeyType.Ed25519);

        var result = await _method.CreateAsync(new DidPeerCreateOptions
        {
            Numalgo = PeerNumalgo.Two,
            Keys =
            [
                new PeerKeyPurpose(new KeyPairSigner(assertKey, _crypto), PeerPurpose.Assertion)
            ]
        });

        result.Did.Value.Should().Contain(".A"); // Assertion prefix
        result.DidDocument.AssertionMethod.Should().HaveCount(1);
        result.DidDocument.Authentication.Should().BeNull();
        result.DidDocument.KeyAgreement.Should().BeNull();

        var resolved = await _method.ResolveAsync(result.Did.Value);
        resolved.DidDocument!.AssertionMethod.Should().HaveCount(1);
        resolved.DidDocument.Authentication.Should().BeNull();
    }

    [Fact]
    public async Task Numalgo2_CapabilityInvocationAndDelegation_RoundTrip()
    {
        var invokeKey = _keyGen.Generate(KeyType.Ed25519);
        var delegateKey = _keyGen.Generate(KeyType.P256);

        var result = await _method.CreateAsync(new DidPeerCreateOptions
        {
            Numalgo = PeerNumalgo.Two,
            Keys =
            [
                new PeerKeyPurpose(new KeyPairSigner(invokeKey, _crypto), PeerPurpose.CapabilityInvocation),
                new PeerKeyPurpose(new KeyPairSigner(delegateKey, _crypto), PeerPurpose.CapabilityDelegation)
            ]
        });

        result.Did.Value.Should().Contain(".I"); // CapabilityInvocation prefix
        result.Did.Value.Should().Contain(".D"); // CapabilityDelegation prefix
        result.DidDocument.CapabilityInvocation.Should().HaveCount(1);
        result.DidDocument.CapabilityDelegation.Should().HaveCount(1);
        result.DidDocument.Authentication.Should().BeNull();

        var resolved = await _method.ResolveAsync(result.Did.Value);
        resolved.DidDocument!.CapabilityInvocation.Should().HaveCount(1);
        resolved.DidDocument.CapabilityDelegation.Should().HaveCount(1);
    }

    [Fact]
    public async Task Numalgo2_AllPurposeCodes_RoundTrip()
    {
        var assertKey = _keyGen.Generate(KeyType.Ed25519);
        var agreeKey = _keyGen.Generate(KeyType.X25519);
        var authKey = _keyGen.Generate(KeyType.Ed25519);
        var invokeKey = _keyGen.Generate(KeyType.P256);
        var delegateKey = _keyGen.Generate(KeyType.P256);

        var result = await _method.CreateAsync(new DidPeerCreateOptions
        {
            Numalgo = PeerNumalgo.Two,
            Keys =
            [
                new PeerKeyPurpose(new KeyPairSigner(assertKey, _crypto), PeerPurpose.Assertion),
                new PeerKeyPurpose(new KeyPairSigner(agreeKey, _crypto), PeerPurpose.KeyAgreement),
                new PeerKeyPurpose(new KeyPairSigner(authKey, _crypto), PeerPurpose.Authentication),
                new PeerKeyPurpose(new KeyPairSigner(invokeKey, _crypto), PeerPurpose.CapabilityInvocation),
                new PeerKeyPurpose(new KeyPairSigner(delegateKey, _crypto), PeerPurpose.CapabilityDelegation)
            ],
            Services =
            [
                new Service
                {
                    Id = "#svc",
                    Type = "DIDCommMessaging",
                    ServiceEndpoint = ServiceEndpointValue.FromUri("https://example.com/endpoint")
                }
            ]
        });

        result.Did.Value.Should().StartWith("did:peer:2.");
        result.DidDocument.VerificationMethod.Should().HaveCount(5);
        result.DidDocument.AssertionMethod.Should().HaveCount(1);
        result.DidDocument.KeyAgreement.Should().HaveCount(1);
        result.DidDocument.Authentication.Should().HaveCount(1);
        result.DidDocument.CapabilityInvocation.Should().HaveCount(1);
        result.DidDocument.CapabilityDelegation.Should().HaveCount(1);
        result.DidDocument.Service.Should().HaveCount(1);

        // Resolve and verify all relationships survive
        var resolved = await _method.ResolveAsync(result.Did.Value);
        resolved.DidDocument.Should().NotBeNull();
        resolved.DidDocument!.VerificationMethod.Should().HaveCount(5);
        resolved.DidDocument.AssertionMethod.Should().HaveCount(1);
        resolved.DidDocument.KeyAgreement.Should().HaveCount(1);
        resolved.DidDocument.Authentication.Should().HaveCount(1);
        resolved.DidDocument.CapabilityInvocation.Should().HaveCount(1);
        resolved.DidDocument.CapabilityDelegation.Should().HaveCount(1);
        resolved.DidDocument.Service.Should().HaveCount(1);
    }

    [Fact]
    public async Task Numalgo2_VmIds_Are1Based_AndAbsolute()
    {
        var key1 = _keyGen.Generate(KeyType.Ed25519);
        var key2 = _keyGen.Generate(KeyType.X25519);

        var result = await _method.CreateAsync(new DidPeerCreateOptions
        {
            Numalgo = PeerNumalgo.Two,
            Keys =
            [
                new PeerKeyPurpose(new KeyPairSigner(key1, _crypto), PeerPurpose.Authentication),
                new PeerKeyPurpose(new KeyPairSigner(key2, _crypto), PeerPurpose.KeyAgreement)
            ]
        });

        var did = result.Did.Value;

        // Create path: IDs should be absolute and 1-based
        result.DidDocument.VerificationMethod![0].Id.Should().Be($"{did}#key-1");
        result.DidDocument.VerificationMethod[1].Id.Should().Be($"{did}#key-2");

        // Resolve path: same
        var resolved = await _method.ResolveAsync(did);
        resolved.DidDocument!.VerificationMethod![0].Id.Should().Be($"{did}#key-1");
        resolved.DidDocument.VerificationMethod[1].Id.Should().Be($"{did}#key-2");
    }

    [Fact]
    public async Task Numalgo2_CallerServiceId_PreservedThroughRoundTrip()
    {
        var key = _keyGen.Generate(KeyType.Ed25519);

        var result = await _method.CreateAsync(new DidPeerCreateOptions
        {
            Numalgo = PeerNumalgo.Two,
            Keys =
            [
                new PeerKeyPurpose(new KeyPairSigner(key, _crypto), PeerPurpose.Authentication)
            ],
            Services =
            [
                new Service
                {
                    Id = "#my-custom-svc",
                    Type = "DIDCommMessaging",
                    ServiceEndpoint = ServiceEndpointValue.FromUri("https://example.com/endpoint")
                }
            ]
        });

        var did = result.Did.Value;

        // Create path: caller-provided ID preserved (absolute)
        result.DidDocument.Service![0].Id.Should().Be($"{did}#my-custom-svc");

        // Resolve path: same
        var resolved = await _method.ResolveAsync(did);
        resolved.DidDocument!.Service![0].Id.Should().Be($"{did}#my-custom-svc");
    }

    [Fact]
    public async Task Numalgo2_AutoGeneratedServiceIds_FollowSpecConvention()
    {
        var key = _keyGen.Generate(KeyType.Ed25519);

        var result = await _method.CreateAsync(new DidPeerCreateOptions
        {
            Numalgo = PeerNumalgo.Two,
            Keys =
            [
                new PeerKeyPurpose(new KeyPairSigner(key, _crypto), PeerPurpose.Authentication)
            ],
            Services =
            [
                new Service
                {
                    Id = "not-a-fragment", // no '#' prefix — will be auto-generated
                    Type = "DIDCommMessaging",
                    ServiceEndpoint = ServiceEndpointValue.FromUri("https://a.example.com")
                },
                new Service
                {
                    Id = "also-not-fragment",
                    Type = "LinkedDomains",
                    ServiceEndpoint = ServiceEndpointValue.FromUri("https://b.example.com")
                }
            ]
        });

        var did = result.Did.Value;

        // Per spec: first auto = "#service", second auto = "#service-1"
        result.DidDocument.Service![0].Id.Should().Be($"{did}#service");
        result.DidDocument.Service[1].Id.Should().Be($"{did}#service-1");
    }

    // --- Numalgo 4 ---

    [Fact]
    public async Task Numalgo4_CreateAndResolveLongForm()
    {
        var keyPair = _keyGen.Generate(KeyType.Ed25519);

        var inputDoc = new DidDocument
        {
            Id = new Did("did:peer:placeholder"),
            VerificationMethod =
            [
                new VerificationMethod
                {
                    Id = "#key-0",
                    Type = "Multikey",
                    Controller = new Did("did:peer:placeholder"),
                    PublicKeyMultibase = keyPair.MultibasePublicKey
                }
            ],
            Authentication =
            [
                VerificationRelationshipEntry.FromReference("#key-0")
            ]
        };

        var result = await _method.CreateAsync(new DidPeerCreateOptions
        {
            Numalgo = PeerNumalgo.Four,
            InputDocument = inputDoc
        });

        result.Did.Value.Should().StartWith("did:peer:4z");
        result.Did.Value.Should().Contain(":"); // Long form has ':'
        result.DidDocument.VerificationMethod.Should().HaveCount(1);

        // Resolve the long-form DID
        var resolved = await _method.ResolveAsync(result.Did.Value);
        resolved.DidDocument.Should().NotBeNull();
        resolved.DidDocument!.Id.Value.Should().Be(result.Did.Value);
        resolved.DidDocument.VerificationMethod.Should().HaveCount(1);
        resolved.DidDocument.Authentication.Should().HaveCount(1);
    }

    [Fact]
    public async Task Numalgo4_ShortFormOnly_ReturnsNotFound()
    {
        var keyPair = _keyGen.Generate(KeyType.Ed25519);

        var inputDoc = new DidDocument
        {
            Id = new Did("did:peer:placeholder"),
            VerificationMethod =
            [
                new VerificationMethod
                {
                    Id = "#key-0",
                    Type = "Multikey",
                    Controller = new Did("did:peer:placeholder"),
                    PublicKeyMultibase = keyPair.MultibasePublicKey
                }
            ]
        };

        var result = await _method.CreateAsync(new DidPeerCreateOptions
        {
            Numalgo = PeerNumalgo.Four,
            InputDocument = inputDoc
        });

        // Extract short form only (everything before the ':')
        var fullDid = result.Did.Value;
        var parts = fullDid.Split(':');
        // did:peer:4{hash}:{longform} -> did:peer:4{hash}
        var shortFormDid = $"{parts[0]}:{parts[1]}:{parts[2]}";

        var resolved = await _method.ResolveAsync(shortFormDid);
        resolved.DidDocument.Should().BeNull();
        resolved.ResolutionMetadata.Error.Should().Be("notFound");
    }

    [Fact]
    public async Task Numalgo4_ControllerRewritten()
    {
        var keyPair = _keyGen.Generate(KeyType.Ed25519);

        var inputDoc = new DidDocument
        {
            Id = new Did("did:peer:placeholder"),
            Controller = [new Did("did:peer:placeholder")],
            VerificationMethod =
            [
                new VerificationMethod
                {
                    Id = "#key-0",
                    Type = "Multikey",
                    Controller = new Did("did:peer:placeholder"),
                    PublicKeyMultibase = keyPair.MultibasePublicKey
                }
            ],
            Authentication =
            [
                VerificationRelationshipEntry.FromReference("#key-0")
            ]
        };

        var result = await _method.CreateAsync(new DidPeerCreateOptions
        {
            Numalgo = PeerNumalgo.Four,
            InputDocument = inputDoc
        });

        // Controller should be rewritten to actual DID
        result.DidDocument.Controller.Should().HaveCount(1);
        result.DidDocument.Controller![0].Value.Should().Be(result.Did.Value);
        result.DidDocument.Controller[0].Value.Should().NotBe("did:peer:placeholder");

        // VM controller also rewritten
        result.DidDocument.VerificationMethod![0].Controller.Value.Should().Be(result.Did.Value);

        // Resolve round-trip
        var resolved = await _method.ResolveAsync(result.Did.Value);
        resolved.DidDocument!.Controller.Should().HaveCount(1);
        resolved.DidDocument.Controller![0].Value.Should().Be(result.Did.Value);
        resolved.DidDocument.VerificationMethod![0].Controller.Value.Should().Be(result.Did.Value);
    }

    [Fact]
    public async Task Numalgo4_EmbeddedVerificationMethod_Rewritten()
    {
        var keyPair = _keyGen.Generate(KeyType.Ed25519);

        var inputDoc = new DidDocument
        {
            Id = new Did("did:peer:placeholder"),
            Authentication =
            [
                VerificationRelationshipEntry.FromEmbedded(new VerificationMethod
                {
                    Id = "#embedded-key",
                    Type = "Multikey",
                    Controller = new Did("did:peer:placeholder"),
                    PublicKeyMultibase = keyPair.MultibasePublicKey
                })
            ]
        };

        var result = await _method.CreateAsync(new DidPeerCreateOptions
        {
            Numalgo = PeerNumalgo.Four,
            InputDocument = inputDoc
        });

        var embeddedVm = result.DidDocument.Authentication![0].EmbeddedMethod!;
        embeddedVm.Id.Should().Be(result.Did.Value + "#embedded-key");
        embeddedVm.Controller.Value.Should().Be(result.Did.Value);

        // Resolve round-trip
        var resolved = await _method.ResolveAsync(result.Did.Value);
        var resolvedVm = resolved.DidDocument!.Authentication![0].EmbeddedMethod!;
        resolvedVm.Id.Should().Be(result.Did.Value + "#embedded-key");
        resolvedVm.Controller.Value.Should().Be(result.Did.Value);
    }

    [Fact]
    public async Task Numalgo4_ContextPreserved()
    {
        var keyPair = _keyGen.Generate(KeyType.Ed25519);

        var inputDoc = new DidDocument
        {
            Id = new Did("did:peer:placeholder"),
            Context = ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"],
            VerificationMethod =
            [
                new VerificationMethod
                {
                    Id = "#key-0",
                    Type = "Multikey",
                    Controller = new Did("did:peer:placeholder"),
                    PublicKeyMultibase = keyPair.MultibasePublicKey
                }
            ]
        };

        var result = await _method.CreateAsync(new DidPeerCreateOptions
        {
            Numalgo = PeerNumalgo.Four,
            InputDocument = inputDoc
        });

        result.DidDocument.Context.Should().HaveCount(2);

        var resolved = await _method.ResolveAsync(result.Did.Value);
        resolved.DidDocument!.Context.Should().HaveCount(2);
    }

    [Fact]
    public async Task Numalgo4_AdditionalPropertiesPreserved()
    {
        var keyPair = _keyGen.Generate(KeyType.Ed25519);
        var customElement = System.Text.Json.JsonDocument.Parse("\"custom-value\"").RootElement.Clone();

        var inputDoc = new DidDocument
        {
            Id = new Did("did:peer:placeholder"),
            VerificationMethod =
            [
                new VerificationMethod
                {
                    Id = "#key-0",
                    Type = "Multikey",
                    Controller = new Did("did:peer:placeholder"),
                    PublicKeyMultibase = keyPair.MultibasePublicKey
                }
            ],
            AdditionalProperties = new Dictionary<string, System.Text.Json.JsonElement>
            {
                ["customProp"] = customElement
            }
        };

        var result = await _method.CreateAsync(new DidPeerCreateOptions
        {
            Numalgo = PeerNumalgo.Four,
            InputDocument = inputDoc
        });

        result.DidDocument.AdditionalProperties.Should().ContainKey("customProp");

        var resolved = await _method.ResolveAsync(result.Did.Value);
        resolved.DidDocument!.AdditionalProperties.Should().ContainKey("customProp");
        resolved.DidDocument.AdditionalProperties!["customProp"].GetString().Should().Be("custom-value");
    }

    [Fact]
    public async Task Numalgo4_ServiceIdRewritten()
    {
        var keyPair = _keyGen.Generate(KeyType.Ed25519);

        var inputDoc = new DidDocument
        {
            Id = new Did("did:peer:placeholder"),
            VerificationMethod =
            [
                new VerificationMethod
                {
                    Id = "#key-0",
                    Type = "Multikey",
                    Controller = new Did("did:peer:placeholder"),
                    PublicKeyMultibase = keyPair.MultibasePublicKey
                }
            ],
            Service =
            [
                new Service
                {
                    Id = "#svc-0",
                    Type = "DIDCommMessaging",
                    ServiceEndpoint = ServiceEndpointValue.FromUri("https://example.com/endpoint")
                }
            ]
        };

        var result = await _method.CreateAsync(new DidPeerCreateOptions
        {
            Numalgo = PeerNumalgo.Four,
            InputDocument = inputDoc
        });

        result.DidDocument.Service.Should().HaveCount(1);
        result.DidDocument.Service![0].Id.Should().Be(result.Did.Value + "#svc-0");

        var resolved = await _method.ResolveAsync(result.Did.Value);
        resolved.DidDocument!.Service.Should().HaveCount(1);
        resolved.DidDocument.Service![0].Id.Should().Be(result.Did.Value + "#svc-0");
        resolved.DidDocument.Service[0].ServiceEndpoint.Uri.Should().Be("https://example.com/endpoint");
    }

    [Fact]
    public async Task Numalgo4_TamperedLongForm_ReturnsNotFound()
    {
        var keyPair = _keyGen.Generate(KeyType.Ed25519);

        var inputDoc = new DidDocument
        {
            Id = new Did("did:peer:placeholder"),
            VerificationMethod =
            [
                new VerificationMethod
                {
                    Id = "#key-0",
                    Type = "Multikey",
                    Controller = new Did("did:peer:placeholder"),
                    PublicKeyMultibase = keyPair.MultibasePublicKey
                }
            ]
        };

        var result = await _method.CreateAsync(new DidPeerCreateOptions
        {
            Numalgo = PeerNumalgo.Four,
            InputDocument = inputDoc
        });

        // Tamper with the long-form portion
        var tampered = result.Did.Value + "TAMPERED";
        var resolved = await _method.ResolveAsync(tampered);
        resolved.DidDocument.Should().BeNull();
    }

    // --- Resolution edge cases ---

    [Fact]
    public async Task Resolve_WrongMethod_ReturnsMethodNotSupported()
    {
        var result = await _method.ResolveAsync("did:key:z6Mktest");
        result.ResolutionMetadata.Error.Should().Be("methodNotSupported");
    }

    [Fact]
    public async Task Resolve_UnknownNumalgo_ReturnsNotFound()
    {
        var result = await _method.ResolveAsync("did:peer:9invalidnumalgo");
        result.DidDocument.Should().BeNull();
        result.ResolutionMetadata.Error.Should().Be("notFound");
    }

    // --- Capabilities ---

    [Fact]
    public void Capabilities_CreateAndResolve()
    {
        _method.Capabilities.Should().HaveFlag(DidMethodCapabilities.Create);
        _method.Capabilities.Should().HaveFlag(DidMethodCapabilities.Resolve);
        _method.Capabilities.Should().NotHaveFlag(DidMethodCapabilities.Update);
        _method.Capabilities.Should().NotHaveFlag(DidMethodCapabilities.Deactivate);
    }

    [Fact]
    public void MethodName_IsPeer()
    {
        _method.MethodName.Should().Be("peer");
    }
}
