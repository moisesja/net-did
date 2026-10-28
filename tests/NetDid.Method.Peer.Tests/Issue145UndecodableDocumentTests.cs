using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using AwesomeAssertions;
using NetCid;
using NetCrypto;
using NetDid.Core.Model;
using NetDid.Method.Peer;

namespace NetDid.Method.Peer.Tests;

/// <summary>
/// Issue #145 (adversarial review): a did:peer:4 long form whose encoded document carries a lone
/// UTF-16 surrogate in an extension value used to resolve, returning a document that could not
/// be serialized. Core consumption now decodes every string once, so such a document fails closed.
/// </summary>
public class Issue145UndecodableDocumentTests
{
    private readonly DidPeerMethod _method = new(new DefaultKeyGenerator());

    // Encodes an input document exactly as did:peer:4 Create does (JSON multicodec 0x0200,
    // base58btc long form, SHA-256 multihash of the long-form string), from raw JSON, so the
    // test can carry content the serializer would never emit.
    private static string EncodePeer4(string inputDocumentJson)
        => EncodePeer4(Encoding.UTF8.GetBytes(inputDocumentJson));

    private static string EncodePeer4(byte[] inputDocumentUtf8)
    {
        var longForm = Multibase.Encode(
            Multicodec.Prefix(0x0200, inputDocumentUtf8),
            MultibaseEncoding.Base58Btc);
        var shortForm = Multibase.Encode(
            Multihash.Encode(0x12, SHA256.HashData(Encoding.UTF8.GetBytes(longForm))),
            MultibaseEncoding.Base58Btc);
        return $"did:peer:4{shortForm}:{longForm}";
    }

    [Fact]
    public async Task Issue145_Control_HandEncodedDocument_Resolves()
    {
        var resolved = await _method.ResolveAsync(EncodePeer4("""{"x-ext":"😀"}"""));

        resolved.DidDocument.Should().NotBeNull("the hand encoding must match Create's");
    }

    [Theory]
    [InlineData("""{"x-ext":"\uD800"}""")]
    [InlineData("""{"service":[{"id":"#s","type":"X","serviceEndpoint":{"uri":"\uDC00"}}]}""")]
    public async Task Issue145_LoneSurrogateExtensionValue_FailsClosed(string inputDocumentJson)
    {
        var resolved = await _method.ResolveAsync(EncodePeer4(inputDocumentJson));

        resolved.DidDocument.Should().BeNull(
            "a document that cannot be serialized must not be returned as a resolution result");
        resolved.ResolutionMetadata.Error.Should().Be("notFound");
    }

    [Theory]
    [InlineData("""{"verificationMethod":[{"id":"#k","type":null,"publicKeyMultibase":"z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"}]}""")]
    [InlineData("""{"verificationMethod":[null]}""")]
    public async Task Issue145_MalformedDocumentShape_FailsClosed(string inputDocumentJson)
    {
        // Round-3 adversarial review: these resolved to documents that crash Serialize.
        var resolved = await _method.ResolveAsync(EncodePeer4(inputDocumentJson));

        resolved.DidDocument.Should().BeNull();
    }

    // ── Writer side (round 4): Create used to publish U+FFFD in place of the caller's text ──

    private static Service ServiceWithType(string type) => new()
    {
        Id = "#svc",
        Type = type,
        ServiceEndpoint = ServiceEndpointValue.FromUri("https://example.com/didcomm")
    };

    [Fact]
    public async Task Issue145_Numalgo2Create_ServiceWithUnpairedSurrogate_ThrowsArgumentException()
    {
        var act = () => _method.CreateAsync(new DidPeerCreateOptions
        {
            Numalgo = PeerNumalgo.Two,
            Keys =
            [
                new PeerKeyPurpose(
                    new KeyPairSigner(new DefaultKeyGenerator().Generate(KeyType.Ed25519),
                        new DefaultCryptoProvider()),
                    PeerPurpose.Authentication)
            ],
            Services = [ServiceWithType("DIDComm\uD800Messaging")]
        });

        await act.Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public async Task Issue145_Numalgo4Create_ServiceWithUnpairedSurrogate_ThrowsArgumentException()
    {
        // Before the fix the DID hashed the U+FFFD-altered bytes while the returned document
        // kept the original text, so the two disagreed.
        var act = () => _method.CreateAsync(new DidPeerCreateOptions
        {
            Numalgo = PeerNumalgo.Four,
            InputDocument = new DidDocument { Service = [ServiceWithType("Example\uDC00")] }
        });

        await act.Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public async Task Issue145_Control_Numalgo2Create_SurrogatePairServiceType_RoundTrips()
    {
        var created = await _method.CreateAsync(new DidPeerCreateOptions
        {
            Numalgo = PeerNumalgo.Two,
            Keys =
            [
                new PeerKeyPurpose(
                    new KeyPairSigner(new DefaultKeyGenerator().Generate(KeyType.Ed25519),
                        new DefaultCryptoProvider()),
                    PeerPurpose.Authentication)
            ],
            Services = [ServiceWithType("Example😀")]
        });

        var resolved = await _method.ResolveAsync(created.Did.Value);

        resolved.DidDocument!.Service![0].Type.Should().Be("Example😀");
    }

    // ── PR #149 review round 1 + final adversarial pass ──────────────────────────────

    private static PeerKeyPurpose AuthenticationKey() => new(
        new KeyPairSigner(new DefaultKeyGenerator().Generate(KeyType.Ed25519), new DefaultCryptoProvider()),
        PeerPurpose.Authentication);

    private static ServiceEndpointValue FlatMixedSet() => ServiceEndpointValue.FromSet(
    [
        ServiceEndpointValue.FromUri("https://a.example"),
        ServiceEndpointValue.FromMap(new Dictionary<string, JsonElement>
        {
            ["uri"] = JsonSerializer.SerializeToElement("https://b.example")
        })
    ]);

    [Fact]
    public async Task Issue145_Numalgo4Create_NestedEndpointSet_CannotBeBuilt()
    {
        // Reviewer reproduction: Create succeeded with this shape and the returned DID then resolved
        // as notFound. The shape is now unrepresentable, so Create can never be handed it.
        var act = () => _method.CreateAsync(new DidPeerCreateOptions
        {
            Numalgo = PeerNumalgo.Four,
            InputDocument = new DidDocument
            {
                Service =
                [
                    new Service
                    {
                        Id = "#svc",
                        Type = "Example",
                        ServiceEndpoint = ServiceEndpointValue.FromSet(
                            [ServiceEndpointValue.FromSet([ServiceEndpointValue.FromUri("https://example.com")])])
                    }
                ]
            }
        });

        await act.Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public async Task Issue145_Control_Numalgo4CreateResolve_FlatMixedSet_RoundTrips()
    {
        var created = await _method.CreateAsync(new DidPeerCreateOptions
        {
            Numalgo = PeerNumalgo.Four,
            InputDocument = new DidDocument
            {
                Service = [new Service { Id = "#svc", Type = "Example", ServiceEndpoint = FlatMixedSet() }]
            }
        });

        var resolved = await _method.ResolveAsync(created.Did.Value);

        resolved.ResolutionMetadata.Error.Should().BeNull();
        var endpoint = resolved.DidDocument!.Service![0].ServiceEndpoint;
        endpoint.Set.Should().HaveCount(2);
        endpoint.Set![0].Uri.Should().Be("https://a.example");
        endpoint.Set[1].IsMap.Should().BeTrue();
    }

    [Fact]
    public async Task Issue145_Control_Numalgo2CreateResolve_FlatMixedSet_RoundTrips()
    {
        var created = await _method.CreateAsync(new DidPeerCreateOptions
        {
            Numalgo = PeerNumalgo.Two,
            Keys = [AuthenticationKey()],
            Services = [new Service { Id = "#svc", Type = "Example", ServiceEndpoint = FlatMixedSet() }]
        });

        var resolved = await _method.ResolveAsync(created.Did.Value);

        var endpoint = resolved.DidDocument!.Service![0].ServiceEndpoint;
        endpoint.Set.Should().HaveCount(2);
        endpoint.Set![1].IsMap.Should().BeTrue();
    }

    private static JsonElement Wtf8String()
    {
        byte[] utf8 = [.. "\"a"u8.ToArray(), 0xED, 0xA0, 0x80, .. "b\""u8.ToArray()];
        using var document = JsonDocument.Parse(utf8);
        return document.RootElement.Clone();
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Issue145_Numalgo2Create_UndecodableJsonElement_ThrowsArgumentException(bool inExtension)
    {
        // JsonSerializer replaced the ill-formed bytes with U+FFFD inside the DID.
        var service = new Service
        {
            Id = "#svc",
            Type = "Example",
            ServiceEndpoint = inExtension
                ? ServiceEndpointValue.FromUri("https://example.com")
                : ServiceEndpointValue.FromMap(new Dictionary<string, JsonElement> { ["uri"] = Wtf8String() }),
            AdditionalProperties = inExtension
                ? new Dictionary<string, JsonElement> { ["accept"] = Wtf8String() }
                : null
        };

        var act = () => _method.CreateAsync(new DidPeerCreateOptions
        {
            Numalgo = PeerNumalgo.Two,
            Keys = [AuthenticationKey()],
            Services = [service]
        });

        await act.Should().ThrowAsync<ArgumentException>();
    }

    [Theory]
    [InlineData("serviceEndpoint")]
    [InlineData("s")]
    [InlineData("type")]
    [InlineData("t")]
    [InlineData("id")]
    [InlineData("a")]
    public async Task Issue145_Numalgo2Create_ExtensionKeyCollision_ThrowsArgumentException(string key)
    {
        // A colliding key overwrote the encoded member, so the DID encoded a different service than
        // the DidDocument Create returned. "a" collides with the abbreviated "accept" added first.
        var service = new Service
        {
            Id = "#svc",
            Type = "Example",
            ServiceEndpoint = ServiceEndpointValue.FromUri("https://good.example"),
            AdditionalProperties = new Dictionary<string, JsonElement>
            {
                ["accept"] = JsonSerializer.SerializeToElement(new[] { "didcomm/v2" }),
                [key] = JsonSerializer.SerializeToElement("https://evil.example")
            }
        };

        var act = () => _method.CreateAsync(new DidPeerCreateOptions
        {
            Numalgo = PeerNumalgo.Two,
            Keys = [AuthenticationKey()],
            Services = [service]
        });

        await act.Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public async Task Issue145_Control_Numalgo2Create_ExtensionKeys_RoundTrip()
    {
        var created = await _method.CreateAsync(new DidPeerCreateOptions
        {
            Numalgo = PeerNumalgo.Two,
            Keys = [AuthenticationKey()],
            Services =
            [
                new Service
                {
                    Id = "#svc",
                    Type = "DIDCommMessaging",
                    ServiceEndpoint = ServiceEndpointValue.FromUri("https://good.example"),
                    AdditionalProperties = new Dictionary<string, JsonElement>
                    {
                        ["accept"] = JsonSerializer.SerializeToElement(new[] { "didcomm/v2" }),
                        ["routingKeys"] = JsonSerializer.SerializeToElement(Array.Empty<string>())
                    }
                }
            ]
        });

        var service = (await _method.ResolveAsync(created.Did.Value)).DidDocument!.Service![0];

        service.ServiceEndpoint.Uri.Should().Be("https://good.example");
        service.AdditionalProperties.Should().ContainKeys("accept", "routingKeys");
    }

    // ── Resolution decodes the embedded JSON as strict UTF-8 (was lossy) ──

    [Fact]
    public async Task Issue145_Numalgo4Resolve_IllFormedUtf8_FailsClosed()
    {
        byte[] document = [.. """{"alsoKnownAs":["https://a.example/"""u8.ToArray(), 0xED, 0xA0, 0x80, .. "\"]}"u8.ToArray()];

        var resolved = await _method.ResolveAsync(EncodePeer4(document));

        resolved.DidDocument.Should().BeNull("ill-formed UTF-8 must not resolve as U+FFFD");
    }

    [Fact]
    public async Task Issue145_Numalgo2Resolve_IllFormedUtf8ServiceBlock_FailsClosed()
    {
        var created = await _method.CreateAsync(new DidPeerCreateOptions
        {
            Numalgo = PeerNumalgo.Two,
            Keys = [AuthenticationKey()]
        });
        byte[] block = [.. """{"t":"dm","s":"https://a.example/"""u8.ToArray(), 0xED, 0xA0, 0x80, .. "\"}"u8.ToArray()];
        var segment = Convert.ToBase64String(block).TrimEnd('=').Replace('+', '-').Replace('/', '_');

        var resolved = await _method.ResolveAsync(created.Did.Value + ".S" + segment);

        resolved.DidDocument.Should().BeNull("ill-formed UTF-8 must not resolve as U+FFFD");
    }

    [Fact]
    public async Task Issue145_Numalgo2Create_DefaultJsonElement_ThrowsArgumentException()
    {
        // Final adversarial pass: default(JsonElement) escaped as a raw InvalidOperationException.
        var act = () => _method.CreateAsync(new DidPeerCreateOptions
        {
            Numalgo = PeerNumalgo.Two,
            Keys = [AuthenticationKey()],
            Services =
            [
                new Service
                {
                    Id = "#svc",
                    Type = "Example",
                    ServiceEndpoint = ServiceEndpointValue.FromUri("https://example.com"),
                    AdditionalProperties = new Dictionary<string, JsonElement> { ["accept"] = default }
                }
            ]
        });

        await act.Should().ThrowAsync<ArgumentException>();
    }
}
