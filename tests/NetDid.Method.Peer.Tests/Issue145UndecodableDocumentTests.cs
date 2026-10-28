using System.Security.Cryptography;
using System.Text;
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
    {
        var longForm = Multibase.Encode(
            Multicodec.Prefix(0x0200, Encoding.UTF8.GetBytes(inputDocumentJson)),
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
}
