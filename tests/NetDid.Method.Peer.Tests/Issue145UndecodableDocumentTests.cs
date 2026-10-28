using System.Security.Cryptography;
using System.Text;
using AwesomeAssertions;
using NetCid;
using NetCrypto;
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
}
