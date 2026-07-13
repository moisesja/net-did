using FluentAssertions;
using NetCrypto;

namespace NetDid.Method.WebVh.Tests;

/// <summary>
/// Contract tests for the did:webvh authorization adapter. The resolver supplies the pipeline
/// only keys that are well-formed, Ed25519, and verbatim members of the active updateKeys;
/// every rejection returns null so the proof fails closed.
/// </summary>
public sealed class WebVhUpdateKeyResolverTests
{
    [Fact]
    public async Task Issue101_MalformedAuthorizedKey_FailsClosed()
    {
        // A log can declare a syntactically arbitrary string in updateKeys. A proof whose
        // did:key verificationMethod references it verbatim passes the membership check, but
        // the value is not a decodable Multikey — FromMultikey's documented ArgumentException
        // must resolve to null (unauthorized), not escape or authorize.
        const string malformed = "not-a-valid-multikey";
        var resolver = new WebVhUpdateKeyResolver([malformed]);

        var resolved = await resolver.ResolveAsync($"did:key:{malformed}#{malformed}");

        resolved.Should().BeNull();
    }

    [Fact]
    public async Task Issue101_WellFormedAuthorizedEd25519Key_Resolves()
    {
        var keyPair = new DefaultKeyGenerator().Generate(KeyType.Ed25519);
        var multibase = new KeyPairSigner(keyPair, new DefaultCryptoProvider()).MultibasePublicKey;
        var resolver = new WebVhUpdateKeyResolver([multibase]);

        var resolved = await resolver.ResolveAsync($"did:key:{multibase}#{multibase}");

        resolved.Should().NotBeNull();
        resolved!.PublicKey.KeyType.Should().Be(KeyType.Ed25519);
        resolved.Relationships.Should().BeEquivalentTo(["assertionMethod"]);
    }
}
