using FluentAssertions;
using NetDid.Core.Crypto;
using NetDid.Core.Model;
using NetDid.Method.Peer;

namespace NetDid.Method.Peer.Tests;

public class Numalgo2ServiceEncoderTests
{
    private readonly DefaultKeyGenerator _keyGen = new();
    private readonly DefaultCryptoProvider _crypto = new();

    [Fact]
    public async Task DIDCommMessaging_AbbreviationRoundTrip()
    {
        var method = new DidPeerMethod(_keyGen);
        var authKey = _keyGen.Generate(KeyType.Ed25519);

        var originalService = new Service
        {
            Id = "#didcomm",
            Type = "DIDCommMessaging",
            ServiceEndpoint = ServiceEndpointValue.FromUri("https://example.com/endpoint")
        };

        var result = await method.CreateAsync(new DidPeerCreateOptions
        {
            Numalgo = PeerNumalgo.Two,
            Keys =
            [
                new PeerKeyPurpose(new KeyPairSigner(authKey, _crypto), PeerPurpose.Authentication)
            ],
            Services = [originalService]
        });

        // The DID should contain 'S' for the service
        result.Did.Value.Should().Contain(".S");

        // Resolve and verify
        var resolved = await method.ResolveAsync(result.Did.Value);
        resolved.DidDocument!.Service.Should().HaveCount(1);
        var svc = resolved.DidDocument.Service![0];
        svc.Type.Should().Be("DIDCommMessaging");
        svc.ServiceEndpoint.IsUri.Should().BeTrue();
        svc.ServiceEndpoint.Uri.Should().Be("https://example.com/endpoint");
    }

    [Fact]
    public async Task MultipleServices_RoundTrip()
    {
        var method = new DidPeerMethod(_keyGen);
        var authKey = _keyGen.Generate(KeyType.Ed25519);

        var result = await method.CreateAsync(new DidPeerCreateOptions
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
                    Id = "#svc1",
                    Type = "DIDCommMessaging",
                    ServiceEndpoint = ServiceEndpointValue.FromUri("https://relay1.example.com")
                },
                new Service
                {
                    Id = "#svc2",
                    Type = "LinkedDomains",
                    ServiceEndpoint = ServiceEndpointValue.FromUri("https://example.com")
                }
            ]
        });

        var resolved = await method.ResolveAsync(result.Did.Value);
        resolved.DidDocument!.Service.Should().HaveCount(2);
        resolved.DidDocument.Service![0].Type.Should().Be("DIDCommMessaging");
        resolved.DidDocument.Service![1].Type.Should().Be("LinkedDomains");
    }

    [Fact]
    public async Task CustomServiceType_PreservedRoundTrip()
    {
        var method = new DidPeerMethod(_keyGen);
        var authKey = _keyGen.Generate(KeyType.Ed25519);

        var result = await method.CreateAsync(new DidPeerCreateOptions
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
                    Id = "#custom",
                    Type = "CustomService",
                    ServiceEndpoint = ServiceEndpointValue.FromUri("https://custom.example.com")
                }
            ]
        });

        var resolved = await method.ResolveAsync(result.Did.Value);
        resolved.DidDocument!.Service![0].Type.Should().Be("CustomService");
    }
}
