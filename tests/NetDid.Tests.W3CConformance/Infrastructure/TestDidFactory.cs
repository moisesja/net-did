using NetDid.Core;
using NetDid.Core.Crypto;
using NetDid.Core.Model;
using NetDid.Core.Resolution;
using NetDid.Method.Key;
using NetDid.Method.Peer;

namespace NetDid.Tests.W3CConformance.Infrastructure;

public sealed class TestDidFactory
{
    private readonly DefaultKeyGenerator _keyGen = new();
    private readonly DefaultCryptoProvider _crypto = new();
    private readonly DidKeyMethod _keyMethod;
    private readonly DidPeerMethod _peerMethod;

    public TestDidFactory()
    {
        _keyMethod = new DidKeyMethod(_keyGen);
        _peerMethod = new DidPeerMethod(_keyGen);
    }

    public async Task<(string Did, DidDocument Doc)> CreateDidKey(
        KeyType keyType = KeyType.Ed25519,
        VerificationMethodRepresentation repr = VerificationMethodRepresentation.Multikey)
    {
        var result = await _keyMethod.CreateAsync(new DidKeyCreateOptions
        {
            KeyType = keyType,
            Representation = repr
        });
        return (result.Did.Value, result.DidDocument);
    }

    public async Task<(string Did, DidDocument Doc)> CreateDidPeerNumalgo2WithService()
    {
        var authKey = _keyGen.Generate(KeyType.Ed25519);
        var agreeKey = _keyGen.Generate(KeyType.X25519);

        var result = await _peerMethod.CreateAsync(new DidPeerCreateOptions
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
                    Id = "#svc-1",
                    Type = "DIDCommMessaging",
                    ServiceEndpoint = ServiceEndpointValue.FromUri("https://example.com/endpoint")
                }
            ]
        });
        return (result.Did.Value, result.DidDocument);
    }

    public async Task<(string Did, DidDocument Doc)> CreateDidPeerNumalgo4WithController()
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
            Authentication = [VerificationRelationshipEntry.FromReference("#key-0")],
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

        var result = await _peerMethod.CreateAsync(new DidPeerCreateOptions
        {
            Numalgo = PeerNumalgo.Four,
            InputDocument = inputDoc
        });
        return (result.Did.Value, result.DidDocument);
    }

    public async Task<(string Did, DidDocument Doc)> CreateDid(string method)
    {
        return method switch
        {
            "did:key" => await CreateDidKey(),
            "did:peer" => await CreateDidPeerNumalgo2WithService(),
            _ => throw new ArgumentException($"Unknown method: {method}")
        };
    }

    public async Task<(string Did, DidDocument Doc)> CreateDidWithServices(string method)
    {
        return method switch
        {
            "did:peer" => await CreateDidPeerNumalgo2WithService(),
            _ => throw new ArgumentException($"Method {method} does not produce services in test fixtures")
        };
    }

    public async Task<(string Did, DidDocument Doc)> CreateDidWithController(string method)
    {
        return method switch
        {
            "did:peer" => await CreateDidPeerNumalgo4WithController(),
            _ => throw new ArgumentException($"Method {method} does not set controller in test fixtures")
        };
    }

    public IDidMethod GetMethod(string method) => method switch
    {
        "did:key" => _keyMethod,
        "did:peer" => _peerMethod,
        _ => throw new ArgumentException($"Unknown method: {method}")
    };

    public CompositeDidResolver CreateCompositeResolver()
        => new([_keyMethod, _peerMethod]);

    public DefaultDidUrlDereferencer CreateDereferencer()
        => new(CreateCompositeResolver());
}
