using NetDid.Core;
using NetDid.Core.Crypto;
using NetDid.Core.Model;
using NetDid.Core.Resolution;
using NetDid.Method.Key;
using NetDid.Method.Peer;
using NetDid.Method.WebVh;

namespace NetDid.Tests.W3CConformance.Infrastructure;

public sealed class TestDidFactory
{
    private readonly DefaultKeyGenerator _keyGen = new();
    private readonly DefaultCryptoProvider _crypto = new();
    private readonly DidKeyMethod _keyMethod;
    private readonly DidPeerMethod _peerMethod;
    private readonly DidWebVhMethod _webVhMethod;
    private readonly MockWebVhHttpClient _webVhHttpClient = new();

    public TestDidFactory()
    {
        _keyMethod = new DidKeyMethod(_keyGen);
        _peerMethod = new DidPeerMethod(_keyGen);
        _webVhMethod = new DidWebVhMethod(_webVhHttpClient, _crypto);
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

    public async Task<(string Did, DidDocument Doc)> CreateDidWebVh()
    {
        var keyPair = _keyGen.Generate(KeyType.Ed25519);
        var signer = new KeyPairSigner(keyPair, _crypto);

        var result = await _webVhMethod.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = signer
        });

        // Set up mock HTTP so resolve works
        var logContent = (byte[])result.Artifacts!["did.jsonl"];
        var logUrl = DidUrlMapper.MapToLogUrl(result.Did.Value);
        _webVhHttpClient.SetLogResponse(logUrl, logContent);

        return (result.Did.Value, result.DidDocument);
    }

    public async Task<(string Did, DidDocument Doc)> CreateDidWebVhWithService()
    {
        var keyPair = _keyGen.Generate(KeyType.Ed25519);
        var signer = new KeyPairSigner(keyPair, _crypto);

        var result = await _webVhMethod.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = signer,
            Services =
            [
                new Service
                {
                    Id = "#svc-1",
                    Type = "TurtleShellPds",
                    ServiceEndpoint = ServiceEndpointValue.FromUri("https://example.com/pds")
                }
            ]
        });

        // Set up mock HTTP so resolve works
        var logContent = (byte[])result.Artifacts!["did.jsonl"];
        var logUrl = DidUrlMapper.MapToLogUrl(result.Did.Value);
        _webVhHttpClient.SetLogResponse(logUrl, logContent);

        return (result.Did.Value, result.DidDocument);
    }

    public async Task<(string Did, DidDocument Doc)> CreateDid(string method)
    {
        return method switch
        {
            "did:key" => await CreateDidKey(),
            "did:peer" => await CreateDidPeerNumalgo2WithService(),
            "did:webvh" => await CreateDidWebVh(),
            _ => throw new ArgumentException($"Unknown method: {method}")
        };
    }

    public async Task<(string Did, DidDocument Doc)> CreateDidWithServices(string method)
    {
        return method switch
        {
            "did:peer" => await CreateDidPeerNumalgo2WithService(),
            "did:webvh" => await CreateDidWebVhWithService(),
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
        "did:webvh" => _webVhMethod,
        _ => throw new ArgumentException($"Unknown method: {method}")
    };

    public CompositeDidResolver CreateCompositeResolver()
        => new([_keyMethod, _peerMethod, _webVhMethod]);

    public DefaultDidUrlDereferencer CreateDereferencer()
        => new(CreateCompositeResolver());

    /// <summary>In-memory mock HTTP client for did:webvh tests.</summary>
    private sealed class MockWebVhHttpClient : IWebVhHttpClient
    {
        private readonly Dictionary<string, byte[]> _logResponses = new();

        public void SetLogResponse(Uri url, byte[] content)
            => _logResponses[url.ToString()] = content;

        public Task<byte[]?> FetchDidLogAsync(Uri url, CancellationToken ct = default)
            => Task.FromResult(_logResponses.GetValueOrDefault(url.ToString()));

        public Task<byte[]?> FetchWitnessFileAsync(Uri url, CancellationToken ct = default)
            => Task.FromResult<byte[]?>(null);
    }
}
