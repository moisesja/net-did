using System.Text;
using NetDid.Core;
using NetDid.Core.Crypto;
using NetDid.Core.Model;
using NetDid.Core.Resolution;
using NetDid.Method.Ethr;
using NetDid.Method.Ethr.Erc1056;
using NetDid.Method.Ethr.Rpc;
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
    private readonly MockEthereumRpcClient _mockEthrRpc = new();
    private readonly DidEthrMethod _ethrMethod;

    public TestDidFactory()
    {
        _keyMethod = new DidKeyMethod(_keyGen);
        _peerMethod = new DidPeerMethod(_keyGen);
        _webVhMethod = new DidWebVhMethod(_webVhHttpClient, _crypto);
        _ethrMethod = new DidEthrMethod(
            new MockEthereumRpcClientFactory(_mockEthrRpc),
            [KnownNetworks.Mainnet with { RpcUrl = "http://localhost" }],
            _keyGen);
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
            VerificationMethod =
            [
                new VerificationMethod
                {
                    Id = "#key-0",
                    Type = "Multikey",
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
        var logContent = (string)result.Artifacts!["did.jsonl"];
        var logUrl = DidUrlMapper.MapToLogUrl(result.Did.Value);
        _webVhHttpClient.SetLogResponse(logUrl, Encoding.UTF8.GetBytes(logContent));

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
        var logContent = (string)result.Artifacts!["did.jsonl"];
        var logUrl = DidUrlMapper.MapToLogUrl(result.Did.Value);
        _webVhHttpClient.SetLogResponse(logUrl, Encoding.UTF8.GetBytes(logContent));

        return (result.Did.Value, result.DidDocument);
    }

    public async Task<(string Did, DidDocument Doc)> CreateDidEthr()
    {
        // changed() returns 0 by default → resolver returns default document (no events needed)
        var result = await _ethrMethod.CreateAsync(new DidEthrCreateOptions { Network = "mainnet" });
        return (result.Did.Value, result.DidDocument);
    }

    /// <summary>
    /// Creates a did:ethr DID whose method-specific ID is a compressed secp256k1 public key.
    /// The resolved document includes a #controllerKey VM with publicKeyJwk (no private material).
    /// </summary>
    public async Task<(string Did, DidDocument Doc)> CreateDidEthrWithPubkey()
    {
        var keyPair   = _keyGen.Generate(KeyType.Secp256k1);
        var pubkeyHex = Convert.ToHexString(keyPair.PublicKey).ToLowerInvariant();
        var did       = $"did:ethr:mainnet:0x{pubkeyHex}";
        // changed() returns 0 → no events → #controller + #controllerKey
        var result = await _ethrMethod.ResolveAsync(did);
        return (did, result.DidDocument!);
    }

    public async Task<(string Did, DidDocument Doc)> CreateDidEthrWithService()
    {
        // 1. Create DID (random key → deterministic address for this run)
        var createResult = await _ethrMethod.CreateAsync(new DidEthrCreateOptions { Network = "mainnet" });
        var did = createResult.Did.Value!;
        var address = did[(did.LastIndexOf(':') + 1)..]; // "0x..."

        // 2. Wire mock: changed() returns block 100 for this address;
        //    block 100 carries a DIDAttributeChanged service event
        const ulong svcBlock = 100;
        _mockEthrRpc.SetChanged(address, svcBlock);
        _mockEthrRpc.AddLog(svcBlock, BuildServiceAttributeLog(address));

        // 3. Resolve to obtain the document that now includes the service
        var resolved = await _ethrMethod.ResolveAsync(did);
        return (did, resolved.DidDocument!);
    }

    public async Task<(string Did, DidDocument Doc)> CreateDid(string method)
    {
        return method switch
        {
            "did:key"   => await CreateDidKey(),
            "did:peer"  => await CreateDidPeerNumalgo2WithService(),
            "did:webvh" => await CreateDidWebVh(),
            "did:ethr"  => await CreateDidEthr(),
            _ => throw new ArgumentException($"Unknown method: {method}")
        };
    }

    public async Task<(string Did, DidDocument Doc)> CreateDidWithServices(string method)
    {
        return method switch
        {
            "did:peer"  => await CreateDidPeerNumalgo2WithService(),
            "did:webvh" => await CreateDidWebVhWithService(),
            "did:ethr"  => await CreateDidEthrWithService(),
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
        "did:key"   => _keyMethod,
        "did:peer"  => _peerMethod,
        "did:webvh" => _webVhMethod,
        "did:ethr"  => _ethrMethod,
        _ => throw new ArgumentException($"Unknown method: {method}")
    };

    public CompositeDidResolver CreateCompositeResolver()
        => new([_keyMethod, _peerMethod, _webVhMethod, _ethrMethod]);

    public DefaultDidUrlDereferencer CreateDereferencer()
        => new(CreateCompositeResolver());

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// <summary>
    /// Builds a DIDAttributeChanged log entry for a service endpoint,
    /// using the ABI encoding verified in AbiDecoderTests.
    /// </summary>
    private static EthereumLogEntry BuildServiceAttributeLog(string identityAddress)
    {
        const string serviceName     = "AgentService";
        const string serviceEndpoint = "https://agent.example.com/api";
        const ulong  validTo         = 9_999_999_999UL; // far future

        var nameBytes    = new byte[32];
        Encoding.ASCII.GetBytes($"did/svc/{serviceName}").CopyTo(nameBytes, 0);

        var valueBytes   = Encoding.UTF8.GetBytes(serviceEndpoint);
        var paddedLen    = ((valueBytes.Length + 31) / 32) * 32;

        // Layout: name(32) | valueOffset(32) | validTo(32) | prev(32) | length(32) | value(padded)
        var data = new byte[5 * 32 + paddedLen];
        nameBytes.CopyTo(data, 0);
        data[32 + 31] = (byte)(4 * 32);                               // valueOffset = 128
        WriteUlong(data, 2 * 32, validTo);
        // previousChange = 0 (already zeroed)
        data[4 * 32 + 31] = (byte)valueBytes.Length;
        valueBytes.CopyTo(data, 5 * 32);

        var addrHex = identityAddress.StartsWith("0x") ? identityAddress[2..] : identityAddress;
        return new EthereumLogEntry
        {
            Address     = "0xdCa7EF03e98e0DC2B855bE647C39ABe984fcF21B",
            Topics      = [Erc1056Topics.DIDAttributeChanged, "0x" + addrHex.PadLeft(64, '0')],
            Data        = "0x" + Convert.ToHexString(data).ToLowerInvariant(),
            BlockNumber = "0x64", // block 100
        };
    }

    private static void WriteUlong(byte[] buf, int offset, ulong value)
    {
        for (var i = 7; i >= 0; i--)
        {
            buf[offset + 31 - (7 - i)] = (byte)(value >> (i * 8));
        }
    }

    /// <summary>Minimal in-memory Ethereum RPC mock for did:ethr conformance tests.</summary>
    private sealed class MockEthereumRpcClient : IEthereumRpcClient
    {
        private readonly Dictionary<string, ulong> _changedByAddress =
            new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<ulong, List<EthereumLogEntry>> _logsByBlock = new();

        public void SetChanged(string address, ulong block)
            => _changedByAddress[address] = block;

        public void AddLog(ulong block, EthereumLogEntry log)
        {
            if (!_logsByBlock.TryGetValue(block, out var list))
                _logsByBlock[block] = list = [];
            list.Add(log);
        }

        public Task<string> CallAsync(string to, string data, CancellationToken ct = default)
        {
            // Calldata: 4-byte selector + 12 zero bytes + 20-byte address (total 36 bytes = 72 hex chars)
            var clean = data.StartsWith("0x") ? data[2..] : data;
            if (clean.Length >= 72)
            {
                var addrHex = "0x" + clean[^40..].ToLowerInvariant();
                if (_changedByAddress.TryGetValue(addrHex, out var block))
                    return Task.FromResult("0x" + block.ToString("x64"));
            }
            return Task.FromResult("0x" + new string('0', 64));
        }

        public Task<IReadOnlyList<EthereumLogEntry>> GetLogsAsync(
            EthereumLogFilter filter, CancellationToken ct = default)
        {
            IReadOnlyList<EthereumLogEntry> result =
                _logsByBlock.TryGetValue(filter.FromBlock, out var logs) ? logs : [];
            return Task.FromResult(result);
        }

        public Task<ulong> GetBlockNumberAsync(CancellationToken ct = default)
            => Task.FromResult(1000UL);
        public Task<ulong> GetChainIdAsync(CancellationToken ct = default)
            => Task.FromResult(1UL);
        public Task<ulong> GetBlockTimestampAsync(ulong blockNumber, CancellationToken ct = default)
            => Task.FromResult(0UL);
        public Task<string> SendRawTransactionAsync(byte[] tx, CancellationToken ct = default)
            => throw new NotImplementedException();
        public Task<ulong> GetTransactionCountAsync(string address, CancellationToken ct = default)
            => throw new NotImplementedException();
        public Task<ulong> GetGasPriceAsync(CancellationToken ct = default)
            => throw new NotImplementedException();
    }

    /// <summary>Factory wrapper that always returns the same mock client.</summary>
    private sealed class MockEthereumRpcClientFactory : IEthereumRpcClientFactory
    {
        private readonly IEthereumRpcClient _client;
        internal MockEthereumRpcClientFactory(IEthereumRpcClient client) => _client = client;
        public IEthereumRpcClient GetOrCreate(EthereumNetworkConfig network) => _client;
    }

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
