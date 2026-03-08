using NetDid.Core;
using NetDid.Core.Model;
using NetDid.Core.Parsing;

namespace NetDid.Method.Peer;

/// <summary>
/// Implementation of the did:peer method supporting numalgo 0, 2, and 4.
/// </summary>
public sealed class DidPeerMethod : DidMethodBase
{
    private readonly Numalgo0Handler _numalgo0;
    private readonly Numalgo2Handler _numalgo2;
    private readonly Numalgo4Handler _numalgo4;

    public DidPeerMethod(IKeyGenerator keyGenerator)
    {
        ArgumentNullException.ThrowIfNull(keyGenerator);
        _numalgo0 = new Numalgo0Handler(keyGenerator);
        _numalgo2 = new Numalgo2Handler();
        _numalgo4 = new Numalgo4Handler();
    }

    public override string MethodName => "peer";
    public override DidMethodCapabilities Capabilities => DidMethodCapabilities.Create | DidMethodCapabilities.Resolve;

    protected override Task<DidCreateResult> CreateCoreAsync(DidCreateOptions options, CancellationToken ct)
    {
        if (options is not DidPeerCreateOptions peerOptions)
            throw new ArgumentException($"Options must be {nameof(DidPeerCreateOptions)}.", nameof(options));

        var result = peerOptions.Numalgo switch
        {
            PeerNumalgo.Zero => _numalgo0.Create(peerOptions),
            PeerNumalgo.Two => _numalgo2.Create(peerOptions),
            PeerNumalgo.Four => _numalgo4.Create(peerOptions),
            _ => throw new ArgumentException($"Unsupported numalgo: {peerOptions.Numalgo}")
        };

        return Task.FromResult(result);
    }

    protected override Task<DidResolutionResult> ResolveCoreAsync(
        string did, DidResolutionOptions? options, CancellationToken ct)
    {
        try
        {
            var methodSpecificId = DidParser.ExtractMethodSpecificId(did);
            if (string.IsNullOrEmpty(methodSpecificId) || methodSpecificId.Length < 2)
                return Task.FromResult(DidResolutionResult.InvalidDid(did));

            var numalgoChar = methodSpecificId[0];

            DidDocument? doc = numalgoChar switch
            {
                '0' => _numalgo0.Resolve(did, methodSpecificId),
                '2' => _numalgo2.Resolve(did, methodSpecificId),
                '4' => _numalgo4.Resolve(did, methodSpecificId),
                _ => null
            };

            if (doc is null)
                return Task.FromResult(DidResolutionResult.NotFound(did));

            return Task.FromResult(new DidResolutionResult
            {
                DidDocument = doc,
                ResolutionMetadata = new DidResolutionMetadata
                {
                    ContentType = DidContentTypes.JsonLd
                }
            });
        }
        catch (Exception)
        {
            return Task.FromResult(DidResolutionResult.InvalidDid(did));
        }
    }
}
