using NetDid.Core.Model;

namespace NetDid.Method.Ethr;

public sealed record DidEthrCreateOptions : DidCreateOptions
{
    public override string MethodName => "ethr";
    public required string Network { get; init; }  // "mainnet", "sepolia", "0xaa36a7", etc.
    public NetDid.Core.ISigner? ExistingKey { get; init; }   // must be Secp256k1 if provided
}
