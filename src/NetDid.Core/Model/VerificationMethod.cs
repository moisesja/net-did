using Microsoft.IdentityModel.Tokens;

namespace NetDid.Core.Model;

public sealed class VerificationMethod
{
    /// <summary>DID URL (validated at deserialization).</summary>
    public required string Id { get; init; }

    /// <summary>"Multikey", "JsonWebKey2020", "EcdsaSecp256k1VerificationKey2019"</summary>
    public required string Type { get; init; }

    /// <summary>
    /// The DID of the controller. Required for resolved documents.
    /// May be omitted in input documents (e.g., did:peer:4) where the controller
    /// is inferred during contextualization.
    /// </summary>
    public Did Controller { get; init; }

    /// <summary>For Multikey representation.</summary>
    public string? PublicKeyMultibase { get; init; }

    /// <summary>For JWK representation.</summary>
    public JsonWebKey? PublicKeyJwk { get; init; }

    /// <summary>For did:ethr (CAIP-10 format).</summary>
    public string? BlockchainAccountId { get; init; }
}
