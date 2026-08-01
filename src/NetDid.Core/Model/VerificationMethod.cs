using System.Text.Json;
using Microsoft.IdentityModel.Tokens;

namespace NetDid.Core.Model;

public sealed class VerificationMethod
{
    /// <summary>DID URL (validated at deserialization).</summary>
    public required string Id { get; init; }

    /// <summary>"Multikey", "JsonWebKey2020", "EcdsaSecp256k1VerificationKey2019"</summary>
    public required string Type { get; init; }

    /// <summary>
    /// The DID of the controller. Per W3C DID Core §5.2 this property is REQUIRED on a
    /// verification method and MUST be stated explicitly — it does NOT default to, and cannot
    /// be inferred as, the DID subject. Consuming a resolved DID document that omits it
    /// throws (issue #121); the string path validates via the <see cref="Did"/> constructor.
    /// A <c>default(Did)</c> (null <see cref="Did.Value"/>) is permitted only as a transient,
    /// method-internal pre-contextualization state (e.g. a did:peer:4 template whose controller
    /// is derived from the DID at resolution time) and is never valid in a resolved document.
    /// </summary>
    public Did Controller { get; init; }

    /// <summary>For Multikey representation.</summary>
    public string? PublicKeyMultibase { get; init; }

    /// <summary>For JWK representation.</summary>
    public JsonWebKey? PublicKeyJwk { get; init; }

    /// <summary>For did:ethr (CAIP-10 format).</summary>
    public string? BlockchainAccountId { get; init; }

    /// <summary>Extension properties not defined in DID Core (e.g., publicKeyHex).</summary>
    public IReadOnlyDictionary<string, JsonElement>? AdditionalProperties { get; init; }
}
