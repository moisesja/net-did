namespace NetDid.Core.Model;

public enum VerificationMethodRepresentation
{
    /// <summary>Uses "publicKeyMultibase" property.</summary>
    Multikey,

    /// <summary>Uses "publicKeyJwk" property.</summary>
    JsonWebKey2020
}
