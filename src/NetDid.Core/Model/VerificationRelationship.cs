namespace NetDid.Core.Model;

/// <summary>
/// W3C DID Core §5.3 verification relationships. Each value maps to the corresponding
/// list on <see cref="DidDocument"/>.
/// </summary>
public enum VerificationRelationship
{
    Authentication,
    AssertionMethod,
    KeyAgreement,
    CapabilityInvocation,
    CapabilityDelegation
}

/// <summary>
/// Wire-format names (per W3C DID Core) for <see cref="VerificationRelationship"/> and
/// conversion helpers shared between the dereferencer and the relationship-authorization resolver.
/// </summary>
public static class VerificationRelationshipNames
{
    public const string Authentication = "authentication";
    public const string AssertionMethod = "assertionMethod";
    public const string KeyAgreement = "keyAgreement";
    public const string CapabilityInvocation = "capabilityInvocation";
    public const string CapabilityDelegation = "capabilityDelegation";

    /// <summary>Returns the W3C wire-format relationship name (e.g. "capabilityInvocation").</summary>
    public static string ToWireName(this VerificationRelationship relationship) => relationship switch
    {
        VerificationRelationship.Authentication => Authentication,
        VerificationRelationship.AssertionMethod => AssertionMethod,
        VerificationRelationship.KeyAgreement => KeyAgreement,
        VerificationRelationship.CapabilityInvocation => CapabilityInvocation,
        VerificationRelationship.CapabilityDelegation => CapabilityDelegation,
        _ => throw new ArgumentOutOfRangeException(nameof(relationship), relationship, null)
    };

    /// <summary>
    /// Parses a wire-format relationship name (case-sensitive per spec).
    /// Returns false for unknown names.
    /// </summary>
    public static bool TryParse(string? wireName, out VerificationRelationship relationship)
    {
        switch (wireName)
        {
            case Authentication: relationship = VerificationRelationship.Authentication; return true;
            case AssertionMethod: relationship = VerificationRelationship.AssertionMethod; return true;
            case KeyAgreement: relationship = VerificationRelationship.KeyAgreement; return true;
            case CapabilityInvocation: relationship = VerificationRelationship.CapabilityInvocation; return true;
            case CapabilityDelegation: relationship = VerificationRelationship.CapabilityDelegation; return true;
            default: relationship = default; return false;
        }
    }
}
