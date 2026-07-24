namespace NetDid.Core.Model;

/// <summary>
/// Extension methods over <see cref="DidDocument"/> that keep the record itself a pure data shape.
/// </summary>
public static class DidDocumentExtensions
{
    /// <summary>
    /// Returns the verification-relationship list for the supplied relationship, or null when the
    /// document does not declare that relationship. The returned list may be empty.
    /// </summary>
    public static IReadOnlyList<VerificationRelationshipEntry>? GetRelationshipEntries(
        this DidDocument document, VerificationRelationship relationship)
    {
        ArgumentNullException.ThrowIfNull(document);
        return relationship switch
        {
            VerificationRelationship.Authentication => document.Authentication,
            VerificationRelationship.AssertionMethod => document.AssertionMethod,
            VerificationRelationship.KeyAgreement => document.KeyAgreement,
            VerificationRelationship.CapabilityInvocation => document.CapabilityInvocation,
            VerificationRelationship.CapabilityDelegation => document.CapabilityDelegation,
            _ => throw new ArgumentOutOfRangeException(nameof(relationship), relationship, null)
        };
    }

    /// <summary>
    /// String overload accepting W3C wire-format relationship names. Returns null when the document
    /// does not declare the relationship; returns null also for unknown names.
    /// </summary>
    public static IReadOnlyList<VerificationRelationshipEntry>? GetRelationshipEntries(
        this DidDocument document, string relationshipWireName)
    {
        ArgumentNullException.ThrowIfNull(document);
        return VerificationRelationshipNames.TryParse(relationshipWireName, out var rel)
            ? document.GetRelationshipEntries(rel)
            : null;
    }
}
