namespace NetDid.Core.Model;

/// <summary>
/// A verification relationship entry is either a reference (DID URL string) or an embedded
/// verification method — never both, never neither.
/// </summary>
public sealed class VerificationRelationshipEntry
{
    /// <summary>The referenced DID URL (set when IsReference == true).</summary>
    public string? Reference { get; }

    /// <summary>The embedded verification method (set when IsReference == false).</summary>
    public VerificationMethod? EmbeddedMethod { get; }

    public bool IsReference => Reference is not null;

    private VerificationRelationshipEntry(string? reference, VerificationMethod? embedded)
    {
        Reference = reference;
        EmbeddedMethod = embedded;
    }

    /// <summary>Create a reference entry (DID URL pointing to a verification method defined elsewhere).</summary>
    public static VerificationRelationshipEntry FromReference(string didUrl)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(didUrl);
        return new VerificationRelationshipEntry(didUrl, null);
    }

    /// <summary>Create an embedded entry (inline verification method definition).</summary>
    public static VerificationRelationshipEntry FromEmbedded(VerificationMethod method)
    {
        ArgumentNullException.ThrowIfNull(method);
        return new VerificationRelationshipEntry(null, method);
    }

    /// <summary>Implicit conversion from string for ergonomic reference creation.</summary>
    public static implicit operator VerificationRelationshipEntry(string didUrl) => FromReference(didUrl);
}
