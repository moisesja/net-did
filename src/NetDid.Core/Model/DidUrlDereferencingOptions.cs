namespace NetDid.Core.Model;

public sealed record DidUrlDereferencingOptions
{
    /// <summary>The Media Type the caller prefers for the dereferenced content.</summary>
    public string? Accept { get; init; }

    /// <summary>
    /// Filter verification methods by relationship (e.g., "authentication", "assertionMethod").
    /// When set, fragment dereferencing only returns VMs present in the specified relationship.
    /// </summary>
    public string? VerificationRelationship { get; init; }
}
