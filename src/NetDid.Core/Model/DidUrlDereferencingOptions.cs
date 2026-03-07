namespace NetDid.Core.Model;

public sealed record DidUrlDereferencingOptions
{
    /// <summary>The Media Type the caller prefers for the dereferenced content.</summary>
    public string? Accept { get; init; }
}
