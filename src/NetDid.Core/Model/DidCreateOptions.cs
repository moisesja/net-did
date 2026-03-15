namespace NetDid.Core.Model;

/// <summary>Base class for create options. Each DID method defines its own derived type.</summary>
public abstract record DidCreateOptions
{
    /// <summary>The DID method name this options type targets (e.g., "key", "peer", "webvh").</summary>
    public abstract string MethodName { get; }
}
