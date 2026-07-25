namespace NetDid.Method.Ethr.Erc1056;

/// <summary>Typed representations of ERC-1056 registry events.</summary>

public abstract record Erc1056Event(string Identity, ulong PreviousChange, ulong BlockNumber);

public sealed record OwnerChangedEvent(
    string Identity,
    string NewOwner,
    ulong PreviousChange,
    ulong BlockNumber) : Erc1056Event(Identity, PreviousChange, BlockNumber);

public sealed record DelegateChangedEvent(
    string Identity,
    string DelegateType,
    string Delegate,
    ulong ValidTo,
    ulong PreviousChange,
    ulong BlockNumber) : Erc1056Event(Identity, PreviousChange, BlockNumber);

public sealed record AttributeChangedEvent(
    string Identity,
    string Name,
    byte[] Value,
    ulong ValidTo,
    ulong PreviousChange,
    ulong BlockNumber) : Erc1056Event(Identity, PreviousChange, BlockNumber);
