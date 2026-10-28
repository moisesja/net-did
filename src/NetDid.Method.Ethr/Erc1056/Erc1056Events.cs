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

/// <summary>
/// A DIDDelegateChanged or DIDAttributeChanged event whose bytes32 delegate type or name is not
/// valid UTF-8. ethr-did-resolver filters such an event out of the DID history: it is not
/// counted, changes nothing, and does not set versionId. Its previousChange still links the
/// history walk (issue #145).
/// </summary>
public sealed record FilteredEvent(
    string Identity,
    ulong PreviousChange,
    ulong BlockNumber) : Erc1056Event(Identity, PreviousChange, BlockNumber);

public sealed record AttributeChangedEvent(
    string Identity,
    string Name,
    byte[] Value,
    ulong ValidTo,
    ulong PreviousChange,
    ulong BlockNumber) : Erc1056Event(Identity, PreviousChange, BlockNumber);
