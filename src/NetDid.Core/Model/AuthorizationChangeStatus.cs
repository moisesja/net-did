namespace NetDid.Core.Model;

/// <summary>
/// Whether a <see cref="DidUpdateResult"/> reports a change to the piece of authorization state
/// the carrying property describes: for <see cref="DidUpdateResult.AuthorizationChange"/>, any of
/// the method's authorization material (did:webvh: <c>updateKeys</c> / <c>nextKeyHashes</c> /
/// <c>prerotation</c> / <c>witness</c> config); for
/// <see cref="DidUpdateResult.UpdateKeyChange"/>, specifically the effective set of authorized
/// update keys.
/// <para>
/// The default is <see cref="Unknown"/>, so absence of evidence fails closed. A method that does
/// not evaluate change evidence — including any third-party <see cref="NetDid.Core.IDidMethod"/>
/// implementation compiled without setting the property — leaves the value at <see cref="Unknown"/>.
/// A method-agnostic consumer enforcing a postcondition must therefore require the specific value
/// it needs explicitly and reject <see cref="Unknown"/>; it must never treat "not reported" as
/// "confirmed unchanged."
/// </para>
/// </summary>
public enum AuthorizationChangeStatus
{
    /// <summary>
    /// The method did not report whether the state the carrying property describes changed.
    /// Treat as unsafe: a consumer enforcing a postcondition on that state must reject this.
    /// </summary>
    Unknown = 0,

    /// <summary>The update did not change the state the carrying property describes.</summary>
    Unchanged = 1,

    /// <summary>The update changed the state the carrying property describes.</summary>
    Changed = 2,
}
