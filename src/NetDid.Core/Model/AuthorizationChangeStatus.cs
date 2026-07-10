namespace NetDid.Core.Model;

/// <summary>
/// Whether a <see cref="DidUpdateResult"/> reports a change to the DID method's authorization
/// material — for did:webvh: <c>updateKeys</c> / <c>nextKeyHashes</c> / <c>prerotation</c> /
/// <c>witness</c> config.
/// <para>
/// The default is <see cref="Unknown"/>, so absence of evidence fails closed. A method that does
/// not evaluate change evidence — including any third-party <see cref="NetDid.Core.IDidMethod"/>
/// implementation compiled without setting the property — leaves the value at <see cref="Unknown"/>.
/// A method-agnostic consumer enforcing a document-only postcondition must therefore require
/// <see cref="Unchanged"/> explicitly and reject both <see cref="Unknown"/> and <see cref="Changed"/>;
/// it must never treat "not reported" as "confirmed unchanged."
/// </para>
/// </summary>
public enum AuthorizationChangeStatus
{
    /// <summary>
    /// The method did not report whether authorization material changed. Treat as unsafe:
    /// a consumer enforcing a document-only update must reject this.
    /// </summary>
    Unknown = 0,

    /// <summary>The update did not change the method's authorization material.</summary>
    Unchanged = 1,

    /// <summary>The update changed the method's authorization material.</summary>
    Changed = 2,
}
