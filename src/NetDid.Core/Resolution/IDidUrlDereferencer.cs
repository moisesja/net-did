using NetDid.Core.Model;

namespace NetDid.Core.Resolution;

/// <summary>
/// W3C DID Core §7.2: Dereference a DID URL to the resource it identifies.
/// </summary>
public interface IDidUrlDereferencer
{
    Task<DidUrlDereferencingResult> DereferenceAsync(
        string didUrl,
        DidUrlDereferencingOptions? options = null,
        CancellationToken ct = default);
}
