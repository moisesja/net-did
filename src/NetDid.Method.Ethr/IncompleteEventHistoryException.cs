using NetDid.Core.Exceptions;

namespace NetDid.Method.Ethr;

/// <summary>
/// The event-chain walk detected an incomplete history: a block asserted by
/// <c>changed()</c>/<c>previousChange</c> returned no matching ERC-1056 events
/// (pruned/non-archive or hostile RPC endpoint).
/// </summary>
/// <remarks>
/// Internal and sealed deliberately: the TYPE is trusted provenance. Resolution
/// derives fixed caller-facing metadata text from it, and because code outside this
/// assembly cannot instantiate it, an injected dependency can never steer that text
/// — unlike <see cref="EthereumInteractionException"/>, whose public constructor
/// makes any message arriving through an injectable seam untrusted.
/// </remarks>
internal sealed class IncompleteEventHistoryException(string message)
    : EthereumInteractionException(message);
