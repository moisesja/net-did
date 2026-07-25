using NetDid.Core.Model;

namespace NetDid.Method.Ethr;

/// <summary>
/// Resolution options for did:ethr.
/// VersionId (block number string) and VersionTime (ISO-8601) are inherited from base.
/// </summary>
public sealed record DidEthrResolveOptions : DidResolutionOptions;
