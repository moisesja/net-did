using NetDid.Core.Model;

namespace NetDid.Method.WebVh;

/// <summary>
/// Resolution options for did:webvh.
/// VersionId and VersionTime are inherited from the base DidResolutionOptions.
/// </summary>
public sealed record DidWebVhResolveOptions : DidResolutionOptions;
