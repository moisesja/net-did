using System.Globalization;
using NetDid.Core.Model;

namespace NetDid.Method.WebVh.Model;

/// <summary>
/// A single entry in the did:webvh DID log (did.jsonl).
/// </summary>
public sealed record LogEntry
{
    /// <summary>Format: "{version-number}-{entry-hash}".</summary>
    public required string VersionId { get; init; }

    /// <summary>ISO 8601 timestamp of this entry.</summary>
    public required DateTimeOffset VersionTime { get; init; }

    /// <summary>
    /// Exact timestamp text parsed from the log. Retained internally so hash/proof verification
    /// authenticates the wire value rather than a normalized equivalent representation.
    /// </summary>
    internal string? VersionTimeWireValue { get; init; }

    /// <summary>Exact JSON token for <see cref="VersionTimeWireValue"/>.</summary>
    internal string? VersionTimeRawJson { get; init; }

    /// <summary>Entry parameters (method version, SCID, updateKeys, etc.).</summary>
    public required LogEntryParameters Parameters { get; init; }

    /// <summary>
    /// The typed DID Document at this version. For a parsed log, hashing and proof verification
    /// also retain signed nested wire members that this typed model does not surface.
    /// </summary>
    public required DidDocument State { get; init; }

    /// <summary>
    /// The entry's Data Integrity controller proofs. A did:webvh entry requires at least one
    /// controller proof, and one active update key is sufficient to authorize the entry. Every
    /// supplied proof is processed by DataProofsDotnet and authorized against the active update
    /// keys; the entry is rejected if any supplied proof fails NetDid's controller policy (issue
    /// #101). Controller proofs do not use threshold semantics. Duplicate proof ids are rejected.
    /// Proof extensions are preserved and signature-bound; NetDid enforces documented semantics
    /// for <c>id</c>, <c>expires</c>, and
    /// <c>previousProof</c> but does not claim semantics for every extension (see
    /// <see cref="DataIntegrityProofValue"/>). The wire <c>proof</c> may be a single proof object or
    /// an array; both parse into this list, and serialization uses the array form.
    /// </summary>
    public IReadOnlyList<DataIntegrityProofValue>? Proof { get; init; }

    /// <summary>The version number extracted from the versionId.</summary>
    public int VersionNumber => int.Parse(
        VersionId.Split('-')[0],
        NumberStyles.None,
        CultureInfo.InvariantCulture);

    /// <summary>The entry hash extracted from the versionId.</summary>
    public string EntryHash => VersionId[(VersionId.IndexOf('-') + 1)..];
}
