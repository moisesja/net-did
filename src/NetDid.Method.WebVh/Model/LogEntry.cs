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

    /// <summary>The full DID Document at this version.</summary>
    public required DidDocument State { get; init; }

    /// <summary>
    /// The entry's Data Integrity controller proofs. A did:webvh entry requires at least one
    /// controller proof, and one active update key is sufficient to authorize the entry. If
    /// multiple controller proofs are supplied, every supplied proof must be structurally
    /// valid, cryptographically valid, and signed by an active update key — validation rejects
    /// the entry if any supplied proof fails any check (issue #101). Controller proofs do not
    /// use threshold semantics. Each proof is restricted to the did:webvh controller-proof
    /// profile (see <see cref="DataIntegrityProofValue"/>); proofs carrying other Data Integrity
    /// features are rejected. The wire <c>proof</c> may be a single proof object or an array;
    /// both parse into this list.
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
