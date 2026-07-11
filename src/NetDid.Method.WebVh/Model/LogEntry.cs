using System.Globalization;
using NetDid.Core.Model;

namespace NetDid.Method.WebVh.Model;

/// <summary>
/// A single entry in the did:webvh DID log (did.jsonl).
/// </summary>
public sealed record LogEntry
{
    /// <summary>Format: "{version-number}-{entry-hash}". For genesis: "1-{SCID}".</summary>
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

    /// <summary>Data Integrity Proofs for this entry.</summary>
    public IReadOnlyList<DataIntegrityProofValue>? Proof { get; init; }

    /// <summary>The version number extracted from the versionId.</summary>
    public int VersionNumber => int.Parse(
        VersionId.Split('-')[0],
        NumberStyles.None,
        CultureInfo.InvariantCulture);

    /// <summary>The entry hash extracted from the versionId.</summary>
    public string EntryHash => VersionId[(VersionId.IndexOf('-') + 1)..];
}
