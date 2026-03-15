using NetDid.Core.Model;

namespace NetDid.Method.WebVh.Model;

/// <summary>
/// A single entry in the did:webvh DID log (did.jsonl).
/// </summary>
public sealed class LogEntry
{
    /// <summary>Format: "{version-number}-{entry-hash}". For genesis: "1-{SCID}".</summary>
    public required string VersionId { get; set; }

    /// <summary>ISO 8601 timestamp of this entry.</summary>
    public required DateTimeOffset VersionTime { get; init; }

    /// <summary>Entry parameters (method version, SCID, updateKeys, etc.).</summary>
    public required LogEntryParameters Parameters { get; init; }

    /// <summary>The full DID Document at this version.</summary>
    public required DidDocument State { get; init; }

    /// <summary>Data Integrity Proofs for this entry.</summary>
    public IReadOnlyList<DataIntegrityProofValue>? Proof { get; set; }

    /// <summary>The version number extracted from the versionId.</summary>
    public int VersionNumber => int.Parse(VersionId.Split('-')[0]);

    /// <summary>The entry hash extracted from the versionId.</summary>
    public string EntryHash => VersionId[(VersionId.IndexOf('-') + 1)..];
}
