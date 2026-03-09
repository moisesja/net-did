namespace NetDid.Method.WebVh.Model;

/// <summary>
/// The "parameters" block inside a did:webvh log entry.
/// For the genesis entry, all required fields are populated.
/// For subsequent entries, only changed parameters are included (unchanged = empty object {}).
/// </summary>
public sealed class LogEntryParameters
{
    /// <summary>Method version, e.g., "did:webvh:1.0".</summary>
    public string? Method { get; init; }

    /// <summary>The Self-Certifying Identifier. Required in genesis entry.</summary>
    public string? Scid { get; init; }

    /// <summary>Authorized update keys (multibase-encoded Ed25519 public keys).</summary>
    public IReadOnlyList<string>? UpdateKeys { get; init; }

    /// <summary>Whether pre-rotation is enabled.</summary>
    public bool? Prerotation { get; init; }

    /// <summary>Whether this DID has been deactivated.</summary>
    public bool? Deactivated { get; init; }

    /// <summary>Hashes of next update keys (for pre-rotation).</summary>
    public IReadOnlyList<string>? NextKeyHashes { get; init; }

    /// <summary>Whether the DID is portable (can be moved to another domain).</summary>
    public bool? Portable { get; init; }

    /// <summary>TTL in seconds for caching.</summary>
    public int? Ttl { get; init; }

    /// <summary>Witness configuration.</summary>
    public WitnessConfig? Witness { get; init; }

    /// <summary>
    /// Merge this parameter set with a previous one, producing the effective parameters.
    /// Non-null values in this instance override the previous values.
    /// </summary>
    public LogEntryParameters MergeWith(LogEntryParameters previous)
    {
        return new LogEntryParameters
        {
            Method = Method ?? previous.Method,
            Scid = Scid ?? previous.Scid,
            UpdateKeys = UpdateKeys ?? previous.UpdateKeys,
            Prerotation = Prerotation ?? previous.Prerotation,
            Deactivated = Deactivated ?? previous.Deactivated,
            NextKeyHashes = NextKeyHashes ?? previous.NextKeyHashes,
            Portable = Portable ?? previous.Portable,
            Ttl = Ttl ?? previous.Ttl,
            Witness = Witness ?? previous.Witness
        };
    }
}
