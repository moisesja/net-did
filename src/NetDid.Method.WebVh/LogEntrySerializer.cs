using System.Text;
using System.Text.Json;
using NetDid.Core;
using NetDid.Core.Model;
using NetDid.Core.Serialization;
using NetDid.Method.WebVh.Model;

namespace NetDid.Method.WebVh;

/// <summary>
/// Serializes/deserializes log entries to/from JSON, and parses/generates JSON Lines (did.jsonl).
/// </summary>
public static class LogEntrySerializer
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
        WriteIndented = false
    };

    /// <summary>Parse a did.jsonl file (byte[]) into a list of LogEntry objects.</summary>
    public static IReadOnlyList<LogEntry> ParseJsonLines(byte[] content)
    {
        var text = Encoding.UTF8.GetString(content);
        var lines = text.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var entries = new List<LogEntry>(lines.Length);

        foreach (var line in lines)
        {
            entries.Add(DeserializeEntry(line));
        }

        return entries;
    }

    /// <summary>Serialize a single log entry to JSON string.</summary>
    public static string Serialize(LogEntry entry)
    {
        return WriteEntry(entry, includeProof: true);
    }

    /// <summary>Serialize a single log entry to JSON, excluding the proof field (for hashing/signing).</summary>
    public static string SerializeWithoutProof(LogEntry entry)
    {
        return WriteEntry(entry, includeProof: false);
    }

    /// <summary>Serialize a list of log entries to JSON Lines format (byte[]).</summary>
    public static byte[] ToJsonLines(IReadOnlyList<LogEntry> entries)
    {
        var sb = new StringBuilder();
        for (int i = 0; i < entries.Count; i++)
        {
            if (i > 0) sb.Append('\n');
            sb.Append(Serialize(entries[i]));
        }
        return Encoding.UTF8.GetBytes(sb.ToString());
    }

    private static string WriteEntry(LogEntry entry, bool includeProof)
    {
        using var stream = new MemoryStream();
        using var writer = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = false });

        writer.WriteStartObject();

        // versionId
        writer.WriteString("versionId", entry.VersionId);

        // versionTime — ISO 8601 UTC
        writer.WriteString("versionTime", entry.VersionTime.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"));

        // parameters
        writer.WritePropertyName("parameters");
        WriteParameters(writer, entry.Parameters);

        // state — the DID Document, serialized as JSON-LD
        writer.WritePropertyName("state");
        var stateJson = DidDocumentSerializer.Serialize(entry.State, DidContentTypes.JsonLd);
        using (var stateDoc = JsonDocument.Parse(stateJson))
        {
            stateDoc.RootElement.WriteTo(writer);
        }

        // proof (optional)
        if (includeProof && entry.Proof is { Count: > 0 })
        {
            writer.WritePropertyName("proof");
            WriteProofArray(writer, entry.Proof);
        }

        writer.WriteEndObject();
        writer.Flush();

        return Encoding.UTF8.GetString(stream.ToArray());
    }

    private static void WriteParameters(Utf8JsonWriter writer, LogEntryParameters parameters)
    {
        writer.WriteStartObject();

        if (parameters.Method is not null)
            writer.WriteString("method", parameters.Method);
        if (parameters.Scid is not null)
            writer.WriteString("scid", parameters.Scid);
        if (parameters.UpdateKeys is not null)
        {
            writer.WritePropertyName("updateKeys");
            writer.WriteStartArray();
            foreach (var key in parameters.UpdateKeys)
                writer.WriteStringValue(key);
            writer.WriteEndArray();
        }
        if (parameters.Prerotation.HasValue)
            writer.WriteBoolean("prerotation", parameters.Prerotation.Value);
        if (parameters.Deactivated.HasValue)
            writer.WriteBoolean("deactivated", parameters.Deactivated.Value);
        if (parameters.NextKeyHashes is not null)
        {
            writer.WritePropertyName("nextKeyHashes");
            writer.WriteStartArray();
            foreach (var hash in parameters.NextKeyHashes)
                writer.WriteStringValue(hash);
            writer.WriteEndArray();
        }
        if (parameters.Portable.HasValue)
            writer.WriteBoolean("portable", parameters.Portable.Value);
        if (parameters.Ttl.HasValue)
            writer.WriteNumber("ttl", parameters.Ttl.Value);
        if (parameters.Witness is not null)
        {
            writer.WritePropertyName("witness");
            WriteWitnessConfig(writer, parameters.Witness);
        }

        writer.WriteEndObject();
    }

    private static void WriteWitnessConfig(Utf8JsonWriter writer, WitnessConfig config)
    {
        writer.WriteStartObject();
        writer.WriteNumber("threshold", config.Threshold);
        if (config.Witnesses is { Count: > 0 })
        {
            writer.WritePropertyName("witnesses");
            writer.WriteStartArray();
            foreach (var w in config.Witnesses)
            {
                writer.WriteStartObject();
                writer.WriteString("id", w.Id);
                writer.WriteNumber("weight", w.Weight);
                writer.WriteEndObject();
            }
            writer.WriteEndArray();
        }
        writer.WriteEndObject();
    }

    private static void WriteProofArray(Utf8JsonWriter writer, IReadOnlyList<DataIntegrityProofValue> proofs)
    {
        writer.WriteStartArray();
        foreach (var proof in proofs)
        {
            writer.WriteStartObject();
            writer.WriteString("type", proof.Type);
            writer.WriteString("cryptosuite", proof.Cryptosuite);
            writer.WriteString("verificationMethod", proof.VerificationMethod);
            writer.WriteString("created", proof.Created);
            writer.WriteString("proofPurpose", proof.ProofPurpose);
            writer.WriteString("proofValue", proof.ProofValue);
            writer.WriteEndObject();
        }
        writer.WriteEndArray();
    }

    internal static LogEntry DeserializeEntry(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        var versionId = root.GetProperty("versionId").GetString()!;
        var versionTime = root.GetProperty("versionTime").GetString()!;
        var parameters = ParseParameters(root.GetProperty("parameters"));

        // Parse state as a DID Document
        var stateJson = root.GetProperty("state").GetRawText();
        var state = DidDocumentSerializer.Deserialize(stateJson);

        // Parse proof array (optional)
        IReadOnlyList<DataIntegrityProofValue>? proof = null;
        if (root.TryGetProperty("proof", out var proofProp))
        {
            proof = ParseProofArray(proofProp);
        }

        return new LogEntry
        {
            VersionId = versionId,
            VersionTime = DateTimeOffset.Parse(versionTime),
            Parameters = parameters,
            State = state,
            Proof = proof
        };
    }

    private static LogEntryParameters ParseParameters(JsonElement element)
    {
        string? method = null;
        string? scid = null;
        IReadOnlyList<string>? updateKeys = null;
        bool? prerotation = null;
        bool? deactivated = null;
        IReadOnlyList<string>? nextKeyHashes = null;
        bool? portable = null;
        int? ttl = null;
        WitnessConfig? witness = null;

        if (element.TryGetProperty("method", out var m))
            method = m.GetString();
        if (element.TryGetProperty("scid", out var s))
            scid = s.GetString();
        if (element.TryGetProperty("updateKeys", out var uk))
            updateKeys = uk.EnumerateArray().Select(e => e.GetString()!).ToList();
        if (element.TryGetProperty("prerotation", out var pr))
            prerotation = pr.GetBoolean();
        if (element.TryGetProperty("deactivated", out var d))
            deactivated = d.GetBoolean();
        if (element.TryGetProperty("nextKeyHashes", out var nkh))
            nextKeyHashes = nkh.EnumerateArray().Select(e => e.GetString()!).ToList();
        if (element.TryGetProperty("portable", out var p))
            portable = p.GetBoolean();
        if (element.TryGetProperty("ttl", out var t))
            ttl = t.GetInt32();
        if (element.TryGetProperty("witness", out var w))
            witness = ParseWitnessConfig(w);

        return new LogEntryParameters
        {
            Method = method,
            Scid = scid,
            UpdateKeys = updateKeys,
            Prerotation = prerotation,
            Deactivated = deactivated,
            NextKeyHashes = nextKeyHashes,
            Portable = portable,
            Ttl = ttl,
            Witness = witness
        };
    }

    private static WitnessConfig ParseWitnessConfig(JsonElement element)
    {
        var threshold = element.GetProperty("threshold").GetInt32();
        List<WitnessEntry>? witnesses = null;

        if (element.TryGetProperty("witnesses", out var w))
        {
            witnesses = w.EnumerateArray().Select(e => new WitnessEntry
            {
                Id = e.GetProperty("id").GetString()!,
                Weight = e.TryGetProperty("weight", out var wt) ? wt.GetInt32() : 1
            }).ToList();
        }

        return new WitnessConfig
        {
            Threshold = threshold,
            Witnesses = witnesses
        };
    }

    private static IReadOnlyList<DataIntegrityProofValue> ParseProofArray(JsonElement element)
    {
        return element.EnumerateArray().Select(e => new DataIntegrityProofValue
        {
            Type = e.GetProperty("type").GetString()!,
            Cryptosuite = e.GetProperty("cryptosuite").GetString()!,
            VerificationMethod = e.GetProperty("verificationMethod").GetString()!,
            Created = e.GetProperty("created").GetString()!,
            ProofPurpose = e.GetProperty("proofPurpose").GetString()!,
            ProofValue = e.GetProperty("proofValue").GetString()!
        }).ToList();
    }
}
