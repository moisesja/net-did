using System.Runtime.CompilerServices;
using System.Security.Cryptography;
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
    private static readonly UTF8Encoding StrictUtf8 = new(
        encoderShouldEmitUTF8Identifier: false,
        throwOnInvalidBytes: true);

    // Wire provenance is reference-identity metadata, not part of the public LogEntry value.
    // A `with` clone deliberately has no provenance. The modeled fingerprint also detects
    // in-place mutation through public nested collections before raw-backed serialization.
    private static readonly ConditionalWeakTable<LogEntry, WireEntry> WireEntries = new();

    // State-level provenance, keyed by the parsed DidDocument reference. A freshly built entry
    // that carries a parsed state — a preserve-mode update's new head — must republish that
    // state verbatim: the typed model drops signed nested members it does not surface, and the
    // new head is hashed/signed over whatever is emitted here, so a modeled rewrite would
    // silently erase them. Guard rules: a `with`-cloned document is a new reference with no
    // provenance (modeled fallback), and any model-visible change invalidates the fingerprint
    // (modeled fallback). The fingerprint is over the lossy modeled serialization, so a
    // model-invisible in-place change (a nested raw-only member, or replacing a list element
    // with a model-equal one) is NOT detected and stale raw would be re-emitted — but that is
    // unreachable through a signed path: the only WireStates-registered document that reaches a
    // signed head is the internal previousEntry.State parsed from the fetched log (no caller
    // reference), and a caller-supplied NewDocument is deep-copied by
    // DidWebVhMethod.SnapshotDocument, which produces a fresh unregistered reference.
    private static readonly ConditionalWeakTable<DidDocument, WireState> WireStates = new();

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
        WriteIndented = false
    };

    /// <summary>Parse a did.jsonl file (byte[]) into a list of LogEntry objects.</summary>
    public static IReadOnlyList<LogEntry> ParseJsonLines(byte[] content)
    {
        var text = DecodeUtf8(content);
        var lines = text.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var entries = new List<LogEntry>(lines.Length);

        foreach (var line in lines)
        {
            entries.Add(DeserializeEntry(line));
        }

        return entries.AsReadOnly();
    }

    /// <summary>Serialize a single log entry to JSON string.</summary>
    public static string Serialize(LogEntry entry)
    {
        return WriteEntry(entry, includeProof: true, versionIdOverride: null);
    }

    /// <summary>Serialize a single log entry to JSON, excluding the proof field (for hashing/signing).</summary>
    public static string SerializeWithoutProof(LogEntry entry)
    {
        return WriteEntry(entry, includeProof: false, versionIdOverride: null);
    }

    /// <summary>
    /// Serialize an entry without its proof while replacing only the top-level version id.
    /// Parsed-wire provenance, when still current, remains the source for every other member.
    /// </summary>
    internal static string SerializeWithoutProof(LogEntry entry, string versionIdOverride)
    {
        ArgumentNullException.ThrowIfNull(versionIdOverride);
        return WriteEntry(
            entry,
            includeProof: false,
            versionIdOverride: versionIdOverride);
    }

    /// <summary>Decode fetched JSON bytes as strict UTF-8.</summary>
    internal static string DecodeUtf8(byte[] content)
    {
        try
        {
            return StrictUtf8.GetString(content);
        }
        catch (DecoderFallbackException ex)
        {
            throw new FormatException("did:webvh content is not valid UTF-8.", ex);
        }
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

    private static string WriteEntry(
        LogEntry entry,
        bool includeProof,
        string? versionIdOverride)
    {
        if (TryGetCurrentWireEntry(entry, out var wireEntry))
            return WriteWireEntry(entry, wireEntry.RawJson, includeProof, versionIdOverride);

        return WriteModeledEntry(entry, includeProof, versionIdOverride);
    }

    private static string WriteModeledEntry(
        LogEntry entry,
        bool includeProof,
        string? versionIdOverride)
    {
        using var stream = new MemoryStream();
        using var writer = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = false });

        writer.WriteStartObject();

        // versionId
        writer.WriteString("versionId", versionIdOverride ?? entry.VersionId);

        // versionTime — ISO 8601 UTC
        writer.WritePropertyName("versionTime");
        if (entry.VersionTimeRawJson is not null
            && WebVhTimestamp.Matches(entry.VersionTime, entry.VersionTimeWireValue))
        {
            writer.WriteRawValue(entry.VersionTimeRawJson);
        }
        else
        {
            writer.WriteStringValue(WebVhTimestamp.Format(entry.VersionTime));
        }

        // parameters
        writer.WritePropertyName("parameters");
        WriteParameters(writer, entry.Parameters);

        // state — a parsed document with current provenance re-emits its wire JSON verbatim;
        // otherwise the DID Document is serialized as JSON-LD from the typed model.
        writer.WritePropertyName("state");
        if (TryGetCurrentWireState(entry.State, out var stateWireJson))
        {
            writer.WriteRawValue(stateWireJson);
        }
        else
        {
            var stateJson = DidDocumentSerializer.Serialize(entry.State, DidContentTypes.JsonLd);
            using var stateDoc = JsonDocument.Parse(stateJson);
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

    private static string WriteWireEntry(
        LogEntry entry,
        string rawJson,
        bool includeProof,
        string? versionIdOverride)
    {
        using var rawDocument = JsonDocument.Parse(
            rawJson,
            new JsonDocumentOptions { AllowDuplicateProperties = false });
        using var stream = new MemoryStream();
        using var writer = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = false });

        writer.WriteStartObject();
        foreach (var property in rawDocument.RootElement.EnumerateObject())
        {
            if (property.NameEquals("versionId"))
            {
                writer.WriteString("versionId", versionIdOverride ?? entry.VersionId);
                continue;
            }

            if (property.NameEquals("proof"))
            {
                if (includeProof && entry.Proof is { Count: > 0 })
                {
                    writer.WritePropertyName("proof");
                    WriteProofArray(writer, entry.Proof);
                }

                continue;
            }

            writer.WritePropertyName(property.Name);
            property.Value.WriteTo(writer);
        }

        writer.WriteEndObject();
        writer.Flush();
        return Encoding.UTF8.GetString(stream.ToArray());
    }

    private static bool TryGetCurrentWireEntry(
        LogEntry entry,
        out WireEntry wireEntry)
    {
        if (!WireEntries.TryGetValue(entry, out wireEntry!))
            return false;

        var currentFingerprint = ComputeModeledFingerprint(entry);
        return currentFingerprint.AsSpan().SequenceEqual(wireEntry.ModeledFingerprint);
    }

    private static byte[] ComputeModeledFingerprint(LogEntry entry)
    {
        var modeled = WriteModeledEntry(entry, includeProof: true, versionIdOverride: null);
        return SHA256.HashData(Encoding.UTF8.GetBytes(modeled));
    }

    private static bool TryGetCurrentWireState(DidDocument state, out string stateWireJson)
    {
        stateWireJson = null!;
        if (!WireStates.TryGetValue(state, out var wireState))
            return false;

        var currentFingerprint = ComputeModeledStateFingerprint(state);
        if (!currentFingerprint.AsSpan().SequenceEqual(wireState.ModeledFingerprint))
            return false;

        stateWireJson = wireState.RawJson;
        return true;
    }

    private static byte[] ComputeModeledStateFingerprint(DidDocument state)
        => SHA256.HashData(Encoding.UTF8.GetBytes(
            DidDocumentSerializer.Serialize(state, DidContentTypes.JsonLd)));

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
        if (parameters.Watchers is not null)
        {
            writer.WritePropertyName("watchers");
            writer.WriteStartArray();
            foreach (var watcher in parameters.Watchers)
                writer.WriteStringValue(watcher);
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

        var programmaticEmpty = !config.ThresholdPropertyPresent.HasValue && config.IsDisabled;
        if (!programmaticEmpty && config.ThresholdPropertyPresent != false)
            writer.WriteNumber("threshold", config.Threshold);

        var writeWitnesses = config.WitnessesPropertyPresent == true
            || (!config.WitnessesPropertyPresent.HasValue && config.Witnesses is not null);
        if (writeWitnesses)
        {
            writer.WritePropertyName("witnesses");
            writer.WriteStartArray();
            foreach (var w in config.Witnesses ?? [])
            {
                writer.WriteStartObject();
                writer.WriteString("id", w.Id);
                if (w.LegacyWireWeight.HasValue)
                    writer.WriteNumber("weight", w.LegacyWireWeight.Value);
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
            // A proof parsed from a log re-emits verbatim (byte-identical), preserving members
            // outside the modeled set (id, expires, extensions) that the signature covers, so
            // republishing a fetched log during Update/Deactivate never corrupts another
            // implementation's proof. A programmatically created proof has no RawJson and is
            // written from the modeled members (the shape NetDid emits).
            if (proof.RawJson is not null)
            {
                writer.WriteRawValue(proof.RawJson);
                continue;
            }

            writer.WriteStartObject();
            writer.WriteString("type", proof.Type);
            writer.WriteString("cryptosuite", proof.Cryptosuite);
            writer.WriteString("verificationMethod", proof.VerificationMethod);
            if (proof.Created is not null)
                writer.WriteString("created", proof.Created);
            writer.WriteString("proofPurpose", proof.ProofPurpose);
            writer.WriteString("proofValue", proof.ProofValue);
            writer.WriteEndObject();
        }
        writer.WriteEndArray();
    }

    internal static LogEntry DeserializeEntry(string json)
    {
        JsonDocument doc;
        try
        {
            // Reject duplicate JSON members anywhere in the entry. .NET keeps the last of a
            // duplicate pair, so a leading decoy "proof" beside a valid trailing one would let
            // an unchecked proof ride along; universal proof validation only holds if the
            // parser cannot silently drop a supplied member. See issue #101.
            doc = JsonDocument.Parse(
                json, new JsonDocumentOptions { AllowDuplicateProperties = false });
        }
        catch (JsonException ex)
        {
            throw new FormatException("did:webvh log entry is not valid JSON.", ex);
        }

        using (doc)
        try
        {
            var root = doc.RootElement;

            foreach (var property in root.EnumerateObject())
            {
                if (property.Name is not ("versionId" or "versionTime" or "parameters" or "state" or "proof"))
                    throw new FormatException(
                        $"Unknown did:webvh log-entry property '{property.Name}'.");
            }

            var versionId = root.GetProperty("versionId").GetString()!;
            if (!root.TryGetProperty("versionTime", out var versionTimeElement)
                || versionTimeElement.ValueKind != JsonValueKind.String
                || versionTimeElement.GetString() is not { } versionTime)
            {
                throw new FormatException(
                    "did:webvh versionTime must be a non-null JSON string.");
            }
            var parameters = ParseParameters(root.GetProperty("parameters"));

            // Parse state as a DID Document, retaining its wire JSON as state-level provenance
            // (registered before the whole-entry provenance below so the entry fingerprint is
            // computed over the same raw-state-backed output it will be compared against).
            var stateJson = root.GetProperty("state").GetRawText();
            var state = DidDocumentSerializer.Deserialize(stateJson);
            WireStates.Add(state, new WireState(
                stateJson, ComputeModeledStateFingerprint(state)));

            // Parse proof (optional here; chain validation requires one per entry). The schema
            // permits a single proof object or an array of proof objects.
            IReadOnlyList<DataIntegrityProofValue>? proof = null;
            if (root.TryGetProperty("proof", out var proofProp))
            {
                proof = ParseProof(proofProp);
            }

            var entry = new LogEntry
            {
                VersionId = versionId,
                VersionTime = WebVhTimestamp.Parse(versionTime),
                VersionTimeWireValue = versionTime,
                VersionTimeRawJson = versionTimeElement.GetRawText(),
                Parameters = parameters,
                State = state,
                Proof = proof
            };

            WireEntries.Add(
                entry,
                new WireEntry(root.GetRawText(), ComputeModeledFingerprint(entry)));
            return entry;
        }
        catch (Exception ex) when (ex is InvalidOperationException
            or KeyNotFoundException
            or OverflowException
            or ArgumentException
            or JsonException)
        {
            // Map JSON-access failures at this trust boundary to FormatException so a fetched
            // log with malformed content (e.g. a string carrying an unpaired surrogate that
            // parses as a token but throws on GetString) resolves as invalidDidLog, not notFound
            // or an unhandled exception. Deliberate FormatExceptions above propagate unchanged.
            throw new FormatException("did:webvh log entry contains malformed content.", ex);
        }
    }

    private static LogEntryParameters ParseParameters(JsonElement element)
    {
        string? method = null;
        string? scid = null;
        IReadOnlyList<string>? updateKeys = null;
        bool? deactivated = null;
        IReadOnlyList<string>? nextKeyHashes = null;
        IReadOnlyList<string>? watchers = null;
        bool? portable = null;
        int? ttl = null;
        WitnessConfig? witness = null;

        if (element.TryGetProperty("method", out var m))
            method = m.GetString();
        if (element.TryGetProperty("scid", out var s))
            scid = s.GetString();
        if (element.TryGetProperty("updateKeys", out var uk))
            updateKeys = uk.EnumerateArray().Select(e => e.GetString()!).ToList();
        foreach (var property in element.EnumerateObject())
        {
            if (property.Name == "prerotation")
                throw new FormatException(
                    "The 'prerotation' parameter was removed before did:webvh v1.0; " +
                    "pre-rotation is controlled by nextKeyHashes.");

            if (property.Name is not ("method" or "scid" or "updateKeys" or "deactivated" or
                    "nextKeyHashes" or "watchers" or "portable" or "ttl" or "witness"))
                throw new FormatException(
                    $"Unknown did:webvh v1.0 parameter '{property.Name}'.");
        }
        if (element.TryGetProperty("deactivated", out var d))
            deactivated = d.GetBoolean();
        if (element.TryGetProperty("nextKeyHashes", out var nkh))
            nextKeyHashes = nkh.EnumerateArray().Select(e => e.GetString()!).ToList();
        if (element.TryGetProperty("watchers", out var wa))
        {
            if (wa.ValueKind != JsonValueKind.Array)
                throw new FormatException("The did:webvh watchers parameter must be an array.");

            var parsedWatchers = new List<string>();
            foreach (var watcher in wa.EnumerateArray())
            {
                if (watcher.ValueKind != JsonValueKind.String || watcher.GetString() is not { } value)
                    throw new FormatException(
                        "Every did:webvh watchers entry must be a non-null string.");
                parsedWatchers.Add(value);
            }

            watchers = parsedWatchers;
        }
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
            Deactivated = deactivated,
            NextKeyHashes = nextKeyHashes,
            Watchers = watchers,
            Portable = portable,
            Ttl = ttl,
            Witness = witness
        };
    }

    private static WitnessConfig ParseWitnessConfig(JsonElement element)
    {
        try
        {
            var hasThreshold = element.TryGetProperty("threshold", out var thresholdElement);
            var threshold = hasThreshold ? thresholdElement.GetInt32() : 0;
            List<WitnessEntry>? witnesses = null;

            var hasWitnesses = element.TryGetProperty("witnesses", out var w);
            if (hasWitnesses)
            {
                witnesses = w.EnumerateArray().Select(e =>
                {
                    var hasWeight = e.TryGetProperty("weight", out var wt);
                    var weight = hasWeight ? wt.GetInt32() : 1;
                    return new WitnessEntry
                    {
                        Id = e.GetProperty("id").GetString()!,
                        Weight = weight,
                        LegacyWireWeight = hasWeight ? weight : null
                    };
                }).ToList();
            }

            return new WitnessConfig
            {
                Threshold = threshold,
                Witnesses = witnesses,
                ThresholdPropertyPresent = hasThreshold,
                WitnessesPropertyPresent = hasWitnesses
            };
        }
        catch (Exception ex) when (ex is JsonException
            or InvalidOperationException
            or FormatException
            or OverflowException
            or KeyNotFoundException)
        {
            throw new FormatException("Invalid did:webvh witness configuration.", ex);
        }
    }

    /// <summary>
    /// Parses the log entry's <c>proof</c> member. The official did:webvh v1.0 log-entry
    /// schema permits a single Data Integrity proof object or an array of them; both are
    /// normalized to one list. Every structural violation throws <see cref="FormatException"/>
    /// so callers at the trust boundary map it to <c>invalidDidLog</c> (issue #101).
    /// </summary>
    private static IReadOnlyList<DataIntegrityProofValue> ParseProof(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
            return new List<DataIntegrityProofValue> { ParseProofObject(element) }.AsReadOnly();

        if (element.ValueKind != JsonValueKind.Array)
            throw new FormatException(
                "did:webvh log-entry proof must be a proof object or an array of proof objects.");

        var proofs = new List<DataIntegrityProofValue>();
        var proofIds = new HashSet<string>(StringComparer.Ordinal);
        foreach (var proofElement in element.EnumerateArray())
        {
            var proof = ParseProofObject(proofElement);
            if (proofElement.TryGetProperty("id", out var idElement))
            {
                var id = idElement.GetString()!;
                if (!proofIds.Add(id))
                {
                    throw new FormatException(
                        $"did:webvh log-entry proof id '{id}' is duplicated within the proof set.");
                }
            }

            proofs.Add(proof);
        }

        if (proofs.Count == 0)
            throw new FormatException(
                "did:webvh log-entry proof array must contain at least one proof.");

        return proofs.AsReadOnly();
    }

    private static DataIntegrityProofValue ParseProofObject(JsonElement element)
    {
        if (element.ValueKind != JsonValueKind.Object)
            throw new FormatException("Every did:webvh log-entry proof must be a JSON object.");

        ValidateOptionalProofId(element);

        // The did:webvh v1.0 log-entry schema requires these members "at minimum" and leaves
        // additional properties open, so extra Data Integrity members (id, expires, previousProof,
        // @context, extensions) are preserved verbatim via RawJson. NetDid's conservative
        // absolute-URI policy is enforced at this application-schema boundary; the remaining
        // supported semantics are delegated to the Data Integrity pipeline. The modeled fields
        // below are convenience metadata; RawJson is the fidelity source for proof verification
        // and re-emission.
        return new DataIntegrityProofValue
        {
            Type = RequireProofString(element, "type"),
            Cryptosuite = RequireProofString(element, "cryptosuite"),
            VerificationMethod = RequireProofString(element, "verificationMethod"),
            Created = OptionalProofString(element, "created"),
            ProofPurpose = RequireProofString(element, "proofPurpose"),
            ProofValue = RequireProofString(element, "proofValue"),
            RawJson = element.GetRawText()
        };
    }

    private static void ValidateOptionalProofId(JsonElement proof)
    {
        if (!proof.TryGetProperty("id", out _))
            return;

        var id = OptionalProofString(proof, "id")!;
        if (id.Length == 0
            || !string.Equals(id, id.Trim(), StringComparison.Ordinal)
            || !Uri.TryCreate(id, UriKind.Absolute, out var uri)
            || !uri.IsAbsoluteUri
            || !uri.IsWellFormedOriginalString())
        {
            throw new FormatException(
                "did:webvh log-entry proof member 'id' must be a non-empty, " +
                "System.Uri-compatible absolute URI without surrounding whitespace when present.");
        }
    }

    private sealed record WireEntry(string RawJson, byte[] ModeledFingerprint);

    private sealed record WireState(string RawJson, byte[] ModeledFingerprint);

    private static string RequireProofString(JsonElement proof, string name)
    {
        if (!proof.TryGetProperty(name, out var value)
            || value.ValueKind != JsonValueKind.String
            || value.GetString() is not { } text)
        {
            throw new FormatException(
                $"did:webvh log-entry proof member '{name}' must be a non-null JSON string.");
        }

        return text;
    }

    private static string? OptionalProofString(JsonElement proof, string name)
    {
        if (!proof.TryGetProperty(name, out var value))
            return null;

        if (value.ValueKind != JsonValueKind.String || value.GetString() is not { } text)
            throw new FormatException(
                $"did:webvh log-entry proof member '{name}' must be a JSON string when present.");

        return text;
    }
}
