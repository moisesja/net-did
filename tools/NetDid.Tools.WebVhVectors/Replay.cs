using System.Text;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging;
using NetDid.Core.Model;
using NetDid.Core.Serialization;
using NetDid.Method.WebVh;

namespace NetDid.Tools.WebVhVectors;

/// <summary>
/// Serves one vector's committed artifacts in place of the network. The did:webvh resolve path does
/// no DNS, TLS or wall-clock read — all of that lives inside <c>DefaultWebVhHttpClient</c> — so
/// substituting this client makes replay fully offline and deterministic.
/// </summary>
public sealed class FileWebVhHttpClient(string vectorDirectory) : IWebVhHttpClient
{
    public Task<byte[]?> FetchDidLogAsync(Uri logUrl, CancellationToken ct = default)
        => Read("did.jsonl", ct);

    public Task<byte[]?> FetchWitnessFileAsync(Uri witnessUrl, CancellationToken ct = default)
        => Read("did-witness.json", ct);

    private async Task<byte[]?> Read(string name, CancellationToken ct)
    {
        var path = Path.Combine(vectorDirectory, name);
        if (!File.Exists(path)) return null;
        return await File.ReadAllBytesAsync(path, ct).ConfigureAwait(false);
    }
}

/// <summary>
/// Captures the resolver's own diagnostics. <c>invalidDidLog</c> is a single bucket covering every
/// hash, proof, version and timestamp failure; the specific reason is only ever surfaced through
/// <c>ILogger</c> (DidWebVhMethod.cs:441), so without this the report could not root-cause a
/// rejection.
/// </summary>
public sealed class CapturingLogger : ILogger<DidWebVhMethod>
{
    private readonly List<string> _messages = [];

    public IReadOnlyList<string> Messages => _messages;

    public void Clear() => _messages.Clear();

    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

    public bool IsEnabled(LogLevel logLevel) => true;

    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
        Func<TState, Exception?, string> formatter)
    {
        var text = formatter(state, exception);
        // Walk the whole chain: the resolver wraps parse failures in a generic FormatException,
        // so the actionable cause is always an inner exception.
        for (var ex = exception; ex is not null; ex = ex.InnerException)
            text += " :: " + ex.GetType().Name + ": " + ex.Message;
        _messages.Add(text);
    }
}

/// <summary>Outcome of replaying one committed artifact through NetDid's resolver.</summary>
public sealed record ReplayOutcome
{
    public required string Did { get; init; }
    /// <summary>Null when resolution succeeded.</summary>
    public string? Error { get; init; }
    /// <summary>Resolver diagnostics explaining <see cref="Error"/>, when it was raised.</summary>
    public required IReadOnlyList<string> Diagnostics { get; init; }
    /// <summary>Our result rendered in the suite's three-key envelope, for diffing. Null on error.</summary>
    public JsonObject? Envelope { get; init; }
}

public static class Replay
{
    /// <summary>
    /// Resolves a committed <c>did.jsonl</c>, optionally at a historical version.
    /// </summary>
    /// <param name="vectorDir">Directory holding <c>did.jsonl</c> (and any <c>did-witness.json</c>).</param>
    /// <param name="did">The DID to resolve, taken from the log's own genesis <c>state.id</c>.</param>
    /// <param name="versionId">Historical target, or null for the latest version.</param>
    public static async Task<ReplayOutcome> ResolveAsync(string vectorDir, string did, string? versionId)
    {
        var logger = new CapturingLogger();
        var method = new DidWebVhMethod(new FileWebVhHttpClient(vectorDir), logger);

        DidResolutionResult result;
        try
        {
            result = await method.ResolveAsync(did, new DidResolutionOptions
            {
                VersionId = versionId,
                IncludeLog = true,
            }).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            // A throw out of ResolveAsync is itself a finding: the documented contract is an
            // error-bearing result, not an exception.
            return new ReplayOutcome
            {
                Did = did,
                Error = "THREW:" + ex.GetType().Name,
                Diagnostics = [.. logger.Messages, ex.ToString()],
            };
        }

        if (result.ResolutionMetadata.Error is { } error)
            return new ReplayOutcome { Did = did, Error = error, Diagnostics = logger.Messages };

        return new ReplayOutcome
        {
            Did = did,
            Diagnostics = logger.Messages,
            Envelope = ToEnvelope(result),
        };
    }

    /// <summary>
    /// Renders a <see cref="DidResolutionResult"/> as the suite's
    /// <c>{didDocument, didDocumentMetadata, didResolutionMetadata}</c> envelope. Only members the
    /// resolver actually populates are emitted — absence here is exactly the signal the report needs.
    /// </summary>
    public static JsonObject ToEnvelope(DidResolutionResult result)
    {
        var doc = result.DidDocument is null
            ? null
            : JsonNode.Parse(DidDocumentSerializer.Serialize(result.DidDocument));

        var meta = new JsonObject();
        var m = result.DocumentMetadata;
        if (m is not null)
        {
            if (m.VersionId is not null) meta["versionId"] = m.VersionId;
            if (m.Created is { } created) meta["created"] = Iso(created);
            if (m.Updated is { } updated) meta["updated"] = Iso(updated);
            if (m.VersionTime is { } versionTime) meta["versionTime"] = Iso(versionTime);
            if (m.Deactivated is { } deactivated) meta["deactivated"] = deactivated;
            if (m.NextVersionId is not null) meta["nextVersionId"] = m.NextVersionId;
            if (m.NextUpdate is not null) meta["nextUpdate"] = m.NextUpdate;
            if (m.CanonicalId is not null) meta["canonicalId"] = m.CanonicalId;
            if (m.EquivalentId is not null)
                meta["equivalentId"] = new JsonArray([.. m.EquivalentId.Select(e => (JsonNode)e!)]);
        }

        var resMeta = new JsonObject();
        if (result.ResolutionMetadata.ContentType is not null)
            resMeta["contentType"] = result.ResolutionMetadata.ContentType;
        if (result.ResolutionMetadata.Error is not null)
            resMeta["error"] = result.ResolutionMetadata.Error;

        return new JsonObject
        {
            ["didDocument"] = doc,
            ["didDocumentMetadata"] = meta,
            ["didResolutionMetadata"] = resMeta,
        };
    }

    private static string Iso(DateTimeOffset value)
        => value.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ");

    /// <summary>
    /// Reads the DID to resolve from the log's <paramref name="versionNumber"/>th entry, or its last
    /// entry when resolving the latest version. The resolver binds the requested DID to the
    /// <em>target</em> entry's <c>state.id</c> (DidWebVhMethod.cs:267), and a portable DID's
    /// <c>state.id</c> changes domain mid-log — so taking the genesis id would fail
    /// <c>portable-move</c> for a reason that has nothing to do with conformance.
    /// </summary>
    public static string? ReadDidFromLog(string logPath, int? versionNumber = null)
    {
        string? did = null;
        var seen = 0;
        foreach (var line in File.ReadLines(logPath))
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            seen++;
            var id = JsonNode.Parse(line)?["state"]?["id"]?.GetValue<string>();
            if (id is not null) did = id;
            if (versionNumber is { } n && seen == n) return did;
        }
        return did;
    }

    /// <summary>Reads the SCID a committed log declares in its genesis <c>parameters.scid</c>.</summary>
    public static string? ReadScidFromLog(string logPath)
    {
        foreach (var line in File.ReadLines(logPath))
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            return JsonNode.Parse(line)?["parameters"]?["scid"]?.GetValue<string>();
        }
        return null;
    }

    /// <summary>
    /// Maps a script's <c>versionNumber: N</c> to the log's Nth <c>versionId</c>. The suite resolves
    /// historical versions by ordinal, which
    /// <see cref="DidResolutionOptions"/> has no member for — it exposes only versionId and
    /// versionTime. That gap is itself reported; this bridges it so the comparison can still run.
    /// </summary>
    public static string? VersionIdForNumber(string logPath, int versionNumber)
    {
        var seen = 0;
        foreach (var line in File.ReadLines(logPath))
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            if (++seen == versionNumber)
                return JsonNode.Parse(line)?["versionId"]?.GetValue<string>();
        }
        return null;
    }

    public static string ReadAllTextUtf8(string path) => File.ReadAllText(path, Encoding.UTF8);
}
