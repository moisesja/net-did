using System.Text.Json;
using System.Text.Json.Serialization;

namespace NetDid.Tools.WebVhCli.State;

internal enum WorkflowPhase
{
    Initialized,
    ParamsSet,
    ScidInputReady,
    ScidComputed,
    VersionIdSet,
    VmAdded,
    ProofAdded,
    LineWritten
}

internal sealed class VmEntry
{
    [JsonPropertyName("keyName")]
    public string KeyName { get; set; } = "";

    [JsonPropertyName("relationship")]
    public string Relationship { get; set; } = "";
}

internal sealed class WorkingStateData
{
    [JsonPropertyName("phase")]
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public WorkflowPhase Phase { get; set; }

    [JsonPropertyName("domain")]
    public string Domain { get; set; } = "";

    [JsonPropertyName("path")]
    public string? Path { get; set; }

    [JsonPropertyName("did")]
    public string? Did { get; set; }

    [JsonPropertyName("scid")]
    public string? Scid { get; set; }

    [JsonPropertyName("updateKeyName")]
    public string UpdateKeyName { get; set; } = "";

    [JsonPropertyName("prerotation")]
    public bool Prerotation { get; set; }

    [JsonPropertyName("portable")]
    public bool Portable { get; set; }

    [JsonPropertyName("ttl")]
    public int? Ttl { get; set; }

    [JsonPropertyName("nextKeyName")]
    public string? NextKeyName { get; set; }

    [JsonPropertyName("logEntryJson")]
    public string? LogEntryJson { get; set; }

    [JsonPropertyName("verificationMethods")]
    public List<VmEntry> VerificationMethods { get; set; } = new();

    [JsonPropertyName("versionId")]
    public string? VersionId { get; set; }

    [JsonPropertyName("entryHash")]
    public string? EntryHash { get; set; }

    [JsonPropertyName("proofJson")]
    public string? ProofJson { get; set; }

    [JsonPropertyName("existingLogContent")]
    public string? ExistingLogContent { get; set; }

    [JsonPropertyName("isUpdate")]
    public bool IsUpdate { get; set; }

    [JsonPropertyName("versionNumber")]
    public int VersionNumber { get; set; } = 1;
}

internal static class WorkingState
{
    private const string FileName = "working-state.json";

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true
    };

    public static string GetPath(string outputDir) => System.IO.Path.Combine(outputDir, FileName);

    public static WorkingStateData? Load(string outputDir)
    {
        var path = GetPath(outputDir);
        if (!File.Exists(path))
            return null;

        var json = File.ReadAllText(path);
        return JsonSerializer.Deserialize<WorkingStateData>(json, JsonOptions);
    }

    public static void Save(string outputDir, WorkingStateData state)
    {
        Directory.CreateDirectory(outputDir);
        var json = JsonSerializer.Serialize(state, JsonOptions);
        File.WriteAllText(GetPath(outputDir), json);
    }
}
