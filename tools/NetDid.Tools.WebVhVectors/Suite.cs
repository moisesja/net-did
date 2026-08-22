using System.Text.Json;
using System.Text.Json.Nodes;

namespace NetDid.Tools.WebVhVectors;

/// <summary>A single step from a scenario's <c>script.yaml</c>.</summary>
public sealed record ScriptStep
{
    public required string Op { get; init; }
    public string? Expect { get; init; }
    public string? ExpectError { get; init; }
    public int? VersionNumber { get; init; }
    public string? Did { get; init; }
}

/// <summary>A scenario's <c>script.yaml</c>, reduced to the fields this harness needs.</summary>
public sealed record VectorScript
{
    public required string Description { get; init; }
    public required string SpecRef { get; init; }
    public required bool Negative { get; init; }
    public required IReadOnlyList<ScriptStep> Steps { get; init; }
}

/// <summary>One <c>vectors/&lt;name&gt;/</c> directory: its script plus the impls that committed artifacts.</summary>
public sealed record Scenario
{
    public required string Name { get; init; }
    public required string Directory { get; init; }
    public required VectorScript Script { get; init; }
    /// <summary>Implementations with a non-empty <c>did.jsonl</c>, in canonical order.</summary>
    public required IReadOnlyList<string> Impls { get; init; }
}

public static class Suite
{
    /// <summary>Canonical implementation order used throughout the report.</summary>
    public static readonly string[] AllImpls = ["ts", "python", "rust", "java", "java-eecc", "dart"];

    /// <summary>
    /// Implementations that honour the script's <c>timestamp:</c> field. The other three stamp
    /// wall-clock generation time, so their <c>created</c>/<c>updated</c> churn on every
    /// regeneration and must not be treated as consensus evidence about time handling.
    /// </summary>
    public static readonly string[] DeterministicImpls = ["ts", "python", "rust"];

    public static IReadOnlyList<Scenario> Load(string suiteRoot)
    {
        var vectorsDir = Path.Combine(suiteRoot, "vectors");
        if (!Directory.Exists(vectorsDir))
            throw new DirectoryNotFoundException($"No 'vectors' directory under '{suiteRoot}'.");

        var scenarios = new List<Scenario>();
        foreach (var dir in Directory.GetDirectories(vectorsDir).OrderBy(d => d, StringComparer.Ordinal))
        {
            var scriptPath = Path.Combine(dir, "script.yaml");
            if (!File.Exists(scriptPath))
                continue;

            var impls = AllImpls
                .Where(i =>
                {
                    var log = Path.Combine(dir, i, "did.jsonl");
                    // URL-only negative vectors commit 0-byte (ts) or 1-byte (rust) placeholder
                    // logs; those carry no replayable log content.
                    return File.Exists(log) && new FileInfo(log).Length > 2;
                })
                .ToList();

            scenarios.Add(new Scenario
            {
                Name = Path.GetFileName(dir),
                Directory = dir,
                Script = ParseScript(File.ReadAllText(scriptPath)),
                Impls = impls,
            });
        }

        return scenarios;
    }

    /// <summary>
    /// Minimal scanner for the fixed <c>script.yaml</c> shape used by the suite. Deliberately not a
    /// general YAML parser — Central Package Management means a real YAML dependency would have to
    /// be added to the solution-wide <c>Directory.Packages.props</c> for a single tool.
    /// <para>
    /// Handles exactly: top-level <c>key: value</c>, and a <c>steps:</c> sequence whose entries
    /// begin with <c>- op:</c> at indent 2 and continue with keys at indent 4. Anything nested
    /// deeper (<c>params:</c>) is skipped. Guarded by <see cref="SelfCheck"/>.
    /// </para>
    /// </summary>
    public static VectorScript ParseScript(string yaml)
    {
        string? description = null, specRef = null;
        var negative = false;
        var steps = new List<ScriptStep>();

        // Mutable accumulator for the step currently being read.
        string? op = null, expect = null, expectError = null, did = null;
        int? versionNumber = null;
        var inSteps = false;

        void FlushStep()
        {
            if (op is null) return;
            steps.Add(new ScriptStep
            {
                Op = op,
                Expect = expect,
                ExpectError = expectError,
                VersionNumber = versionNumber,
                Did = did,
            });
            op = expect = expectError = did = null;
            versionNumber = null;
        }

        foreach (var rawLine in yaml.Split('\n'))
        {
            var line = rawLine.TrimEnd('\r');
            var trimmed = line.TrimStart();

            // Whole-line comments only. An inline '#' strip would corrupt DIDs such as
            // "did:webvh:...:127.0.0.1#x" in negative-fragment-leaks-into-domain.
            if (trimmed.Length == 0 || trimmed.StartsWith('#'))
                continue;

            var indent = line.Length - trimmed.Length;

            if (indent == 0)
            {
                FlushStep();
                inSteps = false;

                var (key, value) = SplitKeyValue(trimmed);
                switch (key)
                {
                    case "description": description = value; break;
                    case "spec_ref": specRef = value; break;
                    case "negative": negative = value == "true"; break;
                    case "steps": inSteps = true; break;
                }
                continue;
            }

            if (!inSteps)
                continue;

            if (indent == 2 && trimmed.StartsWith("- "))
            {
                FlushStep();
                var (key, value) = SplitKeyValue(trimmed[2..]);
                if (key == "op") op = value;
                continue;
            }

            // Keys deeper than a step's own key belong to a nested mapping (params:) — skip.
            if (indent != 4)
                continue;

            var (stepKey, stepValue) = SplitKeyValue(trimmed);
            switch (stepKey)
            {
                case "expect": expect = stepValue; break;
                case "expectError": expectError = stepValue; break;
                case "did": did = stepValue; break;
                case "versionNumber":
                    versionNumber = int.TryParse(stepValue, out var n) ? n : null;
                    break;
            }
        }

        FlushStep();

        return new VectorScript
        {
            Description = description ?? "",
            SpecRef = specRef ?? "",
            Negative = negative,
            Steps = steps,
        };
    }

    private static (string Key, string Value) SplitKeyValue(string text)
    {
        var colon = text.IndexOf(':');
        if (colon < 0) return (text.Trim(), "");
        var key = text[..colon].Trim();
        var value = text[(colon + 1)..].Trim();
        if (value.Length >= 2 &&
            ((value[0] == '"' && value[^1] == '"') || (value[0] == '\'' && value[^1] == '\'')))
            value = value[1..^1];
        return (key, value);
    }

    /// <summary>
    /// Proves the hand-rolled scanner read the scripts correctly, by cross-checking every negative
    /// scenario's parsed <c>expectError</c> against the error code in the committed
    /// <c>ts/resolutionResult.json</c>. A mismatch means the scanner is wrong, so it throws rather
    /// than letting a parser bug masquerade as a conformance finding.
    /// </summary>
    public static void SelfCheck(IReadOnlyList<Scenario> scenarios)
    {
        var problems = new List<string>();
        var negatives = scenarios.Where(s => s.Script.Negative).ToList();

        if (negatives.Count == 0)
            problems.Add("parsed 0 negative scenarios — 'negative: true' was not recognised");

        foreach (var s in negatives)
        {
            var codes = s.Script.Steps
                .Where(st => st.ExpectError is not null)
                .Select(st => st.ExpectError!)
                .Distinct(StringComparer.Ordinal)
                .ToList();

            if (codes.Count == 0)
            {
                problems.Add($"{s.Name}: negative scenario with no parsed expectError");
                continue;
            }

            var committed = Path.Combine(s.Directory, "ts", "resolutionResult.json");
            if (!File.Exists(committed))
            {
                problems.Add($"{s.Name}: no committed ts/resolutionResult.json to cross-check against");
                continue;
            }

            var node = JsonNode.Parse(File.ReadAllText(committed));
            var error = node?["didResolutionMetadata"]?["error"]?.GetValue<string>();
            if (error is null)
                problems.Add($"{s.Name}: committed ts result has no didResolutionMetadata.error");
            else if (!codes.Contains(error, StringComparer.Ordinal))
                problems.Add(
                    $"{s.Name}: parsed expectError [{string.Join(", ", codes)}] " +
                    $"does not include committed '{error}'");
        }

        // Every scenario must have parsed at least one step, negative or not.
        foreach (var s in scenarios.Where(s => s.Script.Steps.Count == 0))
            problems.Add($"{s.Name}: parsed 0 steps");

        if (problems.Count > 0)
            throw new InvalidOperationException(
                "script.yaml scanner self-check failed — refusing to report findings from a " +
                "possibly-misparsed suite:" + Environment.NewLine +
                string.Join(Environment.NewLine, problems.Select(p => "  - " + p)));
    }

    /// <summary>Reads the suite's pinned commit so the report is reproducible.</summary>
    public static string ReadSuiteCommit(string suiteRoot)
    {
        try
        {
            var head = Path.Combine(suiteRoot, ".git", "HEAD");
            if (!File.Exists(head)) return "unknown";
            var content = File.ReadAllText(head).Trim();
            if (!content.StartsWith("ref:")) return content;
            var refPath = Path.Combine(suiteRoot, ".git", content[4..].Trim());
            return File.Exists(refPath) ? File.ReadAllText(refPath).Trim() : "unknown";
        }
        catch (IOException)
        {
            return "unknown";
        }
    }

    public static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };
}
