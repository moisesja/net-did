using System.Text.Json.Nodes;

namespace NetDid.Tools.WebVhVectors;

/// <summary>Result of replaying one committed happy-path artifact.</summary>
public sealed record HappyPathResult
{
    public required string Scenario { get; init; }
    public required string Impl { get; init; }
    public required string Target { get; init; }
    public required string Did { get; init; }
    /// <summary>Null when we resolved successfully.</summary>
    public string? Error { get; init; }
    public required IReadOnlyList<string> Diagnostics { get; init; }
    public IReadOnlyList<Divergence> Divergences { get; init; } = [];

    public string Verdict => Error is not null
        ? "REJECTED"
        : Divergences.Count == 0 ? "MATCH" : "DIFF";
}

/// <summary>Result of replaying one negative vector.</summary>
public sealed record NegativeResult
{
    public required string Scenario { get; init; }
    public required string Input { get; init; }
    /// <summary>Whether the input was a DID string (URL-only vector) rather than a committed log.</summary>
    public required bool UrlOnly { get; init; }
    public required IReadOnlyList<string> ExpectedErrors { get; init; }
    public string? ActualError { get; init; }
    public required IReadOnlyList<string> Diagnostics { get; init; }

    /// <summary>The security-relevant axis: did we refuse the input at all?</summary>
    public bool Rejected => ActualError is not null;

    /// <summary>The conformance axis: did we refuse it with the code the suite specifies?</summary>
    public bool CodeMatches => ActualError is not null && ExpectedErrors.Contains(ActualError, StringComparer.Ordinal);
}

public static class Checks
{
    /// <summary>
    /// Replays every committed happy-path log and diffs our resolution against each implementation's
    /// own committed expected result.
    /// </summary>
    public static async Task<List<HappyPathResult>> RunHappyPathAsync(IReadOnlyList<Scenario> scenarios)
    {
        var results = new List<HappyPathResult>();

        foreach (var scenario in scenarios.Where(s => !s.Script.Negative))
        {
            // Which expected-result files this scenario defines, and the version each targets.
            var targets = new List<(string File, int? VersionNumber)>();
            foreach (var step in scenario.Script.Steps.Where(s => s.Op == "resolve" && s.Expect is not null))
                targets.Add((step.Expect!, step.VersionNumber));
            if (targets.Count == 0)
                targets.Add(("resolutionResult.json", null));

            foreach (var (file, versionNumber) in targets)
            {
                // Expected results for this target, from every implementation that committed one.
                var expectedByImpl = new Dictionary<string, Dictionary<string, string>>(StringComparer.Ordinal);
                foreach (var impl in scenario.Impls)
                {
                    var expectedPath = Path.Combine(scenario.Directory, impl, file);
                    var logPath = Path.Combine(scenario.Directory, impl, "did.jsonl");
                    if (!File.Exists(expectedPath)) continue;

                    var scid = Replay.ReadScidFromLog(logPath);
                    var node = JsonNode.Parse(Replay.ReadAllTextUtf8(expectedPath));
                    // Envelope-level @context is a resolution-result wrapper concern, not a
                    // did:webvh one, and only python emits it.
                    (node as JsonObject)?.Remove("@context");
                    expectedByImpl[impl] = JsonDiff.Flatten(JsonDiff.Normalize(node, scid));
                }

                foreach (var impl in scenario.Impls)
                {
                    var vectorDir = Path.Combine(scenario.Directory, impl);
                    var logPath = Path.Combine(vectorDir, "did.jsonl");
                    var did = Replay.ReadDidFromLog(logPath, versionNumber);
                    if (did is null) continue;

                    var versionId = versionNumber is { } n
                        ? Replay.VersionIdForNumber(logPath, n)
                        : null;

                    var outcome = await Replay.ResolveAsync(vectorDir, did, versionId).ConfigureAwait(false);

                    if (outcome.Error is not null)
                    {
                        results.Add(new HappyPathResult
                        {
                            Scenario = scenario.Name,
                            Impl = impl,
                            Target = file,
                            Did = did,
                            Error = outcome.Error,
                            Diagnostics = outcome.Diagnostics,
                        });
                        continue;
                    }

                    var scid = Replay.ReadScidFromLog(logPath);
                    var ours = JsonDiff.Flatten(JsonDiff.Normalize(outcome.Envelope, scid));

                    results.Add(new HappyPathResult
                    {
                        Scenario = scenario.Name,
                        Impl = impl,
                        Target = file,
                        Did = did,
                        Diagnostics = outcome.Diagnostics,
                        Divergences = JsonDiff.Compare(
                            scenario.Name, $"{impl}/{file}", ours, impl, expectedByImpl),
                    });
                }
            }
        }

        return results;
    }

    /// <summary>
    /// Replays every negative vector. Log-based vectors resolve the committed <c>ts/did.jsonl</c>;
    /// URL-only vectors have no replayable log, so the input is each <c>resolve-did</c> step's
    /// literal DID string.
    /// </summary>
    public static async Task<List<NegativeResult>> RunNegativeAsync(IReadOnlyList<Scenario> scenarios)
    {
        var results = new List<NegativeResult>();

        foreach (var scenario in scenarios.Where(s => s.Script.Negative))
        {
            var expected = scenario.Script.Steps
                .Where(s => s.ExpectError is not null)
                .Select(s => s.ExpectError!)
                .Distinct(StringComparer.Ordinal)
                .ToList();

            var urlSteps = scenario.Script.Steps
                .Where(s => s.Op == "resolve-did" && s.Did is not null)
                .ToList();

            if (urlSteps.Count > 0)
            {
                // A DID that never reaches a log: resolution must reject it on the identifier alone.
                var vectorDir = Path.Combine(scenario.Directory, "ts");
                foreach (var step in urlSteps)
                {
                    var outcome = await Replay.ResolveAsync(vectorDir, step.Did!, null).ConfigureAwait(false);
                    results.Add(new NegativeResult
                    {
                        Scenario = scenario.Name,
                        Input = step.Did!,
                        UrlOnly = true,
                        ExpectedErrors = step.ExpectError is not null ? [step.ExpectError] : expected,
                        ActualError = outcome.Error,
                        Diagnostics = outcome.Diagnostics,
                    });
                }
                continue;
            }

            var logPath = Path.Combine(scenario.Directory, "ts", "did.jsonl");
            if (!File.Exists(logPath) || new FileInfo(logPath).Length <= 2)
                continue;

            var did = Replay.ReadDidFromLog(logPath);
            if (did is null) continue;

            var result = await Replay.ResolveAsync(Path.Combine(scenario.Directory, "ts"), did, null)
                .ConfigureAwait(false);

            results.Add(new NegativeResult
            {
                Scenario = scenario.Name,
                Input = did,
                UrlOnly = false,
                ExpectedErrors = expected,
                ActualError = result.Error,
                Diagnostics = result.Diagnostics,
            });
        }

        return results;
    }
}
