using System.Text;

namespace NetDid.Tools.WebVhVectors;

public static class Report
{
    public static string Generate(
        string suiteCommit,
        IReadOnlyList<Scenario> scenarios,
        IReadOnlyList<HappyPathResult> happyPath,
        IReadOnlyList<NegativeResult> negative)
    {
        var sb = new StringBuilder();

        sb.AppendLine("# did:webvh compliance vector divergence report");
        sb.AppendLine();
        sb.AppendLine($"- Suite: `decentralized-identity/didwebvh-test-suite` @ `{suiteCommit}`");
        sb.AppendLine($"- Scenarios: {scenarios.Count} " +
                      $"({scenarios.Count(s => !s.Script.Negative)} happy-path, " +
                      $"{scenarios.Count(s => s.Script.Negative)} negative)");
        sb.AppendLine("- Harness: `tools/NetDid.Tools.WebVhVectors` — replays the suite's committed " +
                      "artifacts through `DidWebVhMethod` offline via a file-backed `IWebVhHttpClient`.");
        sb.AppendLine();
        sb.AppendLine("Resolution recomputes the SCID and every entry hash " +
                      "(`LogChainValidator.cs:136-145`, `:194`), so a successful resolve of a foreign " +
                      "log is direct evidence that our hash encoding interoperates with that " +
                      "implementation — something our self-generated tests cannot establish.");
        sb.AppendLine();

        AppendSummary(sb, happyPath, negative);
        AppendHashConformance(sb, happyPath);
        AppendRootCauses(sb, happyPath);
        AppendNegative(sb, negative);
        AppendHappyPathMatrix(sb, happyPath);
        AppendDiagnostics(sb, happyPath);

        return sb.ToString();
    }

    /// <summary>
    /// Full, untruncated resolver diagnostics for every rejected happy-path log. `invalidDidLog` is a
    /// single bucket covering every hash, proof, parameter and timestamp failure, so the exact
    /// message is the only way to tell those apart.
    /// </summary>
    private static void AppendDiagnostics(StringBuilder sb, IReadOnlyList<HappyPathResult> happyPath)
    {
        var rejected = happyPath.Where(r => r.Error is not null).ToList();
        if (rejected.Count == 0) return;

        sb.AppendLine("## E. Full diagnostics for rejected logs");
        sb.AppendLine();

        foreach (var group in rejected
            .GroupBy(r => r.Diagnostics.LastOrDefault(d => d.Contains("::", StringComparison.Ordinal)) ?? "(no exception logged)")
            .OrderByDescending(g => g.Count()))
        {
            var affected = group
                .Select(r => $"`{r.Scenario}`/`{r.Impl}`")
                .Distinct(StringComparer.Ordinal);

            sb.AppendLine($"**{group.Count()} rejection(s)** — {string.Join(", ", affected)}");
            sb.AppendLine();
            sb.AppendLine("```");
            sb.AppendLine(group.Key);
            sb.AppendLine("```");
            sb.AppendLine();
        }
    }

    private static void AppendSummary(StringBuilder sb, IReadOnlyList<HappyPathResult> happyPath,
        IReadOnlyList<NegativeResult> negative)
    {
        sb.AppendLine("## Summary");
        sb.AppendLine();
        sb.AppendLine("| Check | Cases | Result |");
        sb.AppendLine("|---|---:|---|");

        var resolved = happyPath.Count(r => r.Error is null);
        var rejected = happyPath.Count(r => r.Error is not null);
        var clean = happyPath.Count(r => r.Verdict == "MATCH");

        sb.AppendLine($"| Happy-path logs accepted | {happyPath.Count} | " +
                      $"{resolved} accepted, {rejected} rejected |");
        sb.AppendLine($"| Happy-path exact match | {resolved} | " +
                      $"{clean} match, {resolved - clean} diverge |");
        sb.AppendLine($"| Negative vectors rejected | {negative.Count} | " +
                      $"{negative.Count(n => n.Rejected)} rejected, " +
                      $"{negative.Count(n => !n.Rejected)} **accepted** |");
        sb.AppendLine($"| Negative error code matches | {negative.Count} | " +
                      $"{negative.Count(n => n.CodeMatches)} match, " +
                      $"{negative.Count(n => !n.CodeMatches)} differ |");
        sb.AppendLine();
    }

    private static void AppendHashConformance(StringBuilder sb, IReadOnlyList<HappyPathResult> happyPath)
    {
        sb.AppendLine("## A. Hash / wire-format conformance");
        sb.AppendLine();
        sb.AppendLine("Whether our recomputation of each foreign log's SCID and entry-hash chain agrees " +
                      "with the implementation that authored it. A rejection here means our hash " +
                      "encoding does not interoperate.");
        sb.AppendLine();
        sb.AppendLine("| Implementation | Logs replayed | Accepted | Rejected |");
        sb.AppendLine("|---|---:|---:|---:|");

        foreach (var impl in Suite.AllImpls)
        {
            var forImpl = happyPath.Where(r => r.Impl == impl).ToList();
            if (forImpl.Count == 0) continue;
            var ok = forImpl.Count(r => r.Error is null);
            sb.AppendLine($"| `{impl}` | {forImpl.Count} | {ok} | {forImpl.Count - ok} |");
        }
        sb.AppendLine();

        var rejections = happyPath.Where(r => r.Error is not null).ToList();
        if (rejections.Count == 0)
        {
            sb.AppendLine("**No happy-path log was rejected.** Our SCID and entry-hash computation " +
                          "matches all reference implementations byte-for-byte.");
        }
        else
        {
            sb.AppendLine("Rejected logs:");
            sb.AppendLine();
            sb.AppendLine("| Scenario | Impl | Error | Resolver diagnostic |");
            sb.AppendLine("|---|---|---|---|");
            foreach (var r in rejections)
                sb.AppendLine($"| `{r.Scenario}` | `{r.Impl}` | `{r.Error}` | {Diag(r.Diagnostics)} |");
        }
        sb.AppendLine();
    }

    private static void AppendRootCauses(StringBuilder sb, IReadOnlyList<HappyPathResult> happyPath)
    {
        sb.AppendLine("## B. Resolution divergences, grouped by root cause");
        sb.AppendLine();

        var all = happyPath.SelectMany(r => r.Divergences).ToList();
        if (all.Count == 0)
        {
            sb.AppendLine("No divergences.");
            sb.AppendLine();
            return;
        }

        var groups = all
            .GroupBy(d => (d.ShapePath, d.Kind))
            .OrderByDescending(g => g.Count())
            .ThenBy(g => g.Key.ShapePath, StringComparer.Ordinal);

        sb.AppendLine("Each row is one root cause. `Cases` counts the (scenario × implementation) " +
                      "replays it affects.");
        sb.AppendLine();
        sb.AppendLine("| Path | Kind | Cases | Ours | Reference implementations |");
        sb.AppendLine("|---|---|---:|---|---|");

        foreach (var g in groups)
        {
            var sample = g.First();
            var implValues = string.Join("<br>", sample.ImplValues
                .OrderByDescending(kv => kv.Value.Count)
                .Take(3)
                .Select(kv => $"`{Truncate(kv.Key, 60)}` — {string.Join(", ", kv.Value)}"));

            sb.AppendLine($"| `{g.Key.ShapePath}` | {KindLabel(g.Key.Kind)} | {g.Count()} | " +
                          $"{(sample.OurValue is null ? "*(absent)*" : $"`{Truncate(sample.OurValue, 60)}`")} | " +
                          $"{(implValues.Length == 0 ? "*(none emit it)*" : implValues)} |");
        }
        sb.AppendLine();
    }

    private static void AppendNegative(StringBuilder sb, IReadOnlyList<NegativeResult> negative)
    {
        sb.AppendLine("## C. Negative vectors");
        sb.AppendLine();
        sb.AppendLine("Two independent axes. **Rejected** is the security-relevant question — did we " +
                      "refuse the malicious input at all. **Code** is the conformance question — did " +
                      "we refuse it with the error the suite specifies. Our resolver's vocabulary is " +
                      "`invalidDid` / `methodNotSupported` / `notFound` / `invalidDidLog` / " +
                      "`witnessValidationFailed`; the suite specifies `invalidDid` / `invalidProof` / " +
                      "`invalidParameters`.");
        sb.AppendLine();
        sb.AppendLine("| Scenario | Input | Expected | Actual | Rejected | Code |");
        sb.AppendLine("|---|---|---|---|---|---|");

        foreach (var n in negative.OrderBy(n => n.Scenario, StringComparer.Ordinal))
        {
            var input = n.UrlOnly ? $"`{Truncate(n.Input, 52)}`" : "committed log";
            sb.AppendLine(
                $"| `{n.Scenario}` | {input} | `{string.Join("`, `", n.ExpectedErrors)}` | " +
                $"{(n.ActualError is null ? "**none — accepted**" : $"`{n.ActualError}`")} | " +
                $"{(n.Rejected ? "yes" : "**NO**")} | {(n.CodeMatches ? "match" : "differ")} |");
        }
        sb.AppendLine();

        var accepted = negative.Where(n => !n.Rejected).ToList();
        if (accepted.Count > 0)
        {
            sb.AppendLine($"### Accepted malicious inputs ({accepted.Count})");
            sb.AppendLine();
            foreach (var n in accepted)
                sb.AppendLine($"- `{n.Scenario}` — expected `{string.Join("`/`", n.ExpectedErrors)}`, " +
                              $"resolved successfully. Input: `{Truncate(n.Input, 90)}`");
            sb.AppendLine();
        }

        var rejectedWrongCode = negative.Where(n => n.Rejected && !n.CodeMatches).ToList();
        if (rejectedWrongCode.Count > 0)
        {
            sb.AppendLine($"### Rejected, but with a different error code ({rejectedWrongCode.Count})");
            sb.AppendLine();
            sb.AppendLine("| Scenario | Expected | Ours | Resolver diagnostic |");
            sb.AppendLine("|---|---|---|---|");
            foreach (var n in rejectedWrongCode)
                sb.AppendLine($"| `{n.Scenario}` | `{string.Join("`/`", n.ExpectedErrors)}` | " +
                              $"`{n.ActualError}` | {Diag(n.Diagnostics)} |");
            sb.AppendLine();
        }
    }

    private static void AppendHappyPathMatrix(StringBuilder sb, IReadOnlyList<HappyPathResult> happyPath)
    {
        sb.AppendLine("## D. Full happy-path matrix");
        sb.AppendLine();
        sb.AppendLine("`MATCH` — identical after normalising each implementation's SCID. " +
                      "`DIFF` — resolved, output differs. `REJECTED` — we refused a valid log.");
        sb.AppendLine();

        var targets = happyPath.Select(r => (r.Scenario, r.Target)).Distinct()
            .OrderBy(t => t.Scenario, StringComparer.Ordinal)
            .ThenBy(t => t.Target, StringComparer.Ordinal);

        sb.AppendLine("| Scenario | Target | " + string.Join(" | ", Suite.AllImpls.Select(i => $"`{i}`")) + " |");
        sb.AppendLine("|---|---|" + string.Concat(Suite.AllImpls.Select(_ => "---|")));

        foreach (var (scenario, target) in targets)
        {
            var cells = Suite.AllImpls.Select(impl =>
            {
                var r = happyPath.FirstOrDefault(x =>
                    x.Scenario == scenario && x.Target == target && x.Impl == impl);
                if (r is null) return "—";
                return r.Verdict switch
                {
                    "MATCH" => "MATCH",
                    "REJECTED" => $"**REJECTED**<br>`{r.Error}`",
                    _ => $"DIFF ({r.Divergences.Count})",
                };
            });
            sb.AppendLine($"| `{scenario}` | `{target}` | {string.Join(" | ", cells)} |");
        }
        sb.AppendLine();
    }

    private static string KindLabel(DivergenceKind kind) => kind switch
    {
        DivergenceKind.MissingFromOurs => "missing from ours",
        DivergenceKind.ExtraInOurs => "extra in ours",
        DivergenceKind.ValueDiffersFromUnanimous => "value differs (impls unanimous)",
        _ => "impls disagree",
    };

    private static string Diag(IReadOnlyList<string> diagnostics)
    {
        var text = diagnostics.LastOrDefault(d => d.Contains("::", StringComparison.Ordinal))
                   ?? diagnostics.LastOrDefault();
        return text is null ? "*(none)*" : $"`{Truncate(text.Replace("|", "\\|"), 220)}`";
    }

    private static string Truncate(string value, int max)
    {
        value = value.Replace("\n", " ").Replace("\r", "").Replace("|", "\\|");
        return value.Length <= max ? value : value[..max] + "…";
    }
}
