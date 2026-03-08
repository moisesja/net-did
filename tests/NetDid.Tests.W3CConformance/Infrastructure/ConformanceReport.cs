using System.Collections.Concurrent;
using System.Text;

namespace NetDid.Tests.W3CConformance.Infrastructure;

public sealed record ConformanceResult(
    string Method,
    string Category,
    string Section,
    string StatementId,
    string Description,
    bool Passed,
    string? FailureMessage = null);

public static class ConformanceReportSink
{
    private static readonly ConcurrentBag<ConformanceResult> Results = new();

    public static void Record(ConformanceResult result) => Results.Add(result);

    public static void Record(string method, string category, string section,
        string statementId, string description, bool passed, string? failureMessage = null)
    {
        Results.Add(new ConformanceResult(method, category, section, statementId,
            description, passed, failureMessage));
    }

    public static IReadOnlyList<ConformanceResult> GetResults() => Results.ToList();

    public static void Clear() => Results.Clear();
}

public sealed class W3CReportFixture : IAsyncLifetime
{
    public Task InitializeAsync() => Task.CompletedTask;

    public async Task DisposeAsync()
    {
        var results = ConformanceReportSink.GetResults();
        if (results.Count == 0) return;

        var report = GenerateMarkdownReport(results);
        var reportPath = Path.Combine(
            AppContext.BaseDirectory, "..", "..", "..", "..", "..", "w3c-conformance-report.md");
        await File.WriteAllTextAsync(reportPath, report);
    }

    private static string GenerateMarkdownReport(IReadOnlyList<ConformanceResult> results)
    {
        var sb = new StringBuilder();
        sb.AppendLine("# W3C DID Core Conformance Report");
        sb.AppendLine();
        sb.AppendLine($"Generated: {DateTime.UtcNow:yyyy-MM-ddTHH:mm:ssZ}");
        sb.AppendLine();

        var methods = results.Select(r => r.Method).Distinct().OrderBy(m => m).ToList();
        var categories = results.Select(r => (r.Category, r.Section))
            .Distinct()
            .OrderBy(c => c.Section)
            .ToList();

        // Summary table
        sb.AppendLine("## Summary");
        sb.AppendLine();
        sb.Append("| Method |");
        sb.Append(" Total |");
        sb.Append(" Passed |");
        sb.Append(" Failed |");
        sb.AppendLine();
        sb.Append("|--------|");
        sb.Append("-------|");
        sb.Append("--------|");
        sb.Append("--------|");
        sb.AppendLine();

        foreach (var method in methods)
        {
            var methodResults = results.Where(r => r.Method == method).ToList();
            var passed = methodResults.Count(r => r.Passed);
            var failed = methodResults.Count(r => !r.Passed);
            sb.AppendLine($"| {method} | {methodResults.Count} | {passed} | {failed} |");
        }
        sb.AppendLine();

        // Per-category details
        var groupedByCategory = results
            .GroupBy(r => r.Category)
            .OrderBy(g => g.First().Section);

        foreach (var catGroup in groupedByCategory)
        {
            var catName = catGroup.Key;
            var section = catGroup.First().Section;
            sb.AppendLine($"## {catName} (section {section})");
            sb.AppendLine();

            sb.Append("| Statement | Description |");
            foreach (var method in methods)
                sb.Append($" {method} |");
            sb.AppendLine();

            sb.Append("|-----------|-------------|");
            foreach (var _ in methods)
                sb.Append("----------|");
            sb.AppendLine();

            var statements = catGroup
                .GroupBy(r => r.StatementId)
                .OrderBy(g => g.Key);

            foreach (var stmtGroup in statements)
            {
                var desc = stmtGroup.First().Description;
                sb.Append($"| {stmtGroup.Key} | {desc} |");
                foreach (var method in methods)
                {
                    var result = stmtGroup.FirstOrDefault(r => r.Method == method);
                    if (result is null)
                        sb.Append(" N/A |");
                    else
                        sb.Append(result.Passed ? " PASS |" : $" FAIL |");
                }
                sb.AppendLine();
            }
            sb.AppendLine();
        }

        // Failures section
        var failures = results.Where(r => !r.Passed).ToList();
        if (failures.Count > 0)
        {
            sb.AppendLine("## Failures");
            sb.AppendLine();
            foreach (var f in failures.OrderBy(f => f.StatementId))
            {
                sb.AppendLine($"- **{f.StatementId}** ({f.Method}): {f.Description}");
                if (f.FailureMessage is not null)
                    sb.AppendLine($"  - {f.FailureMessage}");
            }
            sb.AppendLine();
        }

        return sb.ToString();
    }
}

[CollectionDefinition("W3C Conformance")]
public class W3CConformanceCollection : ICollectionFixture<W3CReportFixture>;
