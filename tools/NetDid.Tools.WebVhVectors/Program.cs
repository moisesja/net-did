// Replays the DIF did:webvh compliance test suite's committed vectors through NetDid's resolver and
// writes a divergence report (issue #134).
//
// The suite is not vendored — clone it on demand:
//   git clone https://github.com/decentralized-identity/didwebvh-test-suite.git \
//     tools/NetDid.Tools.WebVhVectors/suite
//
// Usage:
//   dotnet run --project tools/NetDid.Tools.WebVhVectors -- [--suite <path>] [--out <path>]
//
// The suite's artifacts are untrusted third-party data: they are read as bytes and fed to the
// resolver, never executed, and the clone is gitignored so its own CLAUDE.md and .claude/settings.json
// cannot be mistaken for this repository's agent instructions.

using NetDid.Tools.WebVhVectors;

var toolDir = AppContext.BaseDirectory;
var repoRoot = Path.GetFullPath(Path.Combine(toolDir, "..", "..", "..", "..", ".."));

var suitePath = ArgValue("--suite")
    ?? Path.Combine(repoRoot, "tools", "NetDid.Tools.WebVhVectors", "suite");
var outPath = ArgValue("--out");

if (!Directory.Exists(Path.Combine(suitePath, "vectors")))
{
    Console.Error.WriteLine($"No test suite at '{suitePath}'.");
    Console.Error.WriteLine();
    Console.Error.WriteLine("Clone it with:");
    Console.Error.WriteLine("  git clone https://github.com/decentralized-identity/didwebvh-test-suite.git \\");
    Console.Error.WriteLine("    tools/NetDid.Tools.WebVhVectors/suite");
    Console.Error.WriteLine();
    Console.Error.WriteLine("Or point at an existing checkout with --suite <path>.");
    return 2;
}

var suiteCommit = Suite.ReadSuiteCommit(suitePath);
Console.WriteLine($"Suite: {suitePath}");
Console.WriteLine($"Commit: {suiteCommit}");

var scenarios = Suite.Load(suitePath);
Suite.SelfCheck(scenarios);
Console.WriteLine($"Loaded {scenarios.Count} scenarios " +
                  $"({scenarios.Count(s => !s.Script.Negative)} happy-path, " +
                  $"{scenarios.Count(s => s.Script.Negative)} negative); script parser self-check passed.");

Console.WriteLine("Replaying happy-path vectors…");
var happyPath = await Checks.RunHappyPathAsync(scenarios);

Console.WriteLine("Replaying negative vectors…");
var negative = await Checks.RunNegativeAsync(scenarios);

var report = Report.Generate(suiteCommit, scenarios, happyPath, negative);

var destination = outPath ?? Path.Combine(repoRoot, "tasks", "webvh-vector-divergence.md");
Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
await File.WriteAllTextAsync(destination, report);

Console.WriteLine();
Console.WriteLine($"Happy-path replays : {happyPath.Count} " +
                  $"({happyPath.Count(r => r.Verdict == "MATCH")} match, " +
                  $"{happyPath.Count(r => r.Verdict == "DIFF")} diff, " +
                  $"{happyPath.Count(r => r.Verdict == "REJECTED")} rejected)");
Console.WriteLine($"Negative replays   : {negative.Count} " +
                  $"({negative.Count(n => n.Rejected)} rejected, " +
                  $"{negative.Count(n => !n.Rejected)} accepted, " +
                  $"{negative.Count(n => n.CodeMatches)} exact code match)");
Console.WriteLine($"Report             : {destination}");

// A divergence is data, not a harness failure.
return 0;

string? ArgValue(string name)
{
    var index = Array.IndexOf(args, name);
    return index >= 0 && index + 1 < args.Length ? args[index + 1] : null;
}
