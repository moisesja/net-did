using System.CommandLine;
using System.Text;
using NetDid.Method.WebVh;
using NetDid.Tools.WebVhCli.State;

namespace NetDid.Tools.WebVhCli.Commands;

internal static class NewLineCommand
{
    public static Command Create()
    {
        var outputDirOption = CommonOptions.OutputDir();

        var command = new Command("new-line", "Write the finalized log line to did.jsonl and generate did.json");
        command.Options.Add(outputDirOption);

        command.SetAction(parseResult =>
        {
            var outputDir = parseResult.GetValue(outputDirOption)!;

            var state = WorkingState.Load(outputDir);
            if (state is null || state.Phase != WorkflowPhase.ProofAdded)
            {
                Console.Error.WriteLine("Error: Run 'add-proof' first (expected phase: ProofAdded).");
                return;
            }

            var signedEntry = LogEntrySerializer.DeserializeEntry(state.ProofJson!);

            var allEntries = new List<NetDid.Method.WebVh.Model.LogEntry>();

            if (state.IsUpdate && state.ExistingLogContent is not null)
            {
                var existingEntries = LogEntrySerializer.ParseJsonLines(
                    Encoding.UTF8.GetBytes(state.ExistingLogContent));
                allEntries.AddRange(existingEntries);
            }
            allEntries.Add(signedEntry);

            var logContent = LogEntrySerializer.ToJsonLines(allEntries);
            var didJsonlPath = Path.Combine(outputDir, "did.jsonl");
            Directory.CreateDirectory(outputDir);
            File.WriteAllBytes(didJsonlPath, logContent);

            var did = state.Did!;
            var didJsonContent = DidWebCompatibility.GenerateDidJson(did, signedEntry.State);
            var didJsonPath = Path.Combine(outputDir, "did.json");
            File.WriteAllBytes(didJsonPath, didJsonContent);

            state.Phase = WorkflowPhase.LineWritten;
            state.ExistingLogContent = Encoding.UTF8.GetString(logContent);
            WorkingState.Save(outputDir, state);

            Console.WriteLine("Log line written:");
            Console.WriteLine($"  DID:         {did}");
            Console.WriteLine($"  Version:     {signedEntry.VersionId}");
            Console.WriteLine($"  did.jsonl:   {Path.GetFullPath(didJsonlPath)}");
            Console.WriteLine($"  did.json:    {Path.GetFullPath(didJsonPath)}");
            Console.WriteLine($"  Entries:     {allEntries.Count}");
        });

        return command;
    }
}
