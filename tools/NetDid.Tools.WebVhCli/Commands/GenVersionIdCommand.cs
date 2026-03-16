using System.CommandLine;
using NetDid.Method.WebVh;
using NetDid.Tools.WebVhCli.State;

namespace NetDid.Tools.WebVhCli.Commands;

internal static class GenVersionIdCommand
{
    public static Command Create()
    {
        var outputDirOption = CommonOptions.OutputDir();

        var command = new Command("gen-version-id", "Compute the version ID and entry hash");
        command.Options.Add(outputDirOption);

        command.SetAction(parseResult =>
        {
            var outputDir = parseResult.GetValue(outputDirOption)!;

            var state = WorkingState.Load(outputDir);
            if (state is null || state.Phase != WorkflowPhase.ScidComputed)
            {
                Console.Error.WriteLine("Error: Run 'gen-scid-value' first (expected phase: ScidComputed).");
                return;
            }

            if (state.IsUpdate)
            {
                var entryHash = ScidGenerator.ComputeEntryHash(state.LogEntryJson!);
                var versionId = $"{state.VersionNumber}-{entryHash}";

                var entry = LogEntrySerializer.DeserializeEntry(state.LogEntryJson!);
                var updatedEntry = new NetDid.Method.WebVh.Model.LogEntry
                {
                    VersionId = versionId,
                    VersionTime = entry.VersionTime,
                    Parameters = entry.Parameters,
                    State = entry.State
                };
                state.LogEntryJson = LogEntrySerializer.SerializeWithoutProof(updatedEntry);
                state.VersionId = versionId;
                state.EntryHash = entryHash;
            }
            else
            {
                state.VersionId = $"1-{state.Scid}";
                state.EntryHash = state.Scid;
            }

            state.Phase = WorkflowPhase.VersionIdSet;
            WorkingState.Save(outputDir, state);

            Console.WriteLine($"Version ID computed:");
            Console.WriteLine($"  Version ID: {state.VersionId}");
            Console.WriteLine($"  Entry hash: {state.EntryHash}");
        });

        return command;
    }
}
