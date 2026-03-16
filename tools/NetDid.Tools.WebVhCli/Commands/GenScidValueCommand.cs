using System.CommandLine;
using NetDid.Method.WebVh;
using NetDid.Tools.WebVhCli.State;

namespace NetDid.Tools.WebVhCli.Commands;

internal static class GenScidValueCommand
{
    public static Command Create()
    {
        var outputDirOption = CommonOptions.OutputDir();

        var command = new Command("gen-scid-value", "Compute the SCID from the genesis log entry template");
        command.Options.Add(outputDirOption);

        command.SetAction(parseResult =>
        {
            var outputDir = parseResult.GetValue(outputDirOption)!;

            var state = WorkingState.Load(outputDir);
            if (state is null || state.Phase != WorkflowPhase.ScidInputReady)
            {
                Console.Error.WriteLine("Error: Run 'gen-scid-input' first (expected phase: ScidInputReady).");
                return;
            }

            if (state.IsUpdate)
            {
                state.Phase = WorkflowPhase.ScidComputed;
                WorkingState.Save(outputDir, state);
                Console.WriteLine("Update mode: SCID computation skipped (SCID is fixed at creation).");
                Console.WriteLine($"  DID: {state.Did}");
                return;
            }

            var scid = ScidGenerator.ComputeScid(state.LogEntryJson!);
            var updatedJson = ScidGenerator.ReplacePlaceholders(state.LogEntryJson!, scid);

            var did = state.Did!.Replace(ScidGenerator.Placeholder, scid);

            state.Scid = scid;
            state.LogEntryJson = updatedJson;
            state.Did = did;
            state.Phase = WorkflowPhase.ScidComputed;
            WorkingState.Save(outputDir, state);

            Console.WriteLine($"SCID computed:");
            Console.WriteLine($"  SCID: {scid}");
            Console.WriteLine($"  DID:  {did}");
        });

        return command;
    }
}
