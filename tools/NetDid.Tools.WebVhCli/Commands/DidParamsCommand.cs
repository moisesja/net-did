using System.CommandLine;
using NetDid.Method.WebVh;
using NetDid.Tools.WebVhCli.State;

namespace NetDid.Tools.WebVhCli.Commands;

internal static class DidParamsCommand
{
    public static Command Create()
    {
        var prerotationOption = new Option<bool>("--prerotation") { Description = "Enable pre-rotation" };
        var portableOption = new Option<bool>("--portable") { Description = "Enable DID portability" };
        var ttlOption = new Option<int?>("--ttl") { Description = "Time-to-live in seconds" };
        var nextKeyOption = new Option<string?>("--next-key") { Description = "Name of the next key (required with --prerotation)" };
        var outputDirOption = CommonOptions.OutputDir();

        var command = new Command("did-params", "Set DID parameters for the current workflow");
        command.Options.Add(prerotationOption);
        command.Options.Add(portableOption);
        command.Options.Add(ttlOption);
        command.Options.Add(nextKeyOption);
        command.Options.Add(outputDirOption);

        command.SetAction(parseResult =>
        {
            var prerotation = parseResult.GetValue(prerotationOption);
            var portable = parseResult.GetValue(portableOption);
            var ttl = parseResult.GetValue(ttlOption);
            var nextKeyName = parseResult.GetValue(nextKeyOption);
            var outputDir = parseResult.GetValue(outputDirOption)!;

            var state = WorkingState.Load(outputDir);
            if (state is null || state.Phase != WorkflowPhase.Initialized)
            {
                Console.Error.WriteLine("Error: Run 'new-did' first (expected phase: Initialized).");
                return;
            }

            if (prerotation && nextKeyName is null)
            {
                Console.Error.WriteLine("Error: --next-key is required when --prerotation is enabled.");
                return;
            }

            if (prerotation && nextKeyName is not null)
            {
                var nextKey = KeyStore.GetKeyPair(outputDir, nextKeyName);
                if (nextKey is null)
                {
                    Console.Error.WriteLine($"Error: Key '{nextKeyName}' not found.");
                    return;
                }

                var commitment = PreRotationManager.ComputeKeyCommitment(nextKey.MultibasePublicKey);
                Console.WriteLine($"  Pre-rotation commitment: {commitment}");
            }

            state.Prerotation = prerotation;
            state.Portable = portable;
            state.Ttl = ttl;
            state.NextKeyName = nextKeyName;
            state.Phase = WorkflowPhase.ParamsSet;

            WorkingState.Save(outputDir, state);

            Console.WriteLine("Parameters set:");
            Console.WriteLine($"  Prerotation: {prerotation}");
            Console.WriteLine($"  Portable:    {portable}");
            if (ttl.HasValue)
                Console.WriteLine($"  TTL:         {ttl}");
            if (nextKeyName is not null)
                Console.WriteLine($"  Next key:    {nextKeyName}");
        });

        return command;
    }
}
