using System.CommandLine;
using System.Text;
using NetDid.Method.WebVh;
using NetDid.Tools.WebVhCli.State;

namespace NetDid.Tools.WebVhCli.Commands;

internal static class NewDidCommand
{
    public static Command Create()
    {
        var domainOption = new Option<string>("--domain") { Description = "Domain for the DID (e.g., example.com)", Required = true };
        var pathOption = new Option<string?>("--path") { Description = "Optional path segment (e.g., users/alice)" };
        var updateKeyOption = new Option<string>("--update-key") { Description = "Name of the key to use as update key", Required = true };
        var outputDirOption = CommonOptions.OutputDir();

        var command = new Command("new-did", "Initialize a new did:webvh creation workflow");
        command.Options.Add(domainOption);
        command.Options.Add(pathOption);
        command.Options.Add(updateKeyOption);
        command.Options.Add(outputDirOption);

        command.SetAction(parseResult =>
        {
            var domain = parseResult.GetValue(domainOption)!;
            var path = parseResult.GetValue(pathOption);
            var updateKeyName = parseResult.GetValue(updateKeyOption)!;
            var outputDir = parseResult.GetValue(outputDirOption)!;

            var keyPair = KeyStore.GetKeyPair(outputDir, updateKeyName);
            if (keyPair is null)
            {
                Console.Error.WriteLine($"Error: Key '{updateKeyName}' not found. Run 'new-key' first.");
                return;
            }

            var didJsonlPath = Path.Combine(outputDir, "did.jsonl");
            var isUpdate = File.Exists(didJsonlPath);

            var didTemplate = path is not null
                ? $"did:webvh:{{SCID}}:{domain}:{path.Replace("/", ":")}"
                : $"did:webvh:{{SCID}}:{domain}";

            var state = new WorkingStateData
            {
                Phase = WorkflowPhase.Initialized,
                Domain = domain,
                Path = path,
                Did = didTemplate,
                UpdateKeyName = updateKeyName,
                IsUpdate = isUpdate
            };

            if (isUpdate)
            {
                state.ExistingLogContent = File.ReadAllText(didJsonlPath);
                var entries = LogEntrySerializer.ParseJsonLines(Encoding.UTF8.GetBytes(state.ExistingLogContent));
                state.VersionNumber = entries.Count + 1;
                state.Did = entries[0].State.Id.Value;
                Console.WriteLine($"Update mode: found {entries.Count} existing log entries");
            }

            WorkingState.Save(outputDir, state);

            Console.WriteLine($"DID workflow initialized:");
            Console.WriteLine($"  DID template: {state.Did}");
            Console.WriteLine($"  Domain:       {domain}");
            if (path is not null)
                Console.WriteLine($"  Path:         {path}");
            Console.WriteLine($"  Update key:   {updateKeyName} ({keyPair.MultibasePublicKey})");
            Console.WriteLine($"  Mode:         {(isUpdate ? "Update" : "Create")}");
        });

        return command;
    }
}
