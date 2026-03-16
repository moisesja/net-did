using System.CommandLine;
using System.Text;
using NetDid.Core.Model;
using NetDid.Method.WebVh;
using NetDid.Method.WebVh.Model;
using NetDid.Tools.WebVhCli.State;

namespace NetDid.Tools.WebVhCli.Commands;

internal static class GenScidInputCommand
{
    public static Command Create()
    {
        var outputDirOption = CommonOptions.OutputDir();

        var command = new Command("gen-scid-input", "Build the genesis log entry template with {SCID} placeholders");
        command.Options.Add(outputDirOption);

        command.SetAction(parseResult =>
        {
            var outputDir = parseResult.GetValue(outputDirOption)!;

            var state = WorkingState.Load(outputDir);
            if (state is null || state.Phase != WorkflowPhase.ParamsSet)
            {
                Console.Error.WriteLine("Error: Run 'did-params' first (expected phase: ParamsSet).");
                return;
            }

            if (state.IsUpdate)
            {
                HandleUpdate(state, outputDir);
                return;
            }

            var updateKey = KeyStore.GetKeyPair(outputDir, state.UpdateKeyName);
            if (updateKey is null)
            {
                Console.Error.WriteLine($"Error: Update key '{state.UpdateKeyName}' not found.");
                return;
            }

            // Build DID template with safe placeholder
            var didTemplate = state.Path is not null
                ? $"did:webvh:{ScidGenerator.SafePlaceholder}:{state.Domain}:{state.Path.Replace("/", ":")}"
                : $"did:webvh:{ScidGenerator.SafePlaceholder}:{state.Domain}";

            // Build the DID Document template
            var didValue = new Did(didTemplate);
            var updateKeyMultibase = updateKey.MultibasePublicKey;
            var vmId = $"{didTemplate}#{updateKeyMultibase}";

            var docTemplate = new DidDocument
            {
                Id = didValue,
                AlsoKnownAs = [BuildDidWebEquivalent(state)],
                VerificationMethod =
                [
                    new VerificationMethod
                    {
                        Id = vmId,
                        Type = "Multikey",
                        Controller = didValue,
                        PublicKeyMultibase = updateKeyMultibase
                    }
                ],
                Authentication = [VerificationRelationshipEntry.FromReference(vmId)],
                AssertionMethod = [VerificationRelationshipEntry.FromReference(vmId)],
                CapabilityInvocation = [VerificationRelationshipEntry.FromReference(vmId)],
                CapabilityDelegation = [VerificationRelationshipEntry.FromReference(vmId)]
            };

            // Build genesis parameters
            var genesisParams = BuildGenesisParameters(state, updateKey.MultibasePublicKey, outputDir);

            var genesisEntry = new LogEntry
            {
                VersionId = $"1-{ScidGenerator.SafePlaceholder}",
                VersionTime = DateTimeOffset.UtcNow,
                Parameters = genesisParams,
                State = docTemplate
            };

            // Serialize with safe placeholder, then swap to spec-level {SCID}
            var json = LogEntrySerializer.SerializeWithoutProof(genesisEntry);
            json = json.Replace(ScidGenerator.SafePlaceholder, ScidGenerator.Placeholder);

            state.LogEntryJson = json;
            state.Phase = WorkflowPhase.ScidInputReady;
            WorkingState.Save(outputDir, state);

            Console.WriteLine("Genesis log entry template (with {SCID} placeholders):");
            Console.WriteLine(json);
        });

        return command;
    }

    private static void HandleUpdate(WorkingStateData state, string outputDir)
    {
        var updateKey = KeyStore.GetKeyPair(outputDir, state.UpdateKeyName);
        if (updateKey is null)
        {
            Console.Error.WriteLine($"Error: Update key '{state.UpdateKeyName}' not found.");
            return;
        }

        var entries = LogEntrySerializer.ParseJsonLines(Encoding.UTF8.GetBytes(state.ExistingLogContent!));
        var previousEntry = entries[^1];

        var newDocument = previousEntry.State;

        var newParams = new LogEntryParameters();
        if (state.Prerotation)
        {
            var nextKey = state.NextKeyName is not null ? KeyStore.GetKeyPair(outputDir, state.NextKeyName) : null;
            newParams = new LogEntryParameters
            {
                UpdateKeys = [updateKey.MultibasePublicKey],
                Prerotation = true,
                NextKeyHashes = nextKey is not null
                    ? [PreRotationManager.ComputeKeyCommitment(nextKey.MultibasePublicKey)]
                    : null
            };
        }

        var updateEntry = new LogEntry
        {
            VersionId = $"{state.VersionNumber}-{previousEntry.VersionId}",
            VersionTime = DateTimeOffset.UtcNow,
            Parameters = newParams,
            State = newDocument
        };

        var json = LogEntrySerializer.SerializeWithoutProof(updateEntry);

        state.LogEntryJson = json;
        state.Phase = WorkflowPhase.ScidInputReady;
        WorkingState.Save(outputDir, state);

        Console.WriteLine("Update log entry template:");
        Console.WriteLine(json);
    }

    private static LogEntryParameters BuildGenesisParameters(WorkingStateData state, string updateKeyMultibase, string outputDir)
    {
        IReadOnlyList<string>? nextKeyHashes = null;
        if (state.Prerotation && state.NextKeyName is not null)
        {
            var nextKey = KeyStore.GetKeyPair(outputDir, state.NextKeyName);
            if (nextKey is not null)
                nextKeyHashes = [PreRotationManager.ComputeKeyCommitment(nextKey.MultibasePublicKey)];
        }

        return new LogEntryParameters
        {
            Method = "did:webvh:1.0",
            Scid = ScidGenerator.Placeholder,
            UpdateKeys = [updateKeyMultibase],
            Prerotation = state.Prerotation ? true : null,
            NextKeyHashes = nextKeyHashes,
            Deactivated = false
        };
    }

    private static string BuildDidWebEquivalent(WorkingStateData state)
    {
        var didWeb = $"did:web:{state.Domain}";
        if (state.Path is not null)
            didWeb += $":{state.Path.Replace("/", ":")}";
        return didWeb;
    }
}
