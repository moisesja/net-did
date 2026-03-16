using System.CommandLine;
using NetDid.Core.Model;
using NetDid.Method.WebVh;
using NetDid.Tools.WebVhCli.State;

namespace NetDid.Tools.WebVhCli.Commands;

internal static class AddVmCommand
{
    private static readonly string[] ValidRelationships =
        ["authentication", "assertionMethod", "keyAgreement", "capabilityInvocation", "capabilityDelegation"];

    public static Command Create()
    {
        var keyOption = new Option<string>("--key") { Description = "Name of the key to add as a verification method", Required = true };
        var relationshipOption = new Option<string>("--relationship")
        {
            Description = "Verification relationship (authentication, assertionMethod, keyAgreement, capabilityInvocation, capabilityDelegation)",
            Required = true
        };
        var outputDirOption = CommonOptions.OutputDir();

        var command = new Command("add-vm", "Add a verification method to the DID Document");
        command.Options.Add(keyOption);
        command.Options.Add(relationshipOption);
        command.Options.Add(outputDirOption);

        command.SetAction(parseResult =>
        {
            var keyName = parseResult.GetValue(keyOption)!;
            var relationship = parseResult.GetValue(relationshipOption)!;
            var outputDir = parseResult.GetValue(outputDirOption)!;

            var state = WorkingState.Load(outputDir);
            if (state is null || (state.Phase != WorkflowPhase.VersionIdSet && state.Phase != WorkflowPhase.VmAdded))
            {
                Console.Error.WriteLine("Error: Run 'gen-version-id' first (expected phase: VersionIdSet or VmAdded).");
                return;
            }

            if (!ValidRelationships.Contains(relationship))
            {
                Console.Error.WriteLine($"Error: Invalid relationship '{relationship}'. Must be one of: {string.Join(", ", ValidRelationships)}");
                return;
            }

            var keyPair = KeyStore.GetKeyPair(outputDir, keyName);
            if (keyPair is null)
            {
                Console.Error.WriteLine($"Error: Key '{keyName}' not found.");
                return;
            }

            var entry = LogEntrySerializer.DeserializeEntry(state.LogEntryJson!);

            var multibaseKey = keyPair.MultibasePublicKey;
            var vmId = $"{state.Did}#{multibaseKey}";
            var newVm = new VerificationMethod
            {
                Id = vmId,
                Type = "Multikey",
                Controller = new Did(state.Did!),
                PublicKeyMultibase = multibaseKey
            };

            var verificationMethods = entry.State.VerificationMethod?.ToList() ?? [];
            if (!verificationMethods.Any(v => v.Id == vmId))
                verificationMethods.Add(newVm);

            var relationshipRef = VerificationRelationshipEntry.FromReference(vmId);
            var updatedDoc = AddToRelationship(entry.State, relationship, relationshipRef, verificationMethods);

            var updatedEntry = new NetDid.Method.WebVh.Model.LogEntry
            {
                VersionId = entry.VersionId,
                VersionTime = entry.VersionTime,
                Parameters = entry.Parameters,
                State = updatedDoc
            };

            state.LogEntryJson = LogEntrySerializer.SerializeWithoutProof(updatedEntry);
            state.VerificationMethods.Add(new VmEntry { KeyName = keyName, Relationship = relationship });
            state.Phase = WorkflowPhase.VmAdded;
            WorkingState.Save(outputDir, state);

            Console.WriteLine($"Verification method added:");
            Console.WriteLine($"  Key:          {keyName}");
            Console.WriteLine($"  VM ID:        {vmId}");
            Console.WriteLine($"  Relationship: {relationship}");
        });

        return command;
    }

    private static DidDocument AddToRelationship(DidDocument doc, string relationship,
        VerificationRelationshipEntry entry, List<VerificationMethod> verificationMethods)
    {
        var auth = doc.Authentication?.ToList() ?? [];
        var assertion = doc.AssertionMethod?.ToList() ?? [];
        var keyAgreement = doc.KeyAgreement?.ToList() ?? [];
        var capInvocation = doc.CapabilityInvocation?.ToList() ?? [];
        var capDelegation = doc.CapabilityDelegation?.ToList() ?? [];

        // Only add if not already referenced in the target relationship
        var vmId = entry.Reference!;
        switch (relationship)
        {
            case "authentication" when !auth.Any(e => e.Reference == vmId): auth.Add(entry); break;
            case "assertionMethod" when !assertion.Any(e => e.Reference == vmId): assertion.Add(entry); break;
            case "keyAgreement" when !keyAgreement.Any(e => e.Reference == vmId): keyAgreement.Add(entry); break;
            case "capabilityInvocation" when !capInvocation.Any(e => e.Reference == vmId): capInvocation.Add(entry); break;
            case "capabilityDelegation" when !capDelegation.Any(e => e.Reference == vmId): capDelegation.Add(entry); break;
        }

        return new DidDocument
        {
            Id = doc.Id,
            AlsoKnownAs = doc.AlsoKnownAs,
            Controller = doc.Controller,
            VerificationMethod = verificationMethods,
            Authentication = auth.Count > 0 ? auth : null,
            AssertionMethod = assertion.Count > 0 ? assertion : null,
            KeyAgreement = keyAgreement.Count > 0 ? keyAgreement : null,
            CapabilityInvocation = capInvocation.Count > 0 ? capInvocation : null,
            CapabilityDelegation = capDelegation.Count > 0 ? capDelegation : null,
            Service = doc.Service,
            Context = doc.Context,
            AdditionalProperties = doc.AdditionalProperties
        };
    }
}
