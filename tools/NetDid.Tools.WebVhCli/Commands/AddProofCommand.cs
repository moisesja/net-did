using System.CommandLine;
using NetDid.Core.Crypto;
using NetDid.Core.Crypto.DataIntegrity;
using NetDid.Method.WebVh;
using NetDid.Method.WebVh.Model;
using NetDid.Tools.WebVhCli.State;

namespace NetDid.Tools.WebVhCli.Commands;

internal static class AddProofCommand
{
    public static Command Create()
    {
        var keyOption = new Option<string>("--key") { Description = "Name of the signing key", Required = true };
        var outputDirOption = CommonOptions.OutputDir();

        var command = new Command("add-proof", "Sign the log entry with a Data Integrity Proof");
        command.Options.Add(keyOption);
        command.Options.Add(outputDirOption);

        command.SetAction(async parseResult =>
        {
            var keyName = parseResult.GetValue(keyOption)!;
            var outputDir = parseResult.GetValue(outputDirOption)!;

            var state = WorkingState.Load(outputDir);
            if (state is null ||
                (state.Phase != WorkflowPhase.VmAdded && state.Phase != WorkflowPhase.VersionIdSet))
            {
                Console.Error.WriteLine("Error: Run 'add-vm' or 'gen-version-id' first (expected phase: VmAdded or VersionIdSet).");
                return;
            }

            var keyPair = KeyStore.GetKeyPair(outputDir, keyName);
            if (keyPair is null)
            {
                Console.Error.WriteLine($"Error: Key '{keyName}' not found.");
                return;
            }

            var crypto = new DefaultCryptoProvider();
            var signer = new KeyPairSigner(keyPair, crypto);
            var proofEngine = new DataIntegrityProofEngine(crypto);

            var jsonWithoutProof = state.LogEntryJson!;
            var entry = LogEntrySerializer.DeserializeEntry(jsonWithoutProof);

            var proof = await proofEngine.CreateProofAsync(
                jsonWithoutProof, signer, "assertionMethod",
                entry.VersionTime);

            entry.Proof =
            [
                new DataIntegrityProofValue
                {
                    Type = proof.Type,
                    Cryptosuite = proof.Cryptosuite,
                    VerificationMethod = proof.VerificationMethod,
                    Created = proof.Created.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"),
                    ProofPurpose = proof.ProofPurpose,
                    ProofValue = proof.ProofValue
                }
            ];

            state.ProofJson = LogEntrySerializer.Serialize(entry);
            state.Phase = WorkflowPhase.ProofAdded;
            WorkingState.Save(outputDir, state);

            Console.WriteLine("Proof added:");
            Console.WriteLine($"  Cryptosuite:          {proof.Cryptosuite}");
            Console.WriteLine($"  Verification method:  {proof.VerificationMethod}");
            Console.WriteLine($"  Proof purpose:        {proof.ProofPurpose}");
            Console.WriteLine($"  Proof value:          {proof.ProofValue[..40]}...");
        });

        return command;
    }
}
