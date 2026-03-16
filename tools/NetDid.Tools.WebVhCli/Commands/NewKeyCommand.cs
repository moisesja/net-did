using System.CommandLine;
using NetDid.Core.Crypto;
using NetDid.Tools.WebVhCli.State;

namespace NetDid.Tools.WebVhCli.Commands;

internal static class NewKeyCommand
{
    public static Command Create()
    {
        var nameOption = new Option<string>("--name") { Description = "Name for the key pair", Required = true };
        var outputDirOption = CommonOptions.OutputDir();

        var command = new Command("new-key", "Generate a new Ed25519 key pair");
        command.Options.Add(nameOption);
        command.Options.Add(outputDirOption);

        command.SetAction(parseResult =>
        {
            var name = parseResult.GetValue(nameOption)!;
            var outputDir = parseResult.GetValue(outputDirOption)!;

            var keyGen = new DefaultKeyGenerator();
            var keyPair = keyGen.Generate(KeyType.Ed25519);

            KeyStore.AddKey(outputDir, name, keyPair);

            var didKey = $"did:key:{keyPair.MultibasePublicKey}";
            Console.WriteLine($"Key generated: {name}");
            Console.WriteLine($"  Multibase public key: {keyPair.MultibasePublicKey}");
            Console.WriteLine($"  did:key DID:          {didKey}");
            Console.WriteLine($"  Saved to:             {KeyStore.GetPath(outputDir)}");
        });

        return command;
    }
}
