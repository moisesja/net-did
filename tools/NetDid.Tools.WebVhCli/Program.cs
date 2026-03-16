using System.CommandLine;
using NetDid.Tools.WebVhCli.Commands;

var rootCommand = new RootCommand("did:webvh CLI — step-by-step DID creation and management tool");

rootCommand.Subcommands.Add(NewKeyCommand.Create());
rootCommand.Subcommands.Add(NewDidCommand.Create());
rootCommand.Subcommands.Add(DidParamsCommand.Create());
rootCommand.Subcommands.Add(GenScidInputCommand.Create());
rootCommand.Subcommands.Add(GenScidValueCommand.Create());
rootCommand.Subcommands.Add(GenVersionIdCommand.Create());
rootCommand.Subcommands.Add(AddVmCommand.Create());
rootCommand.Subcommands.Add(AddProofCommand.Create());
rootCommand.Subcommands.Add(NewLineCommand.Create());

return rootCommand.Parse(args).Invoke();
