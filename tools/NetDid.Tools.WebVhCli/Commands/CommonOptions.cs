using System.CommandLine;

namespace NetDid.Tools.WebVhCli.Commands;

internal static class CommonOptions
{
    public static Option<string> OutputDir()
    {
        return new Option<string>("--output-dir")
        {
            Description = "Output directory for state and artifact files",
            DefaultValueFactory = _ => "."
        };
    }
}
