namespace NEPMetadataDecryptor;

internal sealed record CommandLineOptions(
    string Input,
    string Output,
    string? UnityVersion,
    string? UnityPlayer)
{
    public static CommandLineOptions Parse(string[] args)
    {
        var positional = new List<string>();

        string? unityVersion = null;
        string? unityPlayer = null;

        for (var i = 0; i < args.Length; i++)
            switch (args[i])
            {
                case "--unity-version":
                case "-uv":
                    if (++i >= args.Length)
                        throw new ArgumentException("Missing value for --unity-version.");

                    unityVersion = args[i];
                    break;

                case "--unity-player":
                case "-up":
                    if (++i >= args.Length)
                        throw new ArgumentException("Missing value for --unity-player.");

                    unityPlayer = args[i];
                    break;

                default:
                    if (args[i].StartsWith('-'))
                        throw new ArgumentException($"Unknown option: {args[i]}");

                    positional.Add(args[i]);
                    break;
            }

        if (positional.Count is < 1 or > 2)
            throw new ArgumentException(
                "Usage: NepMetadataDecryptor <global-metadata.dat> [decrypted-metadata.dat] " +
                "[-uv|--unity-version <version>] [-up|--unity-player <path>]");

        var input = positional[0];

        var output = positional.Count == 2
            ? positional[1]
            : Path.Combine(
                Path.GetDirectoryName(Path.GetFullPath(input))!,
                "decrypted-metadata.dat");

        return new CommandLineOptions(
            input,
            output,
            unityVersion,
            unityPlayer);
    }
}