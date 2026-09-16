namespace NEPMetadataDecryptor;

internal static class Program
{
	public static int Main(string[] args)
	{
		try
		{
			CommandLineOptions options = CommandLineOptions.Parse(args);
			NepMetadataDecryptor.Run(options);
			return 0;
		}
		catch (Exception ex)
		{
			Console.Error.WriteLine($"[!] {ex.Message}");
			return 1;
		}
	}
}