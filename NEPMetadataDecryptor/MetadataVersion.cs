using System.Text.RegularExpressions;

namespace NEPMetadataDecryptor;

internal static class MetadataVersion
{
	private static readonly Regex UnityVersionRegex = new(
		@"^(?<major>\d+)\.(?<minor>\d+)\.",
		RegexOptions.Compiled | RegexOptions.CultureInvariant);

	public static uint FromUnityVersion(string version)
	{
		Match match = UnityVersionRegex.Match(version);

		if (!match.Success)
			throw new InvalidDataException($"Invalid Unity version: {version}");

		int major = int.Parse(match.Groups["major"].Value);
		int minor = int.Parse(match.Groups["minor"].Value);

		return (major, minor) switch
		{
			(2018, >= 3) => 24,
			(2019, _) => 24,
			(2020, <= 1) => 24,

			(2020, >= 2) => 27,
			(2021, <= 1) => 27,

			(2021, >= 2) => 29,
			(2022, <= 1) => 29,

			(2022, >= 2) => 31,
			(2023, _) => 31,
			(6000, _) => 31,

			_ => throw new NotSupportedException(
				$"Unknown metadata version for Unity {version}.")
		};
	}
}