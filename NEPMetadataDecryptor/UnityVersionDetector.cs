using System.Diagnostics;
using System.Text;
using System.Text.RegularExpressions;

namespace NEPMetadataDecryptor;

internal static class UnityVersionDetector
{
	private static readonly Regex VersionRegex = new(
		@"(?<!\d)(?:20\d{2}|6000)\.\d+\.\d+[abfp]\d+(?:c\d+)?",
		RegexOptions.Compiled | RegexOptions.CultureInvariant);

	public static (string Version, string Source)? FindLocal(string metadataPath)
	{
		string directory = Path.GetDirectoryName(
			Path.GetFullPath(metadataPath))!;

		var visited = new HashSet<string>(
			StringComparer.OrdinalIgnoreCase);

		string[] candidates =
		[
			Path.Combine(directory, "globalgamemanagers"),
			Path.Combine(directory, "UnityPlayer.dll"),
			Path.Combine(directory, "GameAssembly.dll")
		];

		foreach (string candidate in candidates)
		{
			(string Version, string Source)? result =
				TryFile(candidate, visited);

			if (result is not null)
				return result;
		}

		foreach (string exe in Directory.EnumerateFiles(
					 directory,
					 "*.exe",
					 SearchOption.TopDirectoryOnly))
		{
			(string Version, string Source)? result =
				TryFile(exe, visited);

			if (result is not null)
				return result;
		}

		return null;
	}

	public static string? FromFile(string path)
	{
		if (!File.Exists(path))
			throw new FileNotFoundException("Unity binary not found.", path);

		return TryFileVersion(path) ?? ScanFile(path);
	}

	private static (string Version, string Source)? TryFile(
		string path,
		HashSet<string> visited)
	{
		if (!File.Exists(path))
			return null;

		path = Path.GetFullPath(path);

		if (!visited.Add(path))
			return null;

		string? version = FromFile(path);

		return version is null
			? null
			: (version, path);
	}

	private static string? TryFileVersion(string path)
	{
		string extension = Path.GetExtension(path);

		if (!extension.Equals(".dll", StringComparison.OrdinalIgnoreCase) &&
			!extension.Equals(".exe", StringComparison.OrdinalIgnoreCase))
			return null;

		try
		{
			FileVersionInfo info = FileVersionInfo.GetVersionInfo(path);

			string? version =
				Extract(info.ProductVersion) ??
				Extract(info.FileVersion);

			return version;
		}
		catch
		{
			return null;
		}
	}

	private static string? ScanFile(string path)
	{
		const int chunkSize = 1024 * 1024;
		const int overlap = 128;

		using FileStream stream = File.OpenRead(path);

		byte[] buffer = new byte[chunkSize + overlap];

		int carry = 0;

		while (true)
		{
			int read = stream.Read(
				buffer,
				carry,
				chunkSize);

			if (read == 0)
				break;

			int length = carry + read;

			string text = Encoding.ASCII.GetString(
				buffer,
				0,
				length);

			Match match = VersionRegex.Match(text);

			if (match.Success)
				return match.Value;

			carry = Math.Min(overlap, length);

			Buffer.BlockCopy(
				buffer,
				length - carry,
				buffer,
				0,
				carry);
		}

		return null;
	}

	private static string? Extract(string? value)
	{
		if (string.IsNullOrWhiteSpace(value))
			return null;

		Match match = VersionRegex.Match(value);

		return match.Success
			? match.Value
			: null;
	}
}