using System.Buffers.Binary;

namespace NEPMetadataDecryptor;

internal static class MetadataVersionDetector
{
	public static MetadataVersionGuess Guess(ReadOnlySpan<byte> data)
	{
		if (data.Length < 0x20)
			return new(31, "file too small to inspect; modern fallback");

		uint headerSize = ReadU32(data, 0x08);

		if (!LooksLikeMetadataHeader(data, headerSize))
			return new(31, $"unrecognized header layout (first table at 0x{headerSize:X}); modern fallback");

		return headerSize switch
		{
			// Older metadata layouts still contain the metadata-usage offset/count pairs
			0x110 => new(
				24,
				"0x110-byte metadata header"),

			// Modern metadata layouts use the smaller header
			0x100 => new(
				31,
				"0x100-byte modern metadata header"),

			// Aaaand the fallback
			_ => new(
				31,
				$"valid-looking metadata header of size 0x{headerSize:X}")
		};
	}

	private static bool LooksLikeMetadataHeader(
		ReadOnlySpan<byte> data,
		uint headerSize)
	{
		if (headerSize < 0x80 ||
			headerSize > 0x200 ||
			(headerSize & 3) != 0 ||
			headerSize >= data.Length)
		{
			return false;
		}

		const int commonHeaderEnd = 0xB8;

		if (data.Length < commonHeaderEnd)
			return false;

		int validPairs = 0;
		int checkedPairs = 0;

		for (int offset = 0x08;
			 offset + 8 <= commonHeaderEnd;
			 offset += 8)
		{
			uint tableOffset = ReadU32(data, offset);
			uint tableSize = ReadU32(data, offset + 4);

			checkedPairs++;

			if (tableOffset == 0 && tableSize == 0)
			{
				validPairs++;
				continue;
			}

			if (tableOffset < headerSize)
				continue;

			if (tableOffset > data.Length)
				continue;

			if (tableSize > data.Length)
				continue;

			if ((ulong)tableOffset + tableSize > (ulong)data.Length)
				continue;

			validPairs++;
		}

		return validPairs >= checkedPairs - 2;
	}

	private static uint ReadU32(
		ReadOnlySpan<byte> data,
		int offset) =>
		BinaryPrimitives.ReadUInt32LittleEndian(
			data.Slice(offset, 4));
}

internal readonly record struct MetadataVersionGuess(
	uint Version,
	string Reason);