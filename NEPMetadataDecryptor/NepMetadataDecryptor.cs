using System.Buffers.Binary;

namespace NEPMetadataDecryptor;

internal static class NepMetadataDecryptor
{
    public static void Run(CommandLineOptions options)
    {
        Log($"Reading {options.Input}");

        var data = File.ReadAllBytes(options.Input);

        if (data.Length < 8 ||
            ReadU32(data, 0) != 0xFAB11BAF)
            throw new InvalidDataException(
                "Not a protected IL2CPP metadata file.");

        var protectedSize = ReadU32(data, 4);

        if (protectedSize != data.Length)
            throw new InvalidDataException(
                $"Invalid protected size: 0x{protectedSize:X8} " +
                $"(file is 0x{data.Length:X8}).");

        Log($"Decrypting {data.Length - 8:N0} bytes...");

        Decrypt(data.AsSpan(8));

        var metadataVersion = ResolveMetadataVersion(
            options,
            data);

        WriteU32(
            data,
            4,
            metadataVersion);

        File.WriteAllBytes(
            options.Output,
            data);

        Log($"Wrote {options.Output}");
    }

    private static uint ResolveMetadataVersion(
        CommandLineOptions options,
        ReadOnlySpan<byte> metadata)
    {
        if (options.UnityVersion is not null)
        {
            Log($"Unity version: {options.UnityVersion} (argument)");

            return MetadataVersion.FromUnityVersion(
                options.UnityVersion);
        }

        if (options.UnityPlayer is not null)
        {
            var version = UnityVersionDetector.FromFile(
                options.UnityPlayer);

            if (version is null)
                throw new InvalidDataException(
                    $"Could not determine Unity version from " +
                    $"{options.UnityPlayer}.");

            Log($"Unity version: {version} ({options.UnityPlayer})");

            return MetadataVersion.FromUnityVersion(
                version);
        }

        var detected =
            UnityVersionDetector.FindLocal(options.Input);

        if (detected is not null)
        {
            Log(
                $"Unity version: {detected.Value.Version} " +
                $"({detected.Value.Source})");

            return MetadataVersion.FromUnityVersion(
                detected.Value.Version);
        }

        var guess =
            MetadataVersionDetector.Guess(metadata);

        Log(
            $"Unity version not found. Assuming metadata " +
            $"version {guess.Version} from decrypted header " +
            $"({guess.Reason}).");

        return guess.Version;
    }

    private static void Decrypt(Span<byte> data)
    {
        unchecked
        {
            var table = BuildTable();
            var seed = DeriveSeed(data.Length, table);

            if (data.Length <= 0x80)
            {
                Crypt(data, seed);
                return;
            }

            var tempBytes = data[..0x80].ToArray();
            var original = ReadWords(data[..0x80]);

            var tempKey = seed ^ original[6];

            Crypt(tempBytes, tempKey);

            var temp = ReadWords(tempBytes);

            uint[] keys =
            [
                (original[8] + 0x0008195E) ^ seed,
                (original[19] + 0x00075568) ^ tempKey,
                (temp[11] + 0x003482A5) ^ seed,
                (temp[15] + 0x00A7498D) ^ tempKey
            ];

            var s0 = temp[3] ^ 0x03914F13;
            var s1 = keys[3] ^ 0x0034E00E;
            var s7 = s1 ^ keys[2];
            var s5 = keys[1] ^ 0x00836E4C;
            var s2 = temp[7] ^ s0;
            var s4 = s5 ^ keys[0];
            var s3 = temp[8] ^ s7;
            var s6 = original[4] ^ 0x031BB9B1;
            var s8 = s4 ^ original[6];

            uint[] selectors =
            [
                s0,
                s1,
                s2,
                s3,
                s4,
                s5,
                s6,
                s7,
                s8
            ];

            Crypt(data[..0x80], seed);

            var fullBlocks =
                (data.Length - 0x80) / 0x80;

            var remaining =
                data.Length & 0x7F;

            for (var blockIndex = 0;
                 blockIndex < fullBlocks;
                 blockIndex++)
            {
                var block = data.Slice(
                    0x80 + blockIndex * 0x80,
                    0x80);

                var mode =
                    selectors[blockIndex % 9] & 3;

                for (var i = 0; i < 32; i++)
                {
                    var value = ReadU32(
                        block,
                        i * 4);

                    value ^= mode switch
                    {
                        0 =>
                            temp[i] ^
                            keys[(int)(temp[i] & 3)] ^
                            (uint)i,

                        1 =>
                            temp[i] ^
                            keys[(int)(selectors[i % 9] & 3)] ^
                            (uint)i,

                        2 =>
                            temp[i] ^
                            selectors[i % 9] ^
                            (uint)(32 - i),

                        3 =>
                            temp[i] ^
                            keys[(int)(temp[i] & 3)],

                        _ => 0
                    };

                    WriteU32(
                        block,
                        i * 4,
                        value);
                }
            }

            if (remaining == 0)
                return;

            var tail =
                data[^remaining..];

            for (var i = 0; i < remaining; i++)
            {
                var selector =
                    selectors[(int)(keys[i & 3] % 9)];

                var value =
                    (byte)(selector % 255);

                tail[i] ^= (byte)(
                    value ^
                    tempBytes[i] ^
                    (byte)i);
            }
        }
    }

    private static uint[] BuildTable()
    {
        const uint polynomial = 0x09823D6E;

        var table = new uint[256];

        for (uint i = 0; i < 256; i++)
        {
            var value = i;

            for (var bit = 0; bit < 8; bit++)
                value = (value & 1) != 0
                    ? (value ^ polynomial) >> 1
                    : value >> 1;

            table[i] = value;
        }

        return table;
    }

    private static uint DeriveSeed(
        int length,
        uint[] table)
    {
        unchecked
        {
            var size = (uint)length;

            var value =
                table[(byte)~size] ^
                0x00FFFFFF;

            value += 0x10;

            for (var shift = 8;
                 shift <= 24;
                 shift += 8)
            {
                var index = (byte)(
                    (byte)value ^
                    (byte)(size >> shift));

                value =
                    (value >> 8) ^
                    table[index];

                value += 0x10;
            }

            return ~value - 0x7D29C488;
        }
    }

    private static void Crypt(
        Span<byte> data,
        uint key)
    {
        Span<byte> state =
            stackalloc byte[256];

        for (var i = 0; i < state.Length; i++)
            state[i] = (byte)i;

        Span<byte> keyBytes =
            stackalloc byte[4];

        BinaryPrimitives.WriteUInt32LittleEndian(
            keyBytes,
            key);

        byte j = 0;

        for (var i = 0; i < 256; i++)
        {
            var a = state[i];

            j = (byte)(
                j +
                a +
                keyBytes[i & 3]);

            (state[i], state[j]) =
                (state[j], state[i]);
        }

        byte x = 0;
        j = 0;

        for (var n = 0; n < data.Length; n++)
        {
            x++;

            var a = state[x];

            j = (byte)(j + a);

            var b = state[j];

            state[x] = b;
            state[j] = a;

            var stream =
                state[(byte)(a + b)];

            stream = (byte)(
                (stream >> 2) |
                (stream << 6));

            stream += 0x3A;

            data[n] ^= stream;
        }
    }

    private static uint[] ReadWords(
        ReadOnlySpan<byte> data)
    {
        var words =
            new uint[data.Length / 4];

        for (var i = 0; i < words.Length; i++)
            words[i] = ReadU32(
                data,
                i * 4);

        return words;
    }

    private static uint ReadU32(
        ReadOnlySpan<byte> data,
        int offset)
    {
        return BinaryPrimitives.ReadUInt32LittleEndian(
            data.Slice(offset, 4));
    }

    private static void WriteU32(
        Span<byte> data,
        int offset,
        uint value)
    {
        BinaryPrimitives.WriteUInt32LittleEndian(
            data.Slice(offset, 4),
            value);
    }

    private static void Log(string message)
    {
        Console.WriteLine($"[*] {message}");
    }
}