# NepMetadata
nep nep

# Requirements
- .Net 10
- At least 5 brain cells

# How to use
- Compile via Visual Studio 2026 or the `dotnet build` command
- Usage: `NepMetadataDecryptor.exe <global-metadata.dat> [decrypted-metadata.dat] [-uv|--unity-version <version>] [-up|--unity-player <path>]`

## Notes

NEP2's encryption strips away the metadata version.\
By default the tool will attempt to assume the metadata version based on header.\
It is highly recommended to specify `UnityPlayer.dll` path or unity version.\
You can also put `globalgamemanagers`/`UnityPlayer.dll`/`GameAssembly.dll` near the metadata so the tool can determine the version more accurately.

# I DO NOT CLAIM ANY RESPONSIBILITY FOR ANY USAGE OF THIS SOFTWARE, THE SOFTWARE IS MADE 100% FOR EDUCATIONAL PURPOSES ONLY

Copyright© Hiro420