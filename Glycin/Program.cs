/**
 *  fuck you fuck you fuck you fuck you fuck you fuck you fuck you fuck you fuck you fuck you fuck you fuck you
 *  fuck you fuck you fuck you fuck you fuck you fuck you fuck you fuck you fuck you fuck you fuck you fuck you
 *  fuck you fuck you fuck you fuck you fuck you fuck you fuck you fuck you fuck you fuck you fuck you fuck you
 *  fuck you fuck you fuck you fuck you fuck you fuck you fuck you for making me write this, carx technologies.
 *
 * fun puzzle to solve tho.
 */

namespace Glycin;

using System.Buffers.Binary;
using System.Reflection;
using System.Text.Json;
using ELFSharp.ELF;
using ELFSharp.ELF.Sections;
using Glycin.Analysis;
using Glycin.Cryptography;
using Glycin.DataModel;
using Iced.Intel;
using PeNet;
using PeNet.Header.Pe;
using Decoder = Iced.Intel.Decoder;

internal static class Program
{
    internal static void TerminateIf(Func<bool> condition, string message)
    {
        if (condition())
        {
            Log.Error(message);
            Environment.Exit(1);
        }
    }

    private static ExecutableInfo LoadPE(string filePath)
    {
        var rawBytes = File.ReadAllBytes(filePath);
        var pe = new PeFile(rawBytes);

        var sections = pe.ImageSectionHeaders;
        TerminateIf(
            () => sections == null || sections.Length == 0,
            "specified image has no section headers."
        );

        var optHeader = pe.ImageNtHeaders?.OptionalHeader;
        TerminateIf(
            () => optHeader == null,
            "specified image is missing an optional header."
        );

        ulong imageBase = optHeader!.ImageBase;

        var textHeader = sections!.FirstOrDefault(s => CleanSectionName(s.Name) == ".text");
        TerminateIf(
            () => textHeader == null,
            "missing .text section in the specified image."
        );

        var rdataHeader = sections!.FirstOrDefault(s => CleanSectionName(s.Name) == ".rdata");
        TerminateIf(
            () => rdataHeader == null,
            "missing .rdata section in the specified image."
        );

        var textBytes = ExtractSectionBytes(textHeader!);
        ulong textBase = imageBase + textHeader!.VirtualAddress;

        var rdataBytes = ExtractSectionBytes(rdataHeader!);
        ulong rdataBase = imageBase + rdataHeader!.VirtualAddress;
        ulong rdataEnd = rdataBase + rdataHeader.VirtualSize;

        return new(
            textBytes,
            textBase,
            rdataBytes,
            rdataBase,
            rdataEnd,
            imageBase
        );

        byte[] ExtractSectionBytes(ImageSectionHeader header)
        {
            var offset = (int)header.PointerToRawData;
            var size = (int)Math.Min(header.SizeOfRawData,
                header.VirtualSize != 0 ? header.VirtualSize : header.SizeOfRawData);

            var buffer = new byte[size];
            Array.Copy(rawBytes, offset, buffer, 0, size);
            return buffer;
        }

        static string CleanSectionName(string? rawName) =>
            rawName?.TrimEnd('\0', ' ') ?? string.Empty;
    }

    private static ExecutableInfo LoadELF(string filePath)
    {
        using var elf = ELFReader.Load(filePath);
        var sections = elf.GetSections<Section<ulong>>().ToArray();

        var textSection = sections.FirstOrDefault(x => x.Name == ".text");
        TerminateIf(
            () => textSection == null,
            "missing .text section in the specified image."
        );

        var rodataSection = sections.FirstOrDefault(x => x.Name == ".rodata");
        TerminateIf(
            () => textSection == null,
            "missing .rodata section in the specified image."
        );

        var textBytes = textSection!.GetContents();
        ulong textBase = textSection.LoadAddress;

        byte[] rodataBytes = rodataSection!.GetContents();
        ulong rodataBase = rodataSection.LoadAddress;
        ulong rodataEnd = rodataBase + rodataSection.Size;

        return new(
            textBytes,
            textBase,
            rodataBytes,
            rodataBase,
            rodataEnd
        );
    }
    
    private static bool IsPE(string filePath)
    {
        using var fs = new FileStream(
            filePath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read
        );
        
        if (fs.Length < 2)
        {
            return false;
        }
        
        Span<byte> magic = stackalloc byte[2];
        fs.ReadExactly(magic);
        
        return magic[0] == 0x4D 
            && magic[1] == 0x5A;
    }

    private static string MakeOutPath(string fileName) => Path.Combine(
        $"{Environment.CurrentDirectory}",
        fileName
    );

    private static void WriteTextFile(string fileName, Func<string> textProvider)
    {
        using (var sw = new StreamWriter(MakeOutPath(fileName)))
        {
            sw.WriteLine(textProvider());
        }
    }

    private static void WriteBinaryFile(string fileName, Func<byte[]> dataProvider)
    {
        File.WriteAllBytes(
            MakeOutPath(fileName),
            dataProvider()
        );
    }

    private static readonly List<PointOfInterest> _pointsOfInterest =
    [
        new("assembliesCount", (0x80 + 0), 4),
        new("assembliesCount", (0x80 + 0), 4),
        new("imagesCount", (0x248 + 0), 4)
    ];

    private static void PrintPOIs(Span<byte> hSpan)
    {
        foreach (var poi in _pointsOfInterest)
        {
            var value = BinaryPrimitives.ReadInt32LittleEndian(
                hSpan.Slice(
                    poi.OffsetInHeader,
                    poi.Size
                )
            );

            Log.Info($"{poi}: {value:X16} ({value})");
        }
    }

    private static byte[] ReconstructData(ReadOnlySpan<byte> encryptedData, List<DecryptionVector> vecs)
    {
        var outBytes = encryptedData.ToArray();
        var outSpan = outBytes.AsSpan();

        /* we're analyzing elf and first loop decrypts global-metadata.dat. delete that shit. */
        if (vecs.Count > 0 
            && vecs[0].LengthKind == VectorLengthKind.ImmConstant 
            && vecs[0].LengthOrFieldOffset <= 32)
        {
            vecs.RemoveAt(0);
        }
        
        if (vecs.Count == 0)
            throw new InvalidDataException("no decryption vectors detected.");
        
        var hVec = vecs[0];
        if (hVec.LengthKind != VectorLengthKind.ImmConstant)
            throw new InvalidDataException("expected first vec to be constant.");

        var hSize = hVec.LengthOrFieldOffset;
        var hSpan = outSpan[..hSize];
        Xorshift64.Decrypt(
            hSpan,
            hVec.Seed,
            hVec.SBox
        );

        // PrintPOIs(hSpan);

        for (var i = 1; i < vecs.Count; i++)
        {
            var vec = vecs[i];

            if (vec.LengthKind != VectorLengthKind.Calculated)
            {
                Log.Warn($"the fuck? vec 0x{i:X} should be an offset into the file. but wasn't. skipped.");
                continue;
            }

            /**
             * yeaiknow V, local funcs are cursed.
             * but so is this encryption.
             *
             * fair's fair.
             **/
            bool InBounds()
            {
                if (vec.LengthOrFieldOffset + 4 > hSize)
                {
                    Log.Warn(
                        $"vec 0x{i:X} field offset out of bounds: ({vec.LengthOrFieldOffset:X8} + 4) > {hSize:X8}.");
                    return false;
                }

                return true;
            }

            if (!InBounds())
            {
                continue;
            }

            var vecLen = BinaryPrimitives.ReadInt32LittleEndian(
                hSpan.Slice(vec.LengthOrFieldOffset, 4)
            );

            if (vecLen == 0)
            {
                Log.Warn($"vec 0x{i:X} is empty for some reason. moving on...");
                continue;
            }

            if (!InBounds())
            {
                continue;
            }

            var rawOffset = BinaryPrimitives.ReadInt32LittleEndian(
                hSpan.Slice(vec.HeaderOffsetField, 4)
            );

            /* wtf??? some vectors end up out of bounds unless... mod arith..? */
            var tgtOffset = (int)((uint)rawOffset + (uint)vec.OffsetBaseDelta);
            if (tgtOffset < 0 || tgtOffset + vecLen > outSpan.Length)
            {
                Log.Warn(
                    $"vec 0x{i:X} out of bounds: (0x{tgtOffset:X8} + 0x{vecLen:X8}) > ({outSpan.Length:X8}). skipped.");
                continue;
            }

            Xorshift64.Decrypt(
                outSpan.Slice(tgtOffset, vecLen),
                vec.Seed,
                vec.SBox
            );

            Log.Info($"vec 0x{i:X}: ok");
        }

        return outBytes;
    }

    internal static void Main(string[] args)
    {
        TerminateIf(
            () => args.Length != 1,
            $"usage: {Path.GetFileNameWithoutExtension(Assembly.GetExecutingAssembly().Location)} <filepath>"
        );

        var filePath = args[0];
        TerminateIf(
            () => !File.Exists(filePath),
            $"file not found: {filePath}"
        );

        ExecutableInfo execInfo;
        VectorScanner vectorScanner;
        if (IsPE(filePath))
        {
            Log.Info(
                "seems to be a pe image... " +
                "let's see how it goes."
            );
            
            execInfo = LoadPE(filePath);
            vectorScanner = new PeVectorScanner(execInfo);
        }
        else
        {
            Log.Info(
                "seems to be an elf image... " +
                "you better not be on mac os because i have ptsd related to that platform."
            );

            execInfo = LoadELF(filePath);
            vectorScanner = new ElfVectorScanner(execInfo);
        }
        
        var codeReader = new ByteArrayCodeReader(execInfo.Text);
        var decoder = Decoder.Create(64, codeReader);
        decoder.IP = execInfo.TextBaseAddress;

        Log.Info("decoding... might take a while.");
        var insns = new List<Instruction>();
        while (codeReader.CanReadByte)
        {
            decoder.Decode(out var insn);
            insns.Add(insn);
        }

        Log.Info("here goes... scanning for decryption vectors.");
        var vecs = vectorScanner.Scan(insns);

        Log.Info($"found {vecs.Count} decryption vectors.");
        foreach (var vec in vecs)
        {
            Console.WriteLine(vec);
        }

        Log.Info("generating c# utility class...");
        WriteTextFile(
            "Glycin.Vectors.g.cs",
            () => CodeGen.GenerateDecryptionConfigClass(vecs, "GlycinVectors")
        );

        Log.Info("generating json config...");
        WriteTextFile(
            "glycin.vectors.json",
            () => JsonSerializer.Serialize(vecs, new JsonSerializerOptions
            {
                WriteIndented = true,
                IndentSize = 2
            })
        );

        var absPath = Path.GetFullPath(filePath);
        var dirs = Directory.GetDirectories(Path.GetDirectoryName(absPath)!);
        var tgtDir = dirs.FirstOrDefault(x => x.EndsWith("_Data"));

        if (tgtDir != null)
        {
            var globalMetadataPath = Path.Combine(
                tgtDir,
                "il2cpp_data",
                "Metadata",
                "global-metadata.dat"
            );

            if (File.Exists(globalMetadataPath))
            {
                Log.Info("found global metadata file near the game assembly. attempting decryption...");
                try
                {
                    WriteBinaryFile(
                        "global-metadata-decrypted.dat",
                        () => ReconstructData(
                            File.ReadAllBytes(globalMetadataPath),
                            vecs
                        )
                    );
                }
                catch (Exception e)
                {
                    Log.Error("lol. failed.");
                    Console.WriteLine(e);
                }
            }
        }

        Log.Info("i'm done. now fuck off.");
    }
}