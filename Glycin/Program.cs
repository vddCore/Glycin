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

    private static ElfInfo LoadElf(string filePath)
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

    private static byte[] ReconstructData(ReadOnlySpan<byte> encryptedData, List<DecryptionVector> vecs)
    {
        var outBytes = encryptedData.ToArray();
        var outSpan = outBytes.AsSpan();

        /* var nVec = vecs[0]; // this is irrelevant right now - global-metadata.dat string */
        var hVec = vecs[1];
        if (hVec.LengthKind != VectorLengthKind.ImmConstant)
            throw new InvalidDataException("expected vec 0x1 to be constant.");

        var hSize = hVec.LengthOrFieldOffset;
        var hSpan = outSpan[..hSize];
        Xorshift64.Decrypt(
            hSpan,
            hVec.Seed,
            hVec.SBox
        );

        for (var i = 2; i < vecs.Count; i++)
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
                    Log.Warn($"vec 0x{i:X} field offset out of bounds: ({vec.LengthOrFieldOffset:X8} + 4) > {hSize:X8}.");
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
                Log.Warn($"vec 0x{i:X} out of bounds: (0x{tgtOffset:X8} + 0x{vecLen:X8}) > ({outSpan.Length:X8}). skipped.");
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

        var elfInfo = LoadElf(filePath);

        var codeReader = new ByteArrayCodeReader(elfInfo.Text);
        var decoder = Decoder.Create(64, codeReader);
        decoder.IP = elfInfo.TextBaseAddress;

        Log.Info("decoding... might take a while.");
        var insns = new List<Instruction>();
        while (codeReader.CanReadByte)
        {
            decoder.Decode(out var insn);
            insns.Add(insn);
        }

        Log.Info("here goes... scanning for decryption vectors.");
        var vecs = new VectorScanner(elfInfo).Scan(insns);

        Log.Info($"found {vecs.Count} decryption vectors.");
        // foreach (var vec in vecs)
        // {
        //     Console.WriteLine(vec);
        // }

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