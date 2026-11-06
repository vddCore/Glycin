/**
 *  fuck you fuck you fuck you fuck you fuck you fuck you fuck you fuck you fuck you fuck you fuck you fuck you
 *  fuck you fuck you fuck you fuck you fuck you fuck you fuck you fuck you fuck you fuck you fuck you fuck you
 *  fuck you fuck you fuck you fuck you fuck you fuck you fuck you fuck you fuck you fuck you fuck you fuck you
 *  fuck you fuck you fuck you fuck you fuck you fuck you fuck you for making me write this, carx technologies.
 *
 * fun puzzle to solve tho.
 */

namespace Glycin;

using System.Reflection;
using ELFSharp.ELF;
using ELFSharp.ELF.Sections;
using Glycin.DataModel;
using Iced.Intel;
using Decoder = Iced.Intel.Decoder;

internal static class Program
{
    internal static bool TerminateIf(Func<bool> condition, string message)
    {
        var result = condition();
        if (result)
        {
            Log.Error(message);
            Environment.Exit(1);
        }

        return result;
    }

    private static ElfInfo LoadElf(string filePath)
    {
        using var elf = ELFReader.Load(filePath);
        var sections = elf.GetSections<Section<ulong>>().ToArray();
        
        var textSection = sections.FirstOrDefault(x => x.Name == ".text");
        TerminateIf(
            () => textSection == null,
            "missing .text section in the specified binary image."
        );
        
        var rodataSection = sections.FirstOrDefault(x => x.Name == ".rodata");
        TerminateIf(
            () => rodataSection == null,
            "missing .rodata section in the specified binary image."
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
    
    private static bool IsXorShift64Core(List<Instruction> insns, int index, out Register prngReg)
    {
        prngReg = Register.None;

        if (index + 6 >= insns.Count)
        {
            return false;
        }

        /**
         *  06e416fb 48 bf 30        MOV        RDI,0xafdff1e1dec0830
         *           08 ec 1d
         *           1e ff fd 0a
         *  06e41705 31 c0           XOR        EAX,EAX
         *  06e41707 48 8d 0d        LEA        RCX,[0x324ab90]
         *           82 94 40 fc
         *  06e4170e 66 90           NOP
         *                       LAB_06e41710                                    XREF[1]:     06e41754(j)
         *  06e41710 48 89 fe        MOV        RSI,RDI <------- [index]
         *  06e41713 48 c1 e6 0d     SHL        RSI,0xd <------- [index + 1] => i1
         *  06e41717 48 31 fe        XOR        RSI,RDI
         *  06e4171a 48 89 f5        MOV        RBP,RSI
         *  06e4171d 48 c1 ed 07     SHR        RBP,0x7 <------- [index + 4] => i4
         *  06e41721 48 31 f5        XOR        RBP,RSI <------- X1
         *  06e41724 48 89 ef        MOV        RDI,RBP <------- X2
         *  06e41727 48 c1 e7 11     SHL        RDI,0x11 <------ [index + 7] => i6
         *  06e4172b 48 31 ef        XOR        RDI,RBP
         *  06e4172e 89 fe           MOV        ESI,EDI
         *
         **/
        var i1 = insns[index + 1];
        var i4 = insns[index + 4];
        var i6 = insns[index + 7];

        try
        {
            if (i1.Mnemonic == Mnemonic.Shl && i1.GetImmediate(1) == 0x0D
                                            && i4.Mnemonic == Mnemonic.Shr && i4.GetImmediate(1) == 0x07
                                            && i6.Mnemonic == Mnemonic.Shl && i6.GetImmediate(1) == 0x11)
            {
                prngReg = insns[index].Op1Register; // rdi;
                return true;
            }
        }
        catch
        {
            return false;
        }

        return false;
    }

    private static List<DecryptionSegment> ExtractDecryptionInfo(List<Instruction> insns, ElfInfo elfInfo)
    {
        /* this is not magic. it's arbitrary. */
        const int windowWidth = 42;
        
        var segments = new List<DecryptionSegment>();
        var sboxVa = 0ul;

        for (int i = 0; i < insns.Count - 8; i++)
        {
            var insn = insns[i];

            if (insn is { Mnemonic: Mnemonic.Lea, IsIPRelativeMemoryOperand: true })
            {
                var va = insn.IPRelativeMemoryAddress;
                if (va >= elfInfo.RodataBaseAddress && va + 256 <= elfInfo.RodataEndAddress)
                {
                    sboxVa = va;
                }
            }

            if (IsXorShift64Core(insns, i, out var reg))
            {
                var loopAddr = insn.IP;
                var seed = 0ul;
                var lengthKind = SegmentLengthKind.ImmConstant; /* first one is always constant as per malloc. so far. */
                var lengthOrFieldOffset = 0;
                var headerOffsetField = -1;
                var offsetBaseDelta = 0;
                
                var window = Math.Max(0, i - windowWidth); 
                for (var lb = i - 1; lb >= window; lb--) // lookbehind
                {
                    var prev =  insns[lb];
                    if (prev.Mnemonic == Mnemonic.Mov
                        && prev.Op0Kind == OpKind.Register
                        && prev.Op0Register == reg
                        && prev.Op1Kind == OpKind.Immediate64)
                    {
                        seed = prev.GetImmediate(1);
                    }

                    if (lengthKind != SegmentLengthKind.Calculated
                        && prev.Mnemonic == Mnemonic.Movsxd
                        && prev.Op0Register == Register.RBP
                        && prev.MemoryBase == Register.R13)
                    {
                        lengthKind = SegmentLengthKind.Calculated;
                        lengthOrFieldOffset = (int)prev.MemoryDisplacement32;
                    }

                    if (lengthKind == SegmentLengthKind.ImmConstant
                        && lengthOrFieldOffset == 0
                        && prev.Mnemonic == Mnemonic.Mov
                        && prev.Op0Register == Register.EDI
                        && prev.Op1Kind is OpKind.Immediate32 or OpKind.Immediate32to64)
                    {
                        lengthOrFieldOffset = (int)prev.GetImmediate(1);
                    }

                    if (offsetBaseDelta == 0
                        && prev.Mnemonic == Mnemonic.Mov
                        && prev.Op0Register == Register.EAX
                        && prev.Op1Kind is OpKind.Immediate32 or OpKind.Immediate32to64)
                    {
                        offsetBaseDelta = (int)prev.GetImmediate(1);
                    }

                    if (headerOffsetField == -1
                        && prev.Mnemonic == Mnemonic.Add
                        && prev.Op0Register == Register.EAX
                        && prev.MemoryBase == Register.R13)
                    {
                        headerOffsetField = (int)prev.MemoryDisplacement32;
                    }
                }

                if (lengthOrFieldOffset == 0)
                {
                    var laEnd = Math.Min(insns.Count, i + windowWidth);
                    for (var la = i; la < laEnd; la++) /* lookahead */
                    {
                        var nxt = insns[la];
                        if (nxt is { Mnemonic: Mnemonic.Cmp, Op1Kind: OpKind.Immediate8 or OpKind.Immediate32to64 })
                        {
                            lengthKind = SegmentLengthKind.ImmConstant;
                            lengthOrFieldOffset = (int)nxt.GetImmediate(1);
                            break;
                        }
                    }
                }

                var tbl = Array.Empty<byte>();
                if (sboxVa >= elfInfo.RodataBaseAddress && sboxVa + 256 <= elfInfo.RodataEndAddress)
                {
                    tbl = new byte[256];
                    Array.Copy(elfInfo.Rodata, (long)(sboxVa - elfInfo.RodataBaseAddress), tbl, 0, 256);
                }

                segments.Add(new(
                    loopAddr,
                    seed,
                    sboxVa,
                    tbl,
                    lengthKind,
                    lengthOrFieldOffset, 
                    headerOffsetField,
                    offsetBaseDelta
                ));
            }
        }

        return segments;
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
        var segments = ExtractDecryptionInfo(insns, elfInfo);

        Log.Info($"found {segments.Count} decryption segments.");
        foreach (var segment in segments)
        {
            Console.WriteLine(segment);
        }

        Log.Info("generating c# utility class...");
        var outpath = Path.Combine($"{Environment.CurrentDirectory}", "Glycin.DecryptionConfig.g.cs");
        using (var sw = new StreamWriter(outpath))
        {
            sw.WriteLine(CodeGen.GenerateDecryptionConfigClass(segments, "GlycinSegmentDecryptionConfig"));
        }
        Log.Info("i'm done. now fuck off.");
    }
}