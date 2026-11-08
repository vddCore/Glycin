namespace Glycin.Analysis;

using Glycin.DataModel;
using Iced.Intel;

public class PeVectorScanner : VectorScanner
{
    public PeVectorScanner(ExecutableInfo executableInfo) 
        : base(executableInfo)
    {
    }

public override List<DecryptionVector> Scan(List<Instruction> insns)
    {
        var vectors = new List<DecryptionVector>();

        /* prescan */
        var sboxVa = FindSboxVa(insns);
        var sboxTable = LoadSboxTable(sboxVa);

        for (int i = 0; i < insns.Count - 8; i++)
        {
            if (!IsXorShift64Core(insns, i, out var reg))
            {
                continue;
            }

            var loopAddr = insns[i].IP;
            var seed = 0ul;
            var lengthKind = VectorLengthKind.ImmConstant;
            var lengthOrFieldOffset = 0;
            var headerOffsetField = -1;
            var offsetBaseDelta = 0;

            var window = Math.Max(0, i - AnalysisWindowWidth);
            for (var lb = i - 1; lb >= window; lb--) /* lookbehind */
            {
                var prev = insns[lb];

                if (seed == 0
                    && prev.Mnemonic == Mnemonic.Mov
                    && prev.Op0Kind == OpKind.Register
                    && prev.Op0Register == reg
                    && prev.Op1Kind == OpKind.Immediate64)
                {
                    seed = prev.GetImmediate(1);
                }

                if (lengthKind != VectorLengthKind.Calculated
                    && prev.Mnemonic == Mnemonic.Movsxd
                    && prev.MemoryBase is Register.RDI or Register.RBX)
                {
                    lengthKind = VectorLengthKind.Calculated;
                    lengthOrFieldOffset = (int)prev.MemoryDisplacement32;
                }

                if (lengthKind == VectorLengthKind.ImmConstant
                    && lengthOrFieldOffset == 0
                    && prev.Mnemonic == Mnemonic.Mov
                    && prev.Op0Register == Register.ECX
                    && prev.Op1Kind is OpKind.Immediate32 or OpKind.Immediate32to64)
                {
                    lengthOrFieldOffset = (int)prev.GetImmediate(1);
                }

                if (offsetBaseDelta == 0 && headerOffsetField == -1)
                {
                    if (prev.Mnemonic == Mnemonic.Sub
                        && prev.Op0Register == Register.ECX
                        && prev.Op1Kind is OpKind.Immediate32 or OpKind.Immediate32to64)
                    {
                        offsetBaseDelta = -(int)prev.GetImmediate(1);
                    }
                    else if (prev.Mnemonic == Mnemonic.Add
                        && prev.Op0Register == Register.ECX
                        && prev.Op1Kind is OpKind.Immediate32 or OpKind.Immediate32to64)
                    {
                        offsetBaseDelta = (int)prev.GetImmediate(1);
                    }

                    if (offsetBaseDelta != 0)
                    {
                        for (var k = lb - 1; k >= Math.Max(0, lb - 6); k--)
                        {
                            var candidate = insns[k];
                            if (candidate.Mnemonic == Mnemonic.Mov
                                && candidate.Op0Register == Register.ECX
                                && candidate.MemoryBase is Register.RDI or Register.RBX)
                            {
                                headerOffsetField = (int)candidate.MemoryDisplacement32;
                                break;
                            }
                        }
                    }
                }
            }

            if (lengthOrFieldOffset == 0)
            {
                var laEnd = Math.Min(insns.Count, i + AnalysisWindowWidth);
                for (var la = i; la < laEnd; la++) /* lookahead */
                {
                    var nxt = insns[la];
                    if (nxt.Mnemonic == Mnemonic.Cmp
                        && nxt.Op0Register is Register.R8 or Register.R8D
                        && nxt.Op1Kind is OpKind.Immediate8 or OpKind.Immediate32 or OpKind.Immediate32to64)
                    {
                        lengthKind = VectorLengthKind.ImmConstant;
                        lengthOrFieldOffset = (int)nxt.GetImmediate(1);
                        break;
                    }
                }
            }

            if (seed == 0ul)
            {
                continue;
            }

            if (vectors.Count > 0 && vectors[^1].Seed == seed)
            {
                continue;
            }

            vectors.Add(new(
                loopAddr,
                seed,
                sboxVa,
                sboxTable,
                lengthKind,
                lengthOrFieldOffset,
                headerOffsetField,
                offsetBaseDelta
            ));
        }

        return vectors;
    }

    private ulong FindSboxVa(List<Instruction> insns)
    {
        foreach (var insn in insns)
        {
            if (insn.Op0Register == Register.EAX 
                && insn.MemoryIndex != Register.None 
                && insn.MemoryDisplacement32 != 0)
            {
                var candidateVa = ExecutableInfo.ImageBase + insn.MemoryDisplacement32;
                if (candidateVa >= ExecutableInfo.RodataBaseAddress
                    && candidateVa + 256 <= ExecutableInfo.RodataEndAddress)
                {
                    return candidateVa;
                }
            }
        }

        return 0ul;
    }

    private byte[] LoadSboxTable(ulong sboxVa)
    {
        if (sboxVa >= ExecutableInfo.RodataBaseAddress 
            && sboxVa + 256 <= ExecutableInfo.RodataEndAddress)
        {
            var tbl = new byte[256];
            Array.Copy(
                ExecutableInfo.Rodata,
                (long)(sboxVa - ExecutableInfo.RodataBaseAddress),
                tbl,
                0,
                256
            );
            return tbl;
        }

        return [];
    }

    protected virtual bool IsXorShift64Core(List<Instruction> insns, int index, out Register prngReg)
    {
        prngReg = Register.None;

        if (index + 8 >= insns.Count)
        {
            return false;
        }

        var i1 = insns[index + 1];
        var i4 = insns[index + 4];
        var i7 = insns[index + 7];

        try
        {
            if (i1.Mnemonic == Mnemonic.Shl && i1.GetImmediate(1) == 0x0D
                && i4.Mnemonic == Mnemonic.Shr && i4.GetImmediate(1) == 0x07
                && i7.Mnemonic == Mnemonic.Shl && i7.GetImmediate(1) == 0x11)
            {
                prngReg = insns[index].Op1Register;
                return true;
            }
        }
        catch
        {
            /* same as elf... */
        }

        return false;
    }
}