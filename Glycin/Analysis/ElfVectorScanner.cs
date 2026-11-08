namespace Glycin.Analysis;

using Glycin.DataModel;
using Iced.Intel;

public class ElfVectorScanner : VectorScanner
{
    public ElfVectorScanner(ExecutableInfo executableInfo) 
        : base(executableInfo)
    {
    }

    public override List<DecryptionVector> Scan(List<Instruction> insns)
    {
        var vectors = new List<DecryptionVector>();
        var sboxVa = 0ul;

        for (int i = 0; i < insns.Count - 8; i++)
        {
            var insn = insns[i];

            if (insn is { Mnemonic: Mnemonic.Lea, IsIPRelativeMemoryOperand: true })
            {
                var va = insn.IPRelativeMemoryAddress;
                if (va >= ExecutableInfo.RodataBaseAddress && va + 256 <= ExecutableInfo.RodataEndAddress)
                {
                    sboxVa = va;
                }
            }

            if (IsXorShift64Core(insns, i, out var reg))
            {
                var loopAddr = insn.IP;
                var seed = 0ul;
                
                /* first one is always constant as per malloc. so far. */
                var lengthKind = VectorLengthKind.ImmConstant;
                
                var lengthOrFieldOffset = 0;
                var headerOffsetField = -1;
                var offsetBaseDelta = 0;
                
                var window = Math.Max(0, i - AnalysisWindowWidth); 
                for (var lb = i - 1; lb >= window; lb--) /* lookbehind */
                {
                    var prev =  insns[lb];
                    if (prev.Mnemonic == Mnemonic.Mov
                        && prev.Op0Kind == OpKind.Register
                        && prev.Op0Register == reg
                        && prev.Op1Kind == OpKind.Immediate64)
                    {
                        seed = prev.GetImmediate(1);
                    }

                    if (lengthKind != VectorLengthKind.Calculated
                        && prev.Mnemonic == Mnemonic.Movsxd
                        && prev.Op0Register == Register.RBP
                        && prev.MemoryBase == Register.R13)
                    {
                        lengthKind = VectorLengthKind.Calculated;
                        lengthOrFieldOffset = (int)prev.MemoryDisplacement32;
                    }

                    if (lengthKind == VectorLengthKind.ImmConstant
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

                    /**
                     * so because you're a dumb nugget and can't read
                     * disassembly i wrote it out here for you.
                     * 
                     * 06e4195f b8 20 1d 00 00  MOV   EAX, 0x2d40 <-- this 2nd
                     * 06e41964 41 03 85 ...    ADD   EAX, dword ptr [R13 + 0x228] <-- this 1st
                     * 
                     ** Love, V */
                    if (headerOffsetField == -1 && prev is
                        {
                            Mnemonic: Mnemonic.Add,
                            Op0Register: Register.EAX,
                            MemoryBase: Register.R13
                        })
                    {
                        headerOffsetField = (int)prev.MemoryDisplacement32;

                        if (lb - 1 >= 0)
                        {
                            var deltaInsn = insns[lb - 1];
                            if (deltaInsn is
                                {
                                    Mnemonic: Mnemonic.Mov,
                                    Op0Register: Register.EAX,
                                    Op1Kind: OpKind.Immediate32 or OpKind.Immediate32to64
                                })
                            {
                                offsetBaseDelta = (int)deltaInsn.GetImmediate(1);
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
                        if (nxt is
                            {
                                Mnemonic: Mnemonic.Cmp,
                                Op1Kind: OpKind.Immediate8 or OpKind.Immediate32to64
                            })
                        {
                            lengthKind = VectorLengthKind.ImmConstant;
                            lengthOrFieldOffset = (int)nxt.GetImmediate(1);
                            break;
                        }
                    }
                }

                var tbl = Array.Empty<byte>();
                if (sboxVa >= ExecutableInfo.RodataBaseAddress 
                    && sboxVa + 256 <= ExecutableInfo.RodataEndAddress)
                {
                    tbl = new byte[256];
                    Array.Copy(
                        ExecutableInfo.Rodata, 
                        (long)(sboxVa - ExecutableInfo.RodataBaseAddress), 
                        tbl, 
                        0, 
                        256
                    );
                }

                vectors.Add(new(
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

        return vectors;
    }
    
    protected virtual bool IsXorShift64Core(List<Instruction> insns, int index, out Register prngReg)
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
         *                                      LAB_06e41710               XREF[1]:     06e41754(j)
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
            /**
             * ignore - happens when the assumption
             * that the operand is an imm fails.
             */
        }

        return false;
    }
}