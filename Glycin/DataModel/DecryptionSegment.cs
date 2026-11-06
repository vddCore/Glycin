namespace Glycin.DataModel;

using System.Text;

public record DecryptionSegment(
    ulong LoopAddress,
    ulong Seed,
    ulong SBoxAddr,
    byte[] SBox,
    SegmentLengthKind LengthKind,
    int LengthOrFieldOffset,
    int HeaderOffsetField,
    int OffsetBaseDelta
)
{
    private static bool IsValidPermutation(ReadOnlySpan<byte> tbl)
    {
        if (tbl.Length != 256)
        {
            return false;
        }
        
        Span<bool> seen = stackalloc bool[256];
        for (var i = 0; i < 256; i++)
        {
            var b = tbl[i];
            
            if (seen[b])
            {
                return false;
            }

            seen[b] = true;
        }

        return true;
    }
    
    public override string ToString()
    {
        var sb = new StringBuilder();

        sb.AppendLine($"[Segment @ 0x{LoopAddress:X8}] {{");
        sb.AppendLine($"  Seed       : 0x{Seed:X16}");

        if (LengthKind == SegmentLengthKind.ImmConstant)
        {
            sb.AppendLine($"  Length     : 0x{LengthOrFieldOffset:X} ({LengthOrFieldOffset} bytes, Immediate)");
        }
        else
        {
            sb.AppendLine($"  Length     : Read from [Header + 0x{LengthOrFieldOffset:X}]");
        }

        if (HeaderOffsetField != -1)
        {
            var deltaSign = OffsetBaseDelta >= 0 ? "+" : "-";
            var absDelta = Math.Abs(OffsetBaseDelta);
            sb.AppendLine($"  Src Offset : ([Header + 0x{HeaderOffsetField:X}] {deltaSign} 0x{absDelta:X})");
        }
        else if (OffsetBaseDelta != 0)
        {
            sb.AppendLine($"  Src Delta  : 0x{OffsetBaseDelta:X}");
        }

        sb.AppendLine($"  S-box VA   : 0x{SBoxAddr:X8}");
        sb.AppendLine("  S-box      : {");
        if (SBox is { Length: > 0 })
        {
            for (var i = 0; i < SBox.Length; i += 16)
            {
                var sliceLen = Math.Min(16, SBox.Length - i);
                var row = SBox.AsSpan(i, sliceLen);
                
                sb.Append($"    /* {i:X2}..{i + sliceLen - 1:X2} */  ");
                for (var j = 0; j < row.Length; j++)
                {
                    sb.Append($"{row[j]:X2} ");
                }
                sb.AppendLine();
            }
        }
        else
        {
            sb.AppendLine("    <empty or unmapped>");
        }
        sb.AppendLine("  }");
        sb.AppendLine("}");

        return sb.ToString();
    }
}