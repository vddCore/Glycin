namespace Glycin.DataModel;

public record ExecutableInfo(
    byte[] Text,
    ulong TextBaseAddress,
    byte[] Rodata,
    ulong RodataBaseAddress,
    ulong RodataEndAddress,
    ulong ImageBase = 0
);