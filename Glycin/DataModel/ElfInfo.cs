namespace Glycin.DataModel;

public record ElfInfo(
    byte[] Text,
    ulong TextBaseAddress,
    byte[] Rodata,
    ulong RodataBaseAddress,
    ulong RodataEndAddress
);