namespace Glycin.DataModel;

public record PointOfInterest(
    string Name,
    int OffsetInHeader,
    int Size
)
{
    public override string ToString()
    {
        return $"{Name} (0x{OffsetInHeader:X8} / {Size}B)";
    }
}