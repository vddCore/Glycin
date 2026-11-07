namespace Glycin.Cryptography;

public sealed class Xorshift64
{
    public static void Decrypt(Span<byte> data, ulong seed, ReadOnlySpan<byte> sbox)
    {
        ulong state = seed;

        for (var i = 0; i < data.Length; i++)
        {
            state = state << 0x0D ^ state;
            var extra = state >> 0x07 ^ state;
            state = extra << 0x11 ^ extra;

            uint a = (uint)(state >> 0x18 & 0xFF);
            uint b = (uint)(state >> 0x10 & 0xFFFF);
            uint c = (uint)extra;
            uint d = (uint)(state >> 8) & 0xFFFFFF;

            var sboxIndex =(byte)((a ^ b ^ c ^ d) & 0xFF);
            data[i] ^= sbox[sboxIndex];
        }
    }
}