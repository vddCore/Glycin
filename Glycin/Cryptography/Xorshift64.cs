namespace Glycin.Cryptography;

public sealed class Xorshift64
{
    public static void Decrypt(Span<byte> data, ulong seed, ReadOnlySpan<byte> sbox)
    {
        ulong state = seed;

        for (var i = 0; i < data.Length; i++)
        {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;

            byte sboxIndex = (byte)((state >> 24) ^ (state >> 16) ^ (state >> 8) ^ state);
            data[i] ^= sbox[sboxIndex];
        }
    }
}