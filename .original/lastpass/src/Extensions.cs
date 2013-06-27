using System;

namespace LastPass
{
    static class Extensions
    {
        public static uint Reverse(this uint x)
        {
            return ((x & 0xff) << 24) | ((x & 0xff00) << 8) | ((x & 0xff0000) >> 8) | ((x & 0xff000000) >> 24);
        }

        public static uint FromBigEndian(this uint x)
        {
            return BitConverter.IsLittleEndian ? x.Reverse() : x;
        }
    }
}
