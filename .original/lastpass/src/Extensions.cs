using System;
using System.Linq;
using System.Text;

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

        public static string ToUtf8(this byte[] x)
        {
            return Encoding.UTF8.GetString(x);
        }

        public static string ToHex(this byte[] x)
        {
            return string.Join("", x.Select(i => i.ToString("x2")).ToArray());
        }

        public static byte[] ToBytes(this string s)
        {
            return Encoding.UTF8.GetBytes(s);
        }

        public static byte[] Decode64(this string s)
        {
            return Convert.FromBase64String(s);
        }
    }
}
