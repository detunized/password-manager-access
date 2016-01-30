using System;
using System.Text;

namespace Dashlane
{
    static class Extensions
    {
        public static byte[] ToBytes(this string s)
        {
            return Encoding.UTF8.GetBytes(s);
        }

        public static byte[] Sub(this byte[] array, int start, int length)
        {
            if (length < 0)
                throw new ArgumentOutOfRangeException("length", "Length should be nonnegative");

            var bytesLeft = Math.Max(array.Length - start, 0);
            var actualLength = Math.Min(bytesLeft, length);
            var sub = new byte[actualLength];
            if (actualLength > 0)
                Array.Copy(array, start, sub, 0, actualLength);

            return sub;
        }
    }
}
