// Copyright (C) 2013 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

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

        public static byte[] DecodeHex(this string s)
        {
            if (s.Length % 2 != 0)
                throw new ArgumentException("Input length must be multple of 2");

            var bytes = new byte[s.Length / 2];
            for (var i = 0; i < s.Length / 2; ++i)
            {
                var b = 0;
                for (var j = 0; j < 2; ++j)
                {
                    b <<= 4;
                    var c = char.ToLower(s[i * 2 + j]);
                    if (c >= '0' && c <= '9')
                        b |= c - '0';
                    else if (c >= 'a' && c <= 'f')
                        b |= c - 'a' + 10;
                    else
                        throw new ArgumentException("Input contains invalid characters");
                }

                bytes[i] = (byte)b;
            }

            return bytes;
        }

        public static byte[] Decode64(this string s)
        {
            return Convert.FromBase64String(s);
        }

        public static void Times(this int times, Action action)
        {
            for (var i = 0; i < times; ++i)
                action();
        }
    }
}
