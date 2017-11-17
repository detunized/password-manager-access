// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.IO;
using System.Text;

namespace RoboForm
{
    internal static class Extensions
    {
        //
        // string
        //

        public static byte[] ToBytes(this string s)
        {
            return Encoding.UTF8.GetBytes(s);
        }

        public static byte[] Decode64(this string s)
        {
            return Convert.FromBase64String(s);
        }

        public static string ToBase64(this string s)
        {
            return s.ToBytes().ToBase64();
        }

        public static string EncodeUri(this string s)
        {
            return Uri.EscapeUriString(s);
        }

        //
        // byte[]
        //

        public static string ToUtf8(this byte[] x)
        {
            return Encoding.UTF8.GetString(x);
        }

        public static string ToBase64(this byte[] x)
        {
            return Convert.ToBase64String(x);
        }

        //
        // BinaryReader
        //

        public static uint ReadUInt32LittleEndian(this BinaryReader r)
        {
            var result = r.ReadUInt32();

            if (!BitConverter.IsLittleEndian)
                result = ((result & 0x000000FF) << 24) |
                         ((result & 0x0000FF00) << 8) |
                         ((result & 0x00FF0000) >> 8) |
                         ((result & 0xFF000000) >> 24);

            return result;
        }
    }
}
