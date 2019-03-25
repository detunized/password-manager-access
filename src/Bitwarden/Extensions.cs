// Copyright (C) 2018 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.IO;
using System.Text;

namespace Bitwarden
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

        public static bool IsNullOrEmpty(this string s)
        {
            return string.IsNullOrEmpty(s);
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

        public static void Open(this byte[] bytes, Action<BinaryReader> action)
        {
            bytes.Open(reader => {
                action(reader);
                return 0;
            });
        }

        public static TResult Open<TResult>(this byte[] bytes, Func<BinaryReader, TResult> action)
        {
            using (var stream = new MemoryStream(bytes, false))
            using (var reader = new BinaryReader(stream))
                return action(reader);
        }
    }
}