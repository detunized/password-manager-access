// Copyright (C) 2016 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Linq;
using System.Text;
using Newtonsoft.Json.Linq;

namespace Dashlane
{
    static class Extensions
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

        //
        // byte[]
        //

        public static string ToUtf8(this byte[] x)
        {
            return Encoding.UTF8.GetString(x);
        }

        public static string ToHex(this byte[] x)
        {
            return string.Join("", x.Select(i => i.ToString("x2")));
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

        //
        // JToken
        //

        public static string GetString(this JToken jtoken, string path)
        {
            var t = jtoken.SelectToken(path);
            return t != null && t.Type == JTokenType.String ? (string)t : null;
        }
    }
}
