// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.IO;
using System.Text;
using Newtonsoft.Json.Linq;

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

        public static string ToHex(this byte[] x)
        {
            var hex = new char[x.Length * 2];
            for (int i = 0, c = 0; i < x.Length; i += 1)
            {
                int hi = x[i] >> 4;
                hex[c] = (char)(hi < 10 ? '0' + hi : 'a' + hi - 10);
                c += 1;

                int lo = x[i] & 15;
                hex[c] = (char)(lo < 10 ? '0' + lo : 'a' + lo - 10);
                c += 1;
            }

            return new string(hex);
        }

        public static string ToBase64(this byte[] x)
        {
            return Convert.ToBase64String(x);
        }

        public static string ToUrlSafeBase64(this byte[] x)
        {
            return Convert.ToBase64String(x).TrimEnd('=').Replace('+', '-').Replace('/', '_');
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

        //
        // Nested JToken access by path with and without exceptions
        //

        public static JToken At(this JToken j, string path)
        {
            var c = j;
            foreach (var i in path.Split('/'))
            {
                if (c.Type != JTokenType.Object)
                    throw new JTokenAccessException(
                        string.Format("Expected nested objects at '{0}'", path));

                c = c[i];
                if (c == null)
                    throw new JTokenAccessException(string.Format("Path '{0}' doesn't exist", path));
            }

            return c;
        }

        public static string StringAt(this JToken j, string path)
        {
            var s = j.At(path);
            if (s.Type != JTokenType.String)
                throw new JTokenAccessException(string.Format("Expected a string at '{0}'", path));

            return (string)s;
        }

        public static string StringAt(this JToken j, string path, string defaultValue)
        {
            try
            {
                return j.StringAt(path);
            }
            catch (JTokenAccessException)
            {
                return defaultValue;
            }
        }

        public static int IntAt(this JToken j, string path)
        {
            var i = j.At(path);
            if (i.Type != JTokenType.Integer)
                throw new JTokenAccessException(string.Format("Expected an integer at '{0}'", path));

            return (int)i;
        }

        public static int IntAt(this JToken j, string path, int defaultValue)
        {
            try
            {
                return j.IntAt(path);
            }
            catch (JTokenAccessException)
            {
                return defaultValue;
            }
        }

        public static bool BoolAt(this JToken j, string path)
        {
            var b = j.At(path);
            if (b.Type != JTokenType.Boolean)
                throw new JTokenAccessException(string.Format("Expected a boolean at '{0}'", path));

            return (bool)b;
        }

        public static bool BoolAt(this JToken j, string path, bool defaultValue)
        {
            try
            {
                return j.BoolAt(path);
            }
            catch (JTokenAccessException)
            {
                return defaultValue;
            }
        }
    }
}
