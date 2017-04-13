// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.IO;
using System.Text;
using Newtonsoft.Json.Linq;

namespace TrueKey
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

        //
        // DateTime
        //

        public static uint UnixSeconds(this DateTime time)
        {
            const long secondsSinceEpoch = 62135596800;
            long seconds = time.ToUniversalTime().Ticks / TimeSpan.TicksPerSecond - secondsSinceEpoch;
            // TODO: This will stop working on January 19, 2038 03:14:07. Fix ASAP!
            return (uint)seconds;
        }

        //
        // BinaryReader
        //

        public static ushort ReadUInt16BigEndian(this BinaryReader r)
        {
            var result = r.ReadUInt16();

            if (BitConverter.IsLittleEndian)
                result = (ushort)((result << 8) | (result >> 8));

            return result;
        }

        public static uint ReadUInt32BigEndian(this BinaryReader r)
        {
            var result = r.ReadUInt32();

            if (BitConverter.IsLittleEndian)
                result = ((result & 0x000000FF) << 24) |
                         ((result & 0x0000FF00) <<  8) |
                         ((result & 0x00FF0000) >>  8) |
                         ((result & 0xFF000000) >> 24);

            return result;
        }

        //
        // Case insensitive nested JObject access by path with and without exceptions
        //

        public static JToken At(this JObject j, string path)
        {
            return At(j.Root, path);
        }

        public static JToken AtOrNull(this JObject j, string path)
        {
            return AtOrNull(j.Root, path);
        }

        public static string StringAt(this JObject j, string path)
        {
            return StringAt(j.Root, path);
        }

        public static string StringAtOrNull(this JObject j, string path)
        {
            return StringAtOrNull(j.Root, path);
        }

        //
        // Case insensitive nested JToken access by path with and without exceptions
        //

        public static JToken At(this JToken j, string path)
        {
            var c = j;
            foreach (var i in path.Split('/'))
            {
                if (c.Type != JTokenType.Object)
                    throw new ArgumentException("Must be nested objects all the way down");

                c = ((JObject)c).GetValue(i, StringComparison.OrdinalIgnoreCase);
                if (c == null)
                    throw new ArgumentException("Path doesn't exist", path);
            }

            return c;
        }

        public static JToken AtOrNull(this JToken j, string path)
        {
            var c = j;
            foreach (var i in path.Split('/'))
            {
                if (c.Type != JTokenType.Object)
                    return null;

                c = ((JObject)c).GetValue(i, StringComparison.OrdinalIgnoreCase);
                if (c == null)
                    return null;
            }

            return c;
        }

        public static string StringAt(this JToken j, string path)
        {
            var s = j.At(path);
            if (s.Type != JTokenType.String)
                throw new ArgumentException("The value is not a string");

            return (string)s;
        }

        public static string StringAtOrNull(this JToken j, string path)
        {
            var s = j.AtOrNull(path);
            if (s == null || s.Type != JTokenType.String)
                return null;

            return (string)s;
        }
    }
}
