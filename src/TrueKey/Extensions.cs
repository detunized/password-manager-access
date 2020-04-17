// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.IO;
using System.Text;
using Newtonsoft.Json.Linq;

namespace PasswordManagerAccess.TrueKey
{
    internal static class Extensions
    {
        //
        // uint
        //

        public static uint ChangeEndianness(this uint x)
        {
            return ((x & 0x000000FF) << 24) |
                   ((x & 0x0000FF00) <<  8) |
                   ((x & 0x00FF0000) >>  8) |
                   ((x & 0xFF000000) >> 24);
        }

        public static uint FromBigEndian(this uint x)
        {
            return BitConverter.IsLittleEndian ? x.ChangeEndianness() : x;
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
        // Case insensitive nested JToken access by path with and without exceptions
        //

        public static JToken At(this JToken j, string path)
        {
            var c = j;
            foreach (var i in path.Split('/'))
            {
                if (c.Type != JTokenType.Object)
                    throw new JTokenAccessException($"Expected nested objects at '{path}'");

                c = ((JObject)c).GetValue(i, StringComparison.OrdinalIgnoreCase);
                if (c == null)
                    throw new JTokenAccessException($"Path '{path}' doesn't exist");
            }

            return c;
        }

        public static string StringAt(this JToken j, string path)
        {
            var s = j.At(path);
            if (s.Type != JTokenType.String)
                throw new JTokenAccessException($"Expected a string at '{path}'");

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
                throw new JTokenAccessException($"Expected an integer at '{path}'");

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
                throw new JTokenAccessException($"Expected a boolean at '{path}'");

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
