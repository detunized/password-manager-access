// Copyright (C) 2016 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Linq;
using System.Text;
using Newtonsoft.Json.Linq;

namespace ZohoVault
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

        public static byte[] DecodeHex(this string s)
        {
            if (s.Length % 2 != 0)
                throw new ArgumentException("Input length must be multiple of 2");

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

        //
        // byte[]
        //

        public static string ToUtf8(this byte[] x)
        {
            return Encoding.UTF8.GetString(x);
        }

        public static string ToHex(this byte[] x)
        {
            // TODO: This does not perform very well. We use it just a couple of times
            //       so it shouldn't be a big deal.
            return string.Join("", x.Select(i => i.ToString("x2")));
        }

        //
        // JToken
        //

        public static JToken At(this JObject j, string path)
        {
            return At(j.Root, path);
        }

        public static string StringAt(this JObject j, string path)
        {
            return StringAt(j.Root, path);
        }

        public static int IntAt(this JObject j, string path)
        {
            return IntAt(j.Root, path);
        }

        //
        // JToken
        //

        public static JToken At(this JToken j, string path)
        {
            var c = j;
            foreach (var i in path.Split('/'))
            {
                if (c.Type != JTokenType.Object)
                    throw new ArgumentException("Must be nested objects all the way down");

                c = c[i];
                if (c == null)
                    throw new ArgumentException("Path doesn't exist", path);

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

        public static int IntAt(this JToken j, string path)
        {
            var s = j.At(path);
            if (s.Type != JTokenType.Integer)
                throw new ArgumentException("The value is not an integer");

            return (int)s;
        }
    }
}
