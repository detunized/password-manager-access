// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Globalization;
using System.Linq;
using System.Numerics;
using System.Text;
using Newtonsoft.Json.Linq;

namespace OnePassword
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

        // Handles URL-safe, regular and mixed Base64 with or without padding.
        public static byte[] Decode64(this string s)
        {
            // Remove any padding.
            var withoutPadding = s.TrimEnd('=');

            // Re-pad correctly
            var withPadding = withoutPadding;
            switch (withoutPadding.Length % 4)
            {
            case 2:
                withPadding += "==";
                break;
            case 3:
                withPadding += "=";
                break;
            }

            // Convert to regular Base64
            var regularBase64 = withPadding.Replace('-', '+').Replace('_', '/');

            // Shouldn't fail anymore base of the padding or URL-safe.
            return Convert.FromBase64String(regularBase64);
        }

        public static BigInteger ToBigInt(this string s)
        {
            // Adding a leading '0' is important to trick .NET into treating any number
            // as positive, like OpenSSL does. Otherwise if the number starts with a
            // byte greater or equal to 0x80 it will be negative.
            return BigInteger.Parse('0' + s, NumberStyles.HexNumber);
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

        // URL-safe Base64
        public static string ToBase64(this byte[] x)
        {
            return Convert.ToBase64String(x).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        }

        public static BigInteger ToBigInt(this byte[] x)
        {
            // Need to reverse, since we're trying to match OpenSSL conventions.
            // Adding a trailing 0 is important to trick .NET into treating any number
            // as positive, like OpenSSL does. Otherwise if the last byte is greater or
            // equal to 0x80 it will be negative.
            return new BigInteger(x.Reverse().Concat(new byte[] { 0 }).ToArray());
        }

        //
        // BigInteger
        //

        public static string ToHex(this BigInteger i)
        {
            // Strip out leading zeros to mimic 1Password behavior.
            if (i > 0)
                return i.ToString("x").TrimStart('0');

            if (i < 0)
                return "-" + (-i).ToHex();

            return "0";
        }

        // Calculates (b ^ e) % m in a way that is compatible with 1Password.
        // Specifically the result is never negative. .NET BigInteger.ModPow returns
        // negative mod when b is negative.
        public static BigInteger ModExp(this BigInteger b, BigInteger e, BigInteger m)
        {
            var r = BigInteger.ModPow(b, e, m);
            return r >= 0 ? r : r + m;
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
