// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Text;

namespace PasswordManagerAccess.Common
{
    internal static class Extensions
    {
        //
        // string
        //

        public static bool IsNullOrEmpty(this string s)
        {
            return string.IsNullOrEmpty(s);
        }

        public static byte[] ToBytes(this string s)
        {
            return Encoding.UTF8.GetBytes(s);
        }

        public static byte[] DecodeHex(this string s)
        {
            if (s.Length % 2 != 0)
                throw new InternalErrorException("input length must be multiple of 2");

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
                        throw new InternalErrorException("invalid characters in hex");
                }

                bytes[i] = (byte)b;
            }

            return bytes;
        }

        public static byte[] Decode32(this string s)
        {
            // Remove padding
            var length = s.Length;
            while (length > 0 && s[length - 1] == '=')
                length -= 1;

            var result = new byte[length * 5 / 8];
            int currentByte = 0;
            int bitsReady = 0;
            int outputIndex = 0;

            for (var i  = 0; i < length; i += 1)
            {
                int c = char.ToLower(s[i]);
                if (c >= 'a' && c <= 'z')
                    c -= 'a';
                else if (c >= '2' && c <= '7')
                    c += 26 - '2';
                else
                    throw new InternalErrorException("invalid characters in base32");

                currentByte <<= 5;
                currentByte |= c & 31;
                bitsReady += 5;

                if (bitsReady >= 8)
                {
                    bitsReady -= 8;
                    result[outputIndex] = (byte)(currentByte >> bitsReady);
                    outputIndex += 1;
                }
            }

            return result;
        }

        // Decodes regular/standard Base64 (requires padding)
        public static byte[] Decode64(this string s)
        {
            return Convert.FromBase64String(s);
        }

        // Decodes URL-safe Base64 (requires padding)
        public static byte[] Decode64UrlSafe(this string s)
        {
            var regularBase64 = s.Replace('-', '+').Replace('_', '/');
            return regularBase64.Decode64();
        }

        // Handles URL-safe, regular and mixed Base64 with or without padding
        public static byte[] Decode64Loose(this string s)
        {
            // Remove any padding
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

            // Should be safe to call strict functions now
            return withPadding.Decode64UrlSafe();
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

        // Regular/standard Base64
        public static string ToBase64(this byte[] x)
        {
            return Convert.ToBase64String(x);
        }

        // URL-safe Base64 with padding
        public static string ToUrlSafeBase64(this byte[] x)
        {
            return x.ToBase64().Replace('+', '-').Replace('/', '_');
        }

        // URL-safe Base64 without padding
        public static string ToUrlSafeBase64NoPadding(this byte[] x)
        {
            return x.ToUrlSafeBase64().TrimEnd('=');
        }

        public static BigInteger ToBigInt(this byte[] x)
        {
            // Need to reverse, since we're trying to match OpenSSL conventions.
            // Adding a trailing 0 is important to trick .NET into treating any number
            // as positive, like OpenSSL does. Otherwise if the last byte is greater or
            // equal to 0x80 it will be negative.
            return new BigInteger(x.Reverse().Concat(new byte[] { 0 }).ToArray());
        }

        public static void Open(this byte[] bytes, Action<BinaryReader> action)
        {
            bytes.Open(reader => action(reader));
        }

        public static TResult Open<TResult>(this byte[] bytes, Func<BinaryReader, TResult> action)
        {
            using (var stream = new MemoryStream(bytes, false))
            using (var reader = new BinaryReader(stream))
                return action(reader);
        }

        //
        // Dictionary
        //

        public static TValue GetOrDefault<TKey, TValue>(this Dictionary<TKey, TValue> dictionary,
                                                        TKey key,
                                                        TValue defaultValue)
        {
            TValue v;
            return dictionary.TryGetValue(key, out v) ? v : defaultValue;
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
    }
}
