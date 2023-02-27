// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Buffers;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Text;
using Newtonsoft.Json.Linq;

namespace PasswordManagerAccess.Common
{
    internal static class Extensions
    {
        //
        // byte
        //

        internal static byte ReverseBits(this byte b)
        {
            return (byte)(((b & 0b0000_0001) << 7) |
                          ((b & 0b0000_0010) << 5) |
                          ((b & 0b0000_0100) << 3) |
                          ((b & 0b0000_1000) << 1) |
                          ((b & 0b0001_0000) >> 1) |
                          ((b & 0b0010_0000) >> 3) |
                          ((b & 0b0100_0000) >> 5) |
                          ((b & 0b1000_0000) >> 7));
        }

        //
        // uint
        //

        internal static uint ReverseBits(this uint u)
        {
            return ((uint)ReverseBits((byte)(u & 0xFF)) << 24) |
                   ((uint)ReverseBits((byte)((u >> 8) & 0xFF)) << 16) |
                   ((uint)ReverseBits((byte)((u >> 16) & 0xFF)) << 8) |
                   ReverseBits((byte)((u >> 24) & 0xFF));
        }

        //
        // string
        //

        public static bool IsNullOrEmpty(this string s)
        {
            return String.IsNullOrEmpty(s);
        }

        public static byte[] ToBytes(this string s)
        {
            return Encoding.UTF8.GetBytes(s);
        }

        public static string ToBase64(this string s)
        {
            return s.ToBytes().ToBase64();
        }

        public static string ToUrlSafeBase64(this string s)
        {
            return s.ToBytes().ToUrlSafeBase64();
        }

        public static string ToUrlSafeBase64NoPadding(this string s)
        {
            return s.ToBytes().ToUrlSafeBase64NoPadding();
        }

        public static string EncodeUri(this string s)
        {
            return Uri.EscapeUriString(s);
        }

        public static string EncodeUriData(this string s)
        {
            return Uri.EscapeDataString(s);
        }

        public static bool IsHex(this string s)
        {
            if (s.Length % 2 != 0)
                return false;

            foreach (var c in s)
                if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f')))
                    return false;

            return true;
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
                    var c = Char.ToLower(s[i * 2 + j]);
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

        // This is a forgiving version that pads the input with a '0' when the length is odd
        public static byte[] DecodeHexLoose(this string s)
        {
            return DecodeHex(s.Length % 2 == 0 ? s : "0" + s);
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
                int c = Char.ToLower(s[i]);
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

        public static string Repeat(this string s, int times)
        {
            var result = new StringBuilder(s.Length * times);
            for (var i = 0; i < times; ++i)
                result.Append(s);

            return result.ToString();
        }

        //
        // StringBuilder
        //

        internal static StringBuilder AppendLineLf(this StringBuilder sb, string s)
        {
            return sb.Append(s).Append('\n');
        }

        //
        // byte[]
        //

        internal static ReadOnlySpan<byte> AsRoSpan(this byte[] x)
        {
            return new ReadOnlySpan<byte>(x);
        }

        internal static ReadOnlySpan<byte> AsRoSpan(this byte[] x, int start, int size)
        {
            return new ReadOnlySpan<byte>(x, start, size);
        }

        public static bool IsNullOrEmpty(this byte[] x)
        {
            return x == null || x.Length == 0;
        }

        public static string ToUtf8(this byte[] x)
        {
            return Encoding.UTF8.GetString(x);
        }

        public static string ToHex(this byte[] x)
        {
            return x.AsRoSpan().ToHex();
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

        // Open bytes like an in-memory file and apply a lambda to it.
        public static void Open(this byte[] bytes, Action<BinaryReader> action)
        {
            bytes.Open(reader =>
            {
                action(reader);
                return 0;
            });
        }

        // Open bytes like an in-memory file and apply a lambda to it.
        public static TResult Open<TResult>(this byte[] bytes, Func<BinaryReader, TResult> action)
        {
            using var stream = new MemoryStream(bytes, false);
            using var reader = new BinaryReader(stream);
            return action(reader);
        }

        public static byte[] Sub(this byte[] array, int start, int length)
        {
            if (length < 0)
                throw new InternalErrorException("length should not be negative");

            var bytesLeft = Math.Max(array.Length - start, 0);
            var actualLength = Math.Min(bytesLeft, length);
            var sub = new byte[actualLength];
            if (actualLength > 0)
                Array.Copy(array, start, sub, 0, actualLength);

            return sub;
        }

        //
        // ReadOnlySpan<byte>
        //

        public static string ToUtf8(this ReadOnlySpan<byte> x)
        {
            // TODO: This is inefficient as we're creating a temporary array here.
            //       There doesn't seem to be a way to get a string directly from a byte span.
            return x.ToArray().ToUtf8();
        }

        public static string ToHex(this ReadOnlySpan<byte> x)
        {
            // TODO: Temp alloc, can we get rid of it?
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

        public static SpanStream ToStream(this ReadOnlySpan<byte> span)
        {
            return new SpanStream(span);
        }

        //
        // DateTime
        //

        // TOOD: Remove this in favour of Os.UnixSeconds
        public static uint UnixSeconds(this DateTime time)
        {
            const long secondsSinceEpoch = 62135596800;
            long seconds = time.ToUniversalTime().Ticks / TimeSpan.TicksPerSecond - secondsSinceEpoch;

            // TODO: This will stop working on January 19, 2038 03:14:07. Fix ASAP!
            return (uint)seconds;
        }

        //
        // Dictionary
        //

        public static TValue GetOrDefault<TKey, TValue>(this IReadOnlyDictionary<TKey, TValue> dictionary,
                                                        TKey key,
                                                        TValue defaultValue)
        {
            return dictionary.TryGetValue(key, out var v) ? v : defaultValue;
        }

        public static TValue GetOrAdd<TKey, TValue>(this IDictionary<TKey, TValue> dictionary,
                                                    TKey key,
                                                    Func<TValue> lazyValue)
        {
            if (!dictionary.TryGetValue(key, out var v))
            {
                v = lazyValue();
                dictionary[key] = v;
            }

            return v;
        }

        // Always returns a copy
        public static Dictionary<TKey, TValue> MergeCopy<TKey, TValue>(this IReadOnlyDictionary<TKey, TValue> self,
                                                                       IReadOnlyDictionary<TKey, TValue> other)
        {
            var merged = new Dictionary<TKey, TValue>(self.Count + other.Count);

            foreach (var i in self)
                merged[i.Key] = i.Value;

            foreach (var i in other)
                merged[i.Key] = i.Value;

            return merged;
        }

        // Only returns a copy when the merge is not trivial, otherwise returns either argument.
        public static IReadOnlyDictionary<TKey, TValue> Merge<TKey, TValue>(
            this IReadOnlyDictionary<TKey, TValue> self,
            IReadOnlyDictionary<TKey, TValue> other)
        {
            if (other.Count == 0)
                return self;

            if (self.Count == 0)
                return other;

            return self.MergeCopy(other);
        }

        //
        // IEnumerable
        //

        public static string JoinToString<T>(this IEnumerable<T> e, string separator)
        {
            return String.Join(separator, e);
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
        // Stream
        //

        public static byte[] ReadAll(this Stream stream, int bufferSize = 4096)
        {
            if (bufferSize < 1)
                throw new InternalErrorException($"Buffer size must be positive, got {bufferSize}");

            using var outputStream = new MemoryStream();
            stream.CopyTo(outputStream, bufferSize);

            return outputStream.ToArray();
        }

        public static byte[] ReadExact(this Stream input, int size)
        {
            var bytes = new byte[size];
            input.ReadExact(bytes, 0, size);
            return bytes;
        }

        public static void ReadExact(this Stream input, byte[] buffer, int start, int size)
        {
            if (input.TryReadExact(buffer, start, size))
                return;

            throw new InternalErrorException($"Failed to read {size} bytes from the stream");
        }

        public static bool TryReadExact(this Stream input, byte[] buffer, int start, int size)
        {
            if (buffer.Length - start < size)
                throw new InternalErrorException("The buffer is too small");

            var read = 0;
            for (;;)
            {
                var last = input.Read(buffer, start + read, size - read);
                read += last;

                if (read == size)
                    return true;

                if (last <= 0)
                    return false;
            }
        }

        public static bool TrySkip(this Stream input, int size, int bufferSize = 4096)
        {
            return Rental.With(bufferSize, buffer => input.TrySkip(size, buffer));
        }

        public static bool TrySkip(this Stream input, int size, byte[] buffer)
        {
            if (input.CanSeek)
            {
                var pos = input.Position;
                var newPos = input.Seek(size, SeekOrigin.Current);
                if (newPos != pos + size)
                    return false;
            }
            else
            {
                var readTotal = 0;
                while (readTotal < size)
                {
                    var bytesToRead = Math.Min(size - readTotal, buffer.Length);
                    var bytesRead = input.Read(buffer, 0, bytesToRead);
                    if (bytesRead == 0)
                        return false;

                    readTotal += bytesRead;
                }
            }

            return true;
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
        // JToken
        //

        public static string StringAt(this JToken j, string name, string defaultValue)
        {
            return At(j, name, JTokenType.String, defaultValue);
        }

        public static int IntAt(this JToken j, string name, int defaultValue)
        {
            return At(j, name, JTokenType.Integer, defaultValue);
        }

        public static bool BoolAt(this JToken j, string name, bool defaultValue)
        {
            return At(j, name, JTokenType.Boolean, defaultValue);
        }

        public static JArray ArrayAt(this JToken j, string name, JArray defaultValue)
        {
            return At(j, name, JTokenType.Array, defaultValue);
        }

        public static JArray ArrayAtOrEmpty(this JToken j, string name)
        {
            return ArrayAt(j, name, null) ?? new JArray();
        }

        public static JObject ObjectAt(this JToken j, string name, JObject defaultValue)
        {
            return At(j, name, JTokenType.Object, defaultValue);
        }

        public static JObject ObjectAtOrEmpty(this JToken j, string name)
        {
            return ObjectAt(j, name, null) ?? new JObject();
        }

        private static T At<T>(JToken j, string name, JTokenType type, T defaultValue)
        {
            if (j?.Type == JTokenType.Object)
                if (j[name] is var field && field?.Type == type)
                    return field.ToObject<T>();

            return defaultValue;
        }
    }
}
