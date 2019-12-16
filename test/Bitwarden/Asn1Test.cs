// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using PasswordManagerAccess.Bitwarden;
using Xunit;

namespace PasswordManagerAccess.Test.Bitwarden
{
    public class Asn1Test
    {
        [Fact]
        public void Asn1_ExtractItem_returns_integer()
        {
            ExtractDeadBeefItem(2, Asn1.Kind.Integer);
        }

        [Fact]
        public void Asn1_ExtractItem_returns_bytes()
        {
            ExtractDeadBeefItem(4, Asn1.Kind.OctetString);
        }

        [Fact]
        public void Asn1_ExtractItem_returns_null()
        {
            ExtractDeadBeefItem(5, Asn1.Kind.Null);
        }

        [Fact]
        public void Asn1_ExtractItem_returns_squence()
        {
            ExtractDeadBeefItem(16, Asn1.Kind.Sequence);
        }

        [Fact]
        public void Asn1_ExtractItem_throws_on_invalid_tag()
        {
            Exceptions.AssertThrowsInternalError(() => Asn1.ExtractItem("0D04DEADBEEF".DecodeHex()),
                                                 "Unknown ASN.1 tag 13");
        }

        [Fact]
        public void Asn1_ExtractItem_reads_packed_size()
        {
            const int size = 127;
            var item = Asn1.ExtractItem(("027F" + "AB".Repeat(size)).DecodeHex());

            Assert.Equal(size, item.Value.Length);
        }

        [Fact]
        public void Asn1_ExtractItem_reads_single_byte_size()
        {
            const int size = 128;
            var item = Asn1.ExtractItem(("028180" + "AB".Repeat(size)).DecodeHex());

            Assert.Equal(size, item.Value.Length);
        }

        [Fact]
        public void Asn1_ExtractItem_reads_multi_byte_size()
        {
            const int size = 260;
            var item = Asn1.ExtractItem(("02820104" + "AB".Repeat(size)).DecodeHex());

            Assert.Equal(size, item.Value.Length);
        }

        private static void ExtractDeadBeefItem(byte tag, Asn1.Kind kind)
        {
            var item = Asn1.ExtractItem($"{tag:X2}04DEADBEEF".DecodeHex());

            Assert.Equal(kind, item.Key);
            Assert.Equal(new byte[]{0xDE, 0xAD, 0xBE, 0xEF}, item.Value);
        }

    }

    internal static class Extensions
    {
        public static string Repeat(this string s, int times)
        {
            // Inefficient! Who cares?!
            var result = "";
            for (var i = 0; i < times; ++i)
                result += s;

            return result;
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
    }
}
