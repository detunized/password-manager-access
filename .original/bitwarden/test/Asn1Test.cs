// Copyright (C) 2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using NUnit.Framework;

namespace Bitwarden.Test
{
    [TestFixture]
    class Asn1Test
    {
        [Test]
        public void Asn1_ParseItem_returns_integer()
        {
            ParseDeadBeefItem(2, Asn1.Kind.Integer);
        }

        [Test]
        public void Asn1_ParseItem_returns_bytes()
        {
            ParseDeadBeefItem(4, Asn1.Kind.Bytes);
        }

        [Test]
        public void Asn1_ParseItem_returns_null()
        {
            ParseDeadBeefItem(5, Asn1.Kind.Null);
        }

        [Test]
        public void Asn1_ParseItem_returns_squence()
        {
            ParseDeadBeefItem(16, Asn1.Kind.Sequence);
        }

        [Test]
        public void Asn1_ParseItem_throws_on_invalid_tag()
        {
            Assert.That(() => Asn1.ParseItem("0D04DEADBEEF".DecodeHex()),
                        Throws.ArgumentException.And.Message.EqualTo("Unknown ASN.1 tag 13"));
        }

        [Test]
        public void Asn1_ParseItem_reads_packed_size()
        {
            const int size = 127;
            var item = Asn1.ParseItem(("027F" + "AB".Repeat(size)).DecodeHex());

            Assert.That(item.Value.Length, Is.EqualTo(size));
        }

        [Test]
        public void Asn1_ParseItem_reads_single_byte_size()
        {
            const int size = 128;
            var item = Asn1.ParseItem(("028180" + "AB".Repeat(size)).DecodeHex());

            Assert.That(item.Value.Length, Is.EqualTo(size));
        }

        [Test]
        public void Asn1_ParseItem_reads_multi_byte_size()
        {
            const int size = 260;
            var item = Asn1.ParseItem(("02820104" + "AB".Repeat(size)).DecodeHex());

            Assert.That(item.Value.Length, Is.EqualTo(size));
        }

        private static void ParseDeadBeefItem(byte tag, Asn1.Kind kind)
        {
            var item = Asn1.ParseItem($"{tag:X2}04DEADBEEF".DecodeHex());

            Assert.That(item.Key, Is.EqualTo(kind));
            Assert.That(item.Value, Is.EqualTo(new byte[] {0xDE, 0xAD, 0xBE, 0xEF}));
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
