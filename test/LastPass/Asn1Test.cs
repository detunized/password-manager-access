// Copyright (C) 2013 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using NUnit.Framework;

namespace LastPass.Test
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
        [ExpectedException(typeof(ArgumentException), ExpectedMessage = "Unknown ASN.1 tag 13")]
        public void Asn1_ParseItem_throws_on_invalid_tag()
        {
            Asn1.ParseItem("0D04DEADBEEF".DecodeHex());
        }

        [Test]
        public void Asn1_ParseItem_reads_packed_size()
        {
            const int size = 127;
            var item = Asn1.ParseItem(("027F" + Repeat("AB", size)).DecodeHex());
            Assert.AreEqual(size, item.Value.Length);
        }

        [Test]
        public void Asn1_ParseItem_reads_single_byte_size()
        {
            const int size = 128;
            var item = Asn1.ParseItem(("028180" + Repeat("AB", size)).DecodeHex());
            Assert.AreEqual(size, item.Value.Length);
        }

        [Test]
        public void Asn1_ParseItem_reads_multi_byte_size()
        {
            const int size = 260;
            var item = Asn1.ParseItem(("02820104" + Repeat("AB", size)).DecodeHex());
            Assert.AreEqual(size, item.Value.Length);
        }

        private static void ParseDeadBeefItem(byte tag, Asn1.Kind kind)
        {
            var item = Asn1.ParseItem(string.Format("{0:X2}04DEADBEEF", tag).DecodeHex());
            Assert.AreEqual(kind, item.Key);
            Assert.AreEqual(new byte[] {0xDE, 0xAD, 0xBE, 0xEF}, item.Value);
        }

        private static string Repeat(string s, int times)
        {
            // Inefficient! Who cares?!
            var result = "";
            for (var i = 0; i < times; ++i)
                result += s;

            return result;
        }
    }
}
