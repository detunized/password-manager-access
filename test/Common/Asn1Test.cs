// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Common;
using Xunit;

namespace PasswordManagerAccess.Test.Common
{
    public class Asn1Test
    {
        [Fact]
        public void Asn1_ParseItem_returns_integer()
        {
            ParseDeadBeefItem(2, Asn1.Kind.Integer);
        }

        [Fact]
        public void Asn1_ParseItem_returns_bytes()
        {
            ParseDeadBeefItem(4, Asn1.Kind.Bytes);
        }

        [Fact]
        public void Asn1_ParseItem_returns_null()
        {
            ParseDeadBeefItem(5, Asn1.Kind.Null);
        }

        [Fact]
        public void Asn1_ParseItem_returns_squence()
        {
            ParseDeadBeefItem(16, Asn1.Kind.Sequence);
        }

        [Fact]
        public void Asn1_ParseItem_throws_on_invalid_tag()
        {
            Exceptions.AssertThrowsInternalError(() => Asn1.ParseItem("0D04DEADBEEF".DecodeHex()), "Unknown ASN.1 tag 13");
        }

        [Fact]
        public void Asn1_ParseItem_reads_packed_size()
        {
            const int size = 127;
            var item = Asn1.ParseItem(("027F" + "AB".Repeat(size)).DecodeHex());

            Assert.Equal(size, item.Value.Length);
        }

        [Fact]
        public void Asn1_ParseItem_reads_single_byte_size()
        {
            const int size = 128;
            var item = Asn1.ParseItem(("028180" + "AB".Repeat(size)).DecodeHex());

            Assert.Equal(size, item.Value.Length);
        }

        [Fact]
        public void Asn1_ParseItem_reads_multi_byte_size()
        {
            const int size = 260;
            var item = Asn1.ParseItem(("02820104" + "AB".Repeat(size)).DecodeHex());

            Assert.Equal(size, item.Value.Length);
        }

        private static void ParseDeadBeefItem(byte tag, Asn1.Kind kind)
        {
            var item = Asn1.ParseItem($"{tag:X2}04DEADBEEF".DecodeHex());

            Assert.Equal(kind, item.Key);
            Assert.Equal(new byte[] { 0xDE, 0xAD, 0xBE, 0xEF }, item.Value);
        }
    }
}
