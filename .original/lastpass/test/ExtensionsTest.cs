// Copyright (C) 2013 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using NUnit.Framework;

namespace LastPass.Test
{
    [TestFixture]
    class ExtensionsTest
    {
        [Test]
        public void Reverse()
        {
            Assert.AreEqual(0u, 0u.Reverse());
            Assert.AreEqual(0xffu, 0xff000000u.Reverse());
            Assert.AreEqual(0xff000000u, 0xffu.Reverse());
            Assert.AreEqual(0xff00ff00u, 0xff00ffu.Reverse());
            Assert.AreEqual(0x78563412u, 0x12345678u.Reverse());
            Assert.AreEqual(0xdeadbeefu, 0xefbeaddeu.Reverse());
        }

        [Test]
        public void FromBigEndian()
        {
            Assert.AreEqual(0u, BitConverter.ToUInt32(new byte[] {0x00, 0x00, 0x00, 0x00}, 0).FromBigEndian());
            Assert.AreEqual(0x12345678u, BitConverter.ToUInt32(new byte[] {0x12, 0x34, 0x56, 0x78}, 0).FromBigEndian());
            Assert.AreEqual(0xdeadbeefu, BitConverter.ToUInt32(new byte[] {0xde, 0xad, 0xbe, 0xef}, 0).FromBigEndian());
        }

        [Test]
        public void ToUtf8()
        {
            Assert.AreEqual("", new byte[] {}.ToUtf8());
            Assert.AreEqual(_helloUtf8, _helloUtf8Bytes.ToUtf8());
        }

        [Test]
        public void ToHex()
        {
            foreach (var i in _hexToBytes)
                Assert.AreEqual(i.Key, i.Value.ToHex());
        }

        [Test]
        public void ToBytes()
        {
            Assert.AreEqual(new byte[] {}, "".ToBytes());
            Assert.AreEqual(_helloUtf8Bytes, _helloUtf8.ToBytes());
        }

        [Test]
        public void DecodeHex()
        {
            foreach (var i in _hexToBytes)
            {
                Assert.AreEqual(i.Value, i.Key.DecodeHex());
                Assert.AreEqual(i.Value, i.Key.ToUpper().DecodeHex());
            }
        }

        [Test]
        [ExpectedException(typeof(ArgumentException), ExpectedMessage = "Input length must be multple of 2")]
        public void DecodeHex_throws_on_odd_length()
        {
            "0".DecodeHex();
        }

        [Test]
        [ExpectedException(typeof(ArgumentException), ExpectedMessage = "Input contains invalid characters")]
        public void DecodeHex_throws_on_non_hex_characters()
        {
            "xz".DecodeHex();
        }

        [Test]
        public void Decode64()
        {
            Assert.AreEqual(new byte[] {}, "".Decode64());
            Assert.AreEqual(new byte[] {0x61}, "YQ==".Decode64());
            Assert.AreEqual(new byte[] {0x61, 0x62}, "YWI=".Decode64());
            Assert.AreEqual(new byte[] {0x61, 0x62, 0x63}, "YWJj".Decode64());
            Assert.AreEqual(new byte[] {0x61, 0x62, 0x63, 0x64}, "YWJjZA==".Decode64());
        }

        [Test]
        public void Times()
        {
            var times = new int[] {0, 1, 2, 5, 10};
            foreach (var i in times)
            {
                var called = 0;
                i.Times(() => ++called);
                Assert.AreEqual(i, called);
            }
        }

        private readonly string _helloUtf8 = "Hello, UTF-8!";
        private readonly byte[] _helloUtf8Bytes = new byte[] {
            0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x2C, 0x20, 0x55, 0x54, 0x46, 0x2D, 0x38, 0x21
        };

        private readonly Dictionary<string, byte[]> _hexToBytes = new Dictionary<string, byte[]> {
            {"",
             new byte[] {}},

            {"00",
             new byte[] {0}},

            {"00ff",
             new byte[] {0, 255}},

            {"00010203040506070809",
             new byte[] {0, 1, 2, 3, 4, 5, 6, 7, 8, 9}},

            {"000102030405060708090a0b0c0d0e0f",
             new byte[] {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}},

            {"8af633933e96a3c3550c2734bd814195",
             new byte[] {0x8A, 0xF6, 0x33, 0x93, 0x3E, 0x96, 0xA3, 0xC3, 0x55, 0x0C, 0x27, 0x34, 0xBD, 0x81, 0x41, 0x95}}
        };
    }
}
