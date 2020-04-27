// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using PasswordManagerAccess.LastPass;
using Xunit;

namespace PasswordManagerAccess.Test.LastPass
{
    public class ExtensionsTest
    {
        [Fact]
        public void ToUtf8()
        {
            Assert.Equal("", new byte[] {}.ToUtf8());
            Assert.Equal(_helloUtf8, _helloUtf8Bytes.ToUtf8());
        }

        [Fact]
        public void ToHex()
        {
            foreach (var i in _hexToBytes)
                Assert.Equal(i.Key, i.Value.ToHex());
        }

        [Fact]
        public void ToBytes()
        {
            Assert.Equal(new byte[] {}, "".ToBytes());
            Assert.Equal(_helloUtf8Bytes, _helloUtf8.ToBytes());
        }

        [Fact]
        public void DecodeHex()
        {
            foreach (var i in _hexToBytes)
            {
                Assert.Equal(i.Value, i.Key.DecodeHex());
                Assert.Equal(i.Value, i.Key.ToUpper().DecodeHex());
            }
        }

        [Fact]
        public void DecodeHex_throws_on_odd_length()
        {
            Exceptions.AssertThrowsInternalError(() => "0".DecodeHex());
        }

        [Fact]
        public void DecodeHex_throws_on_non_hex_characters()
        {
            Exceptions.AssertThrowsInternalError(() => "xz".DecodeHex());
        }

        [Fact]
        public void Decode64()
        {
            Assert.Equal(new byte[] {}, "".Decode64());
            Assert.Equal(new byte[] {0x61}, "YQ==".Decode64());
            Assert.Equal(new byte[] {0x61, 0x62}, "YWI=".Decode64());
            Assert.Equal(new byte[] {0x61, 0x62, 0x63}, "YWJj".Decode64());
            Assert.Equal(new byte[] {0x61, 0x62, 0x63, 0x64}, "YWJjZA==".Decode64());
        }

        [Fact]
        public void Times()
        {
            var times = new int[] {0, 1, 2, 5, 10};
            foreach (var i in times)
            {
                var called = 0;
                i.Times(() => ++called);
                Assert.Equal(i, called);
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
