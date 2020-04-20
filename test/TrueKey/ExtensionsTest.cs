// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.IO;
using Newtonsoft.Json.Linq;
using PasswordManagerAccess.TrueKey;
using Xunit;

namespace PasswordManagerAccess.Test.TrueKey
{
    public class ExtensionsTest
    {
        //
        // uint
        //

        [Fact]
        public void ChangeEndianness_swaps_bytes()
        {
            var tests = new Dictionary<uint, uint>
            {
                {0x00000000u, 0x00000000u},
                {0xFF000000u, 0x000000FFu},
                {0x000000FFu, 0xFF000000u},
                {0x00FF00FFu, 0xFF00FF00u},
                {0x12345678u, 0x78563412u},
                {0xEFBEADDEu, 0xDEADBEEFu},
            };

            foreach (var i in tests)
            {
                Assert.Equal(i.Value, i.Key.ChangeEndianness());
                Assert.Equal(i.Key, i.Value.ChangeEndianness());
            }
        }

        [Fact]
        public void ChangeEndianness_applied_twice_doesn_change_value()
        {
            var tests = new []
            {
                0x00000000u,
                0x000000FFu,
                0xFF000000u,
                0xFF00FF00u,
                0x78563412u,
                0xDEADBEEFu,
            };

            foreach (var i in tests)
                Assert.Equal(i, i.ChangeEndianness().ChangeEndianness());
        }

        [Fact]
        public void FromBigEndian()
        {
            var tests = new Dictionary<uint, byte[]>
            {
                {0x00000000u, new byte[] {0x00, 0x00, 0x00, 0x00}},
                {0x12345678u, new byte[] {0x12, 0x34, 0x56, 0x78}},
                {0xDEADBEEFu, new byte[] {0xde, 0xad, 0xbe, 0xef}},
            };

            foreach (var i in tests)
                Assert.Equal(i.Key, BitConverter.ToUInt32(i.Value, 0).FromBigEndian());
        }

        //
        // DateTime
        //

        [Fact]
        public void DateTime_UnixSeconds_returns_number_of_seconds_since_epoch()
        {
            Assert.Equal(1493456789U, new DateTime(2017, 4, 29, 9, 6, 29, DateTimeKind.Utc).UnixSeconds());
        }
    }
}
