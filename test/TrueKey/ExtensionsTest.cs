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

        [Theory]
        [InlineData(0x00000000u, 0x00000000u)]
        [InlineData(0xFF000000u, 0x000000FFu)]
        [InlineData(0x000000FFu, 0xFF000000u)]
        [InlineData(0x00FF00FFu, 0xFF00FF00u)]
        [InlineData(0x12345678u, 0x78563412u)]
        [InlineData(0xEFBEADDEu, 0xDEADBEEFu)]
        public void ChangeEndianness_swaps_bytes(uint big, uint little)
        {
            Assert.Equal(big, little.ChangeEndianness());
            Assert.Equal(little, big.ChangeEndianness());
        }

        [Theory]
        [InlineData(0x00000000u)]
        [InlineData(0x000000FFu)]
        [InlineData(0xFF000000u)]
        [InlineData(0xFF00FF00u)]
        [InlineData(0x78563412u)]
        [InlineData(0xDEADBEEFu)]
        public void ChangeEndianness_applied_twice_doesnt_change_value(uint integer)
        {
            Assert.Equal(integer, integer.ChangeEndianness().ChangeEndianness());
        }

        [Theory]
        [InlineData(0x00000000u, new byte[] {0x00, 0x00, 0x00, 0x00})]
        [InlineData(0x12345678u, new byte[] {0x12, 0x34, 0x56, 0x78})]
        [InlineData(0xDEADBEEFu, new byte[] {0xde, 0xad, 0xbe, 0xef})]
        public void FromBigEndian(uint integer, byte[] bytes)
        {
            Assert.Equal(integer, BitConverter.ToUInt32(bytes, 0).FromBigEndian());
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
