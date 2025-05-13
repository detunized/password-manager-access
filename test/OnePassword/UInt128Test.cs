// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Common;
using UInt128 = PasswordManagerAccess.OnePassword.UInt128;

namespace PasswordManagerAccess.Test.OnePassword
{
    public class UInt128Test
    {
        // TODO: Add more tests. Only testing the tricky places for now.

        [Fact]
        public void UInt128_reads_from_partial_arrays()
        {
            var bytes = "feeddeadbeeff00ddeadbeeffeedf00d".DecodeHex();

            var x0 = new UInt128(bytes, 0, 0);
            Assert.Equal(0UL, x0.High);
            Assert.Equal(0UL, x0.Low);

            var x1 = new UInt128(bytes, 0, 1);
            Assert.Equal(0xFE00000000000000, x1.High);
            Assert.Equal(0UL, x1.Low);

            var x8 = new UInt128(bytes, 0, 8);
            Assert.Equal(0xFEEDDEADBEEFF00D, x8.High);
            Assert.Equal(0UL, x8.Low);

            var x15 = new UInt128(bytes, 0, 15);
            Assert.Equal(0xFEEDDEADBEEFF00D, x15.High);
            Assert.Equal(0xDEADBEEFFEEDF000, x15.Low);

            var x16 = new UInt128(bytes, 0, 16);
            Assert.Equal(0xFEEDDEADBEEFF00D, x16.High);
            Assert.Equal(0xDEADBEEFFEEDF00D, x16.Low);
        }

        [Fact]
        public void ShiftLeftBy1_shifts_left_by_1_from_low_half_to_high()
        {
            var x = new UInt128(0, 1ul << 63);
            x.ShiftLeftBy1();

            Assert.Equal(1UL, x.High);
            Assert.Equal(0UL, x.Low);
        }

        [Fact]
        public void ShiftRightBy1_shifts_right_by_1_from_high_half_to_low()
        {
            var x = new UInt128(1, 0);
            x.ShiftRightBy1();

            Assert.Equal(0UL, x.High);
            Assert.Equal(1ul << 63, x.Low);
        }

        [Fact]
        public void ShiftRightBy1_extends_with_zero()
        {
            var x = new UInt128(~0ul, 0);
            x.ShiftRightBy1();

            Assert.Equal(0UL, x.High & (1ul << 63));
        }
    }
}
