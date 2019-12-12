// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using NUnit.Framework;

namespace OnePassword.Test
{
    [TestFixture]
    public class UInt128Test
    {
        // TODO: Add more tests. Only testing the tricky places for now.

        [Test]
        public void UInt128_reads_from_partial_arrays()
        {
            var bytes = "feeddeadbeeff00ddeadbeeffeedf00d".DecodeHex();

            var x0 = new UInt128(bytes, 0, 0);
            Assert.That(x0.High, Is.EqualTo(0));
            Assert.That(x0.Low, Is.EqualTo(0));

            var x1 = new UInt128(bytes, 0, 1);
            Assert.That(x1.High, Is.EqualTo(0xFE00000000000000));
            Assert.That(x1.Low, Is.EqualTo(0));

            var x8 = new UInt128(bytes, 0, 8);
            Assert.That(x8.High, Is.EqualTo(0xFEEDDEADBEEFF00D));
            Assert.That(x8.Low, Is.EqualTo(0));

            var x15 = new UInt128(bytes, 0, 15);
            Assert.That(x15.High, Is.EqualTo(0xFEEDDEADBEEFF00D));
            Assert.That(x15.Low, Is.EqualTo(0xDEADBEEFFEEDF000));

            var x16 = new UInt128(bytes, 0, 16);
            Assert.That(x16.High, Is.EqualTo(0xFEEDDEADBEEFF00D));
            Assert.That(x16.Low, Is.EqualTo(0xDEADBEEFFEEDF00D));
        }

        [Test]
        public void ShiftLeftBy1_shifts_left_by_1_from_low_half_to_high()
        {
            var x = new UInt128(0, 1ul << 63);
            x.ShiftLeftBy1();

            Assert.That(x.High, Is.EqualTo(1));
            Assert.That(x.Low, Is.EqualTo(0));
        }

        [Test]
        public void ShiftRightBy1_shifts_right_by_1_from_high_half_to_low()
        {
            var x = new UInt128(1, 0);
            x.ShiftRightBy1();

            Assert.That(x.High, Is.EqualTo(0));
            Assert.That(x.Low, Is.EqualTo(1ul << 63));
        }

        [Test]
        public void ShiftRightBy1_extends_with_zero()
        {
            var x = new UInt128(~0ul, 0);
            x.ShiftRightBy1();

            Assert.That(x.High & (1ul << 63), Is.EqualTo(0));
        }
    }
}
