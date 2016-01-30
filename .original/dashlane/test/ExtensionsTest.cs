// Copyright (C) 2016 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using NUnit.Framework;

namespace Dashlane.Test
{
    [TestFixture]
    class ExtensionsTest
    {
        //
        // Dashlane extensions
        //

        [Test]
        public void String_ToBytes_converts_string_to_utf8_bytes()
        {
            Assert.That(
                "".ToBytes(),
                Is.EqualTo(new byte[] { }));

            Assert.That(
                "All your base are belong to us".ToBytes(),
                Is.EqualTo(new byte[] {
                    65, 108, 108, 32, 121, 111, 117, 114, 32, 98, 97, 115, 101, 32, 97, 114,
                    101, 32, 98, 101, 108, 111, 110, 103, 32, 116, 111, 32, 117, 115}
                ));
        }

        [Test]
        public void ByteArray_Sub_returns_subarray()
        {
            var array = "0123456789abcdef".ToBytes();
            var check = new Action<int, int, string>((start, length, expected) =>
                Assert.That(array.Sub(start, length), Is.EqualTo(expected.ToBytes())));

            // Subarrays at 0, no overflow
            check(0, 1, "0");
            check(0, 2, "01");
            check(0, 3, "012");
            check(0, 15, "0123456789abcde");
            check(0, 16, "0123456789abcdef");

            // Subarrays in the middle, no overflow
            check(1, 1, "1");
            check(3, 2, "34");
            check(8, 3, "89a");
            check(15, 1, "f");

            // Subarrays of zero length, no overflow
            check(0, 0, "");
            check(1, 0, "");
            check(9, 0, "");
            check(15, 0, "");

            // Subarrays at 0 with overflow
            check(0, 17, "0123456789abcdef");
            check(0, 12345, "0123456789abcdef");
            check(0, int.MaxValue, "0123456789abcdef");

            // Subarrays in the middle with overflow
            check(1, 16, "123456789abcdef");
            check(1, 12345, "123456789abcdef");
            check(8, 9, "89abcdef");
            check(8, 67890, "89abcdef");
            check(15, 2, "f");
            check(15, int.MaxValue, "f");

            // Subarrays beyond the end
            check(16, 0, "");
            check(16, 1, "");
            check(16, 16, "");
            check(16, int.MaxValue, "");
            check(12345, 0, "");
            check(12345, 1, "");
            check(12345, 56789, "");
            check(12345, int.MaxValue, "");
            check(int.MaxValue, 0, "");
            check(int.MaxValue, 1, "");
            check(int.MaxValue, 12345, "");
            check(int.MaxValue, int.MaxValue, "");
        }

        [Test]
        [ExpectedException(typeof(ArgumentOutOfRangeException), ExpectedMessage = "Length should be nonnegative\r\nParameter name: length")]
        public void ByteArray_Sub_throws_on_negative_length()
        {
            new byte[] {}.Sub(0, -1337);
        }

        //
        // Dashlane.Test extensions
        //

        [Test]
        public void String_Decode64_decodes_base64()
        {
            Assert.That("".Decode64(), Is.EqualTo(new byte[] {}));
            Assert.That("YQ==".Decode64(), Is.EqualTo(new byte[] { 0x61 }));
            Assert.That("YWI=".Decode64(), Is.EqualTo(new byte[] { 0x61, 0x62 }));
            Assert.That("YWJj".Decode64(), Is.EqualTo(new byte[] { 0x61, 0x62, 0x63 }));
            Assert.That("YWJjZA==".Decode64(), Is.EqualTo(new byte[] { 0x61, 0x62, 0x63, 0x64 }));
        }
    }
}
