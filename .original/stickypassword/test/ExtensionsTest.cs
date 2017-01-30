// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.IO;
using NUnit.Framework;

namespace StickyPassword.Test
{
    [TestFixture]
    class ExtensionsTest
    {
        public const string TestString = "All your base are belong to us";
        public static readonly byte[] TestBytes = {
            65, 108, 108, 32, 121, 111, 117, 114, 32, 98, 97, 115, 101, 32, 97,
            114, 101, 32, 98, 101, 108, 111, 110, 103, 32, 116, 111, 32, 117, 115
        };

        //
        // string
        //

        [Test]
        public void String_ToBytes_converts_string_to_utf8_bytes()
        {
            Assert.That("".ToBytes(), Is.EqualTo(new byte[] {}));
            Assert.That(TestString.ToBytes(), Is.EqualTo(TestBytes));
        }

        [Test]
        public void String_Decode64_decodes_base64()
        {
            Assert.That("".Decode64(), Is.EqualTo(new byte[] {}));
            Assert.That("YQ==".Decode64(), Is.EqualTo(new byte[] { 0x61 }));
            Assert.That("YWI=".Decode64(), Is.EqualTo(new byte[] { 0x61, 0x62 }));
            Assert.That("YWJj".Decode64(), Is.EqualTo(new byte[] { 0x61, 0x62, 0x63 }));
            Assert.That("YWJjZA==".Decode64(), Is.EqualTo(new byte[] { 0x61, 0x62, 0x63, 0x64 }));
        }

        //
        // byte[]
        //

        [Test]
        public void ByteArray_ToUtf8_returns_string()
        {
            Assert.That(new byte[] {}.ToUtf8(), Is.EqualTo(""));
            Assert.That(TestBytes.ToUtf8(), Is.EqualTo(TestString));
        }

        [Test]
        public void ByteArray_Encode64_returns_base64()
        {
            Assert.That(new byte[] { }.Encode64(), Is.EqualTo(""));
            Assert.That(new byte[] { 0x61 }.Encode64(), Is.EqualTo("YQ=="));
            Assert.That(new byte[] { 0x61, 0x62 }.Encode64(), Is.EqualTo("YWI="));
            Assert.That(new byte[] { 0x61, 0x62, 0x63 }.Encode64(), Is.EqualTo("YWJj"));
            Assert.That(new byte[] { 0x61, 0x62, 0x63, 0x64 }.Encode64(), Is.EqualTo("YWJjZA=="));
        }

        //
        // Stream
        //

        [Test]
        public void Stream_ReadAll_reads_from_empty_stream()
        {
            var bytes = new byte[][]
            {
                new byte[] {},
                new byte[] {1},
                new byte[] {1, 2},
                new byte[] {1, 2, 3},
                new byte[] {1, 2, 3, 4},
            };

            var bufferSizes = new uint[]
            {
                1,
                2,
                3,
                4,
                100,
                1024,
                65536
            };

            foreach (var b in bytes)
            {
                // Default buffer
                Assert.That(
                    new MemoryStream(b).ReadAll(),
                    Is.EqualTo(b));

                // Custom buffer size
                foreach (var size in bufferSizes)
                    Assert.That(
                        new MemoryStream(b).ReadAll(size),
                        Is.EqualTo(b));
            }
        }

        [Test]
        [ExpectedException(typeof(ArgumentOutOfRangeException))]
        public void Stream_ReadAll_throws_on_zero_buffer_size()
        {
            new MemoryStream().ReadAll(0);
        }
    }
}
