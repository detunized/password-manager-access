// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.IO;
using PasswordManagerAccess.StickyPassword;
using Xunit;

namespace PasswordManagerAccess.Test.StickyPassword
{
    public class ExtensionsTest
    {
        public const string TestString = "All your base are belong to us";
        public static readonly byte[] TestBytes = {
            65, 108, 108, 32, 121, 111, 117, 114, 32, 98, 97, 115, 101, 32, 97,
            114, 101, 32, 98, 101, 108, 111, 110, 103, 32, 116, 111, 32, 117, 115
        };

        //
        // string
        //

        [Fact]
        public void String_ToBytes_converts_string_to_utf8_bytes()
        {
            Assert.Equal(new byte[]{}, "".ToBytes());
            Assert.Equal(TestBytes, TestString.ToBytes());
        }

        [Fact]
        public void String_Decode64_decodes_base64()
        {
            Assert.Equal(new byte[]{}, "".Decode64());
            Assert.Equal(new byte[]{0x61}, "YQ==".Decode64());
            Assert.Equal(new byte[]{0x61, 0x62}, "YWI=".Decode64());
            Assert.Equal(new byte[]{0x61, 0x62, 0x63}, "YWJj".Decode64());
            Assert.Equal(new byte[]{0x61, 0x62, 0x63, 0x64}, "YWJjZA==".Decode64());
        }

        //
        // byte[]
        //

        [Fact]
        public void ByteArray_ToUtf8_returns_string()
        {
            Assert.Equal("", new byte[]{}.ToUtf8());
            Assert.Equal(TestString, TestBytes.ToUtf8());
        }

        [Fact]
        public void ByteArray_Encode64_returns_base64()
        {
            Assert.Equal("", new byte[]{}.Encode64());
            Assert.Equal("YQ==", new byte[]{0x61}.Encode64());
            Assert.Equal("YWI=", new byte[]{0x61, 0x62}.Encode64());
            Assert.Equal("YWJj", new byte[]{0x61, 0x62, 0x63}.Encode64());
            Assert.Equal("YWJjZA==", new byte[]{0x61, 0x62, 0x63, 0x64}.Encode64());
        }

        //
        // Stream
        //

        [Fact]
        public void Stream_ReadAll_reads_from_empty_stream()
        {
            var bytes = new[]
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
                Assert.Equal(b, new MemoryStream(b).ReadAll());

                // Custom buffer size
                foreach (var size in bufferSizes)
                    Assert.Equal(b, new MemoryStream(b).ReadAll(size));
            }
        }

        [Fact]
        public void Stream_ReadAll_throws_on_zero_buffer_size()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => new MemoryStream().ReadAll(0));
        }
    }
}
