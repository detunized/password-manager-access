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
