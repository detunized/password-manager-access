// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Common;
using Xunit;

namespace PasswordManagerAccess.Test.Common
{
    public class OutputSpanStreamTest
    {
        [Fact]
        public void WriteByte_writes_byte()
        {
            var s = Stream(4);
            s.WriteByte(0xDE);
            s.WriteByte(0xAD);
            s.WriteByte(0xBE);
            s.WriteByte(0xEF);

            Assert.True(s.IsEof);
            Assert.Equal(0xDE, s.Span[0]);
            Assert.Equal(0xAD, s.Span[1]);
            Assert.Equal(0xBE, s.Span[2]);
            Assert.Equal(0xEF, s.Span[3]);
        }

        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(2)]
        [InlineData(3)]
        [InlineData(4)]
        [InlineData(5)]
        [InlineData(6)]
        [InlineData(7)]
        [InlineData(13)]
        public void WriteUInt64_writes_ulong(int pad)
        {
            var s = Stream(8, pad);
            s.WriteUInt64(0xFEEDF00DDEADBEEF);

            Assert.True(s.IsEof);
            Assert.Equal(0xEF, s.Span[pad + 0]);
            Assert.Equal(0xBE, s.Span[pad + 1]);
            Assert.Equal(0xAD, s.Span[pad + 2]);
            Assert.Equal(0xDE, s.Span[pad + 3]);
            Assert.Equal(0x0D, s.Span[pad + 4]);
            Assert.Equal(0xF0, s.Span[pad + 5]);
            Assert.Equal(0xED, s.Span[pad + 6]);
            Assert.Equal(0xFE, s.Span[pad + 7]);
        }

        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(2)]
        [InlineData(3)]
        [InlineData(13)]
        public void WriteInt32_writes_int(int pad)
        {
            var s = Stream(4, pad);
            s.WriteInt32(unchecked((int)0xDEADBEEF));

            Assert.True(s.IsEof);
            Assert.Equal(0xEF, s.Span[pad + 0]);
            Assert.Equal(0xBE, s.Span[pad + 1]);
            Assert.Equal(0xAD, s.Span[pad + 2]);
            Assert.Equal(0xDE, s.Span[pad + 3]);
        }

        [Theory]
        [InlineData(0)]
        [InlineData(13)]
        public void WriteBytes_writes_bytes(int pad)
        {
            var s = Stream(4, pad);
            s.WriteBytes("deadbeef".DecodeHex());

            Assert.True(s.IsEof);
            Assert.Equal(0xDE, s.Span[pad + 0]);
            Assert.Equal(0xAD, s.Span[pad + 1]);
            Assert.Equal(0xBE, s.Span[pad + 2]);
            Assert.Equal(0xEF, s.Span[pad + 3]);
        }

        //
        // Helpers
        //

        internal static OutputSpanStream Stream(int size, int pad = 0)
        {
            var s = new OutputSpanStream(new byte[size + pad]);
            for (var i = 0; i < pad; i++)
                s.WriteByte(0xCC);

            return s;
        }
    }
}
