// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Runtime.InteropServices;
using PasswordManagerAccess.Common;
using Xunit;

namespace PasswordManagerAccess.Test.Common
{
    public class SpanStreamTest
    {
        [Fact]
        public void Size_returns_size()
        {
            var s = DeadBeef();
            Assert.Equal(4, s.Size);
            s.ReadByte();
            Assert.Equal(4, s.Size);
            s.ReadByte();
            Assert.Equal(4, s.Size);
            s.ReadByte();
            Assert.Equal(4, s.Size);
            s.ReadByte();
            Assert.Equal(4, s.Size);
            Assert.True(s.IsEof);
        }

        [Fact]
        public void Position_returns_position()
        {
            var s = DeadBeef();
            Assert.Equal(0, s.Position);
            s.ReadByte();
            Assert.Equal(1, s.Position);
            s.ReadByte();
            Assert.Equal(2, s.Position);
            s.ReadByte();
            Assert.Equal(3, s.Position);
            s.ReadByte();
            Assert.Equal(4, s.Position);
            Assert.True(s.IsEof);
        }

        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(2)]
        [InlineData(3)]
        [InlineData(4)]
        public void Skip_skips_ahead(int skip)
        {
            var s = DeadBeef();
            s.Skip(skip);
            Assert.Equal(skip, s.Position);
        }

        [Theory]
        [InlineData(5)]
        [InlineData(13)]
        [InlineData(1337)]
        [InlineData(int.MaxValue)]
        public void Skip_throws_at_end(int skip)
        {
            Exceptions.AssertThrowsInternalError(() =>
                                                 {
                                                     var s = DeadBeef();
                                                     s.Skip(skip);
                                                 },
                                                 "Reading past the end of stream");
        }

        [Fact]
        public void ReadByte_returns_byte()
        {
            var s = DeadBeef();

            Assert.Equal(0xDE, s.ReadByte());
            Assert.Equal(0xAD, s.ReadByte());
            Assert.Equal(0xBE, s.ReadByte());
            Assert.Equal(0xEF, s.ReadByte());
            Assert.True(s.IsEof);
        }

        [Fact]
        public void ReadByte_throws_at_end()
        {
            Exceptions.AssertThrowsInternalError(() =>
                                                 {
                                                     var s = DeadBeef();
                                                     s.Skip(4);
                                                     s.ReadByte();
                                                 },
                                                 "Reading past the end of stream");
        }

        [Fact]
        public void ReadInt16_returns_short()
        {
            var s = DeadBeef();

            Assert.Equal(unchecked((short)0xADDE), s.ReadInt16());
            Assert.Equal(unchecked((short)0xEFBE), s.ReadInt16());
            Assert.True(s.IsEof);
        }

        [Fact]
        public void ReadUInt16_returns_short()
        {
            var s = DeadBeef();

            Assert.Equal(0xADDE, s.ReadUInt16());
            Assert.Equal(0xEFBE, s.ReadUInt16());
            Assert.True(s.IsEof);
        }

        [Theory]
        [InlineData(3)]
        [InlineData(4)]
        public void ReadUInt16_throws_at_end(int skip)
        {
            Exceptions.AssertThrowsInternalError(() =>
                                                 {
                                                     var s = DeadBeef();
                                                     s.Skip(skip);
                                                     s.ReadUInt16();
                                                 },
                                                 "Reading past the end of stream");
        }

        [Fact]
        public void ReadInt32_returns_short()
        {
            var s = DeadBeef();
            Assert.Equal(unchecked((int)0xEFBEADDE), s.ReadInt32());
            Assert.True(s.IsEof);
        }

        [Fact]
        public void ReadUInt32_returns_short()
        {
            var s = DeadBeef();
            Assert.Equal(0xEFBEADDE, s.ReadUInt32());
            Assert.True(s.IsEof);
        }

        [Theory]
        [InlineData(1)]
        [InlineData(2)]
        [InlineData(3)]
        [InlineData(4)]
        public void ReadUInt32_throws_at_end(int skip)
        {
            Exceptions.AssertThrowsInternalError(() =>
                                                 {
                                                     var s = DeadBeef();
                                                     s.Skip(skip);
                                                     s.ReadUInt32();
                                                 },
                                                 "Reading past the end of stream");
        }

        [Fact]
        public void ReadInt64_returns_short()
        {
            var s = DeadBeefX2();
            Assert.Equal(unchecked((long)0xEFBEADDEEFBEADDE), s.ReadInt64());
            Assert.True(s.IsEof);
        }

        [Fact]
        public void ReadUInt64_returns_short()
        {
            var s = DeadBeefX2();
            Assert.Equal(0xEFBEADDEEFBEADDE, s.ReadUInt64());
            Assert.True(s.IsEof);
        }

        [Theory]
        [InlineData(1)]
        [InlineData(2)]
        [InlineData(3)]
        [InlineData(4)]
        [InlineData(5)]
        [InlineData(6)]
        [InlineData(7)]
        [InlineData(8)]
        public void ReadUInt64_throws_at_end(int skip)
        {
            Exceptions.AssertThrowsInternalError(() =>
                                                 {
                                                     var s = DeadBeefX2();
                                                     s.Skip(skip);
                                                     s.ReadUInt64();
                                                 },
                                                 "Reading past the end of stream");
        }

        [Theory]
        [InlineData(1, "de")]
        [InlineData(2, "dead")]
        [InlineData(3, "deadbe")]
        [InlineData(4, "deadbeef")]
        public void ReadBytes_returns_bytes(int size, string expected)
        {
            var s = DeadBeef();
            var slice = s.ReadBytes(size);

            Assert.True(slice.SequenceEqual(expected.DecodeHex()));
        }

        [Theory]
        [InlineData(0, 5)]
        [InlineData(0, 1337)]
        [InlineData(1, 4)]
        [InlineData(1, 1337)]
        [InlineData(2, 3)]
        [InlineData(2, 1337)]
        [InlineData(3, 2)]
        [InlineData(3, 1337)]
        [InlineData(4, 1)]
        [InlineData(4, 1337)]
        public void ReadBytes_throws_at_end(int skip, int read)
        {
            Exceptions.AssertThrowsInternalError(() =>
                                                 {
                                                     var s = DeadBeef();
                                                     s.Skip(skip);
                                                     s.ReadBytes(read);
                                                 },
                                                 "Reading past the end of stream");
        }

        [Fact]
        public void ReadT_returns_T()
        {
            var s = Hex("42" + "3713" + "efbeadde" + "efbeadde0df0edfe");
            var t = s.Read<TestStruct>();

            Assert.Equal(0x42, t.B);
            Assert.Equal(0x1337, t.S);
            Assert.Equal(0xDEADBEEF, t.I);
            Assert.Equal(0xFEEDF00DDEADBEEF, t.L);
            Assert.True(s.IsEof);
        }

        [Theory]
        [InlineData(1)]
        [InlineData(2)]
        [InlineData(5)]
        [InlineData(10)]
        [InlineData(14)]
        [InlineData(15)]
        public void ReadT_throws_at_end(int skip)
        {
            Exceptions.AssertThrowsInternalError(() =>
                                                 {
                                                     var s = Hex("42" + "3713" + "efbeadde" + "efbeadde0df0edfe");
                                                     s.Skip(skip);
                                                     s.Read<TestStruct>();
                                                 },
                                                 "Reading past the end of stream");
        }

        //
        // Helpers
        //

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        internal readonly struct TestStruct
        {
            public readonly byte B;
            public readonly ushort S;
            public readonly uint I;
            public readonly ulong L;
        }

        internal static SpanStream DeadBeef() => Hex("deadbeef");
        internal static SpanStream DeadBeefX2() => Hex("deadbeefdeadbeef");
        internal static SpanStream Hex(string hex) => hex.DecodeHex().AsRoSpan().ToStream();
    }
}
