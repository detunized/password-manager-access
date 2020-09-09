// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace PasswordManagerAccess.Common
{
    internal ref struct SpanStream
    {
        public int Size => _span.Length;
        public int Position => _offset;
        public bool IsEof => Position == Size;

        public SpanStream(byte[] bytes): this(bytes.AsRoSpan())
        {
        }

        public SpanStream(ReadOnlySpan<byte> span)
        {
            _span = span;
            _offset = 0;
        }

        public void Skip(int size)
        {
            CheckAdvance(size);
        }

        public byte ReadByte()
        {
            return _span[CheckAdvance(1)];
        }

        public short ReadInt16()
        {
            return (short)ReadUInt16();
        }

        public ushort ReadUInt16()
        {
            var offset = CheckAdvance(2);
            return (ushort)(_span[offset] | (_span[offset + 1] << 8));
        }

        public int ReadInt32()
        {
            return (int)ReadUInt32();
        }

        public uint ReadUInt32()
        {
            var offset = CheckAdvance(4);
            return _span[offset] |
                   ((uint)_span[offset + 1] << 8) |
                   ((uint)_span[offset + 2] << 16) |
                   ((uint)_span[offset + 3] << 24);
        }

        public long ReadInt64()
        {
            return (long)ReadUInt64();
        }

        public ulong ReadUInt64()
        {
            var offset = CheckAdvance(8);
            return _span[offset] |
                   ((ulong)_span[offset + 1] << 8) |
                   ((ulong)_span[offset + 2] << 16) |
                   ((ulong)_span[offset + 3] << 24) |
                   ((ulong)_span[offset + 4] << 32) |
                   ((ulong)_span[offset + 5] << 40) |
                   ((ulong)_span[offset + 6] << 48) |
                   ((ulong)_span[offset + 7] << 56);
        }

        public ReadOnlySpan<byte> ReadBytes(int size)
        {
            return _span.Slice(CheckAdvance(size), size);
        }

        public T Read<T>() where T: struct
        {
            var size = Unsafe.SizeOf<T>();
            var offset = CheckAdvance(size);
            return MemoryMarshal.Read<T>(_span.Slice(offset, size));
        }

        //
        // Private
        //

        private int CheckAdvance(int size)
        {
            if (size < 0)
                throw new InternalErrorException("Size should not be negative");

            var o = _offset;
            if (o + size > _span.Length)
                throw new InternalErrorException("Reading past the end of stream");
            _offset += size;
            return o;
        }

        private readonly ReadOnlySpan<byte> _span;
        private int _offset;
    }
}
