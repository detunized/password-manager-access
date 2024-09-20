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

        public SpanStream(byte[] bytes)
            : this(bytes.AsRoSpan()) { }

        public SpanStream(byte[] bytes, int start, int size)
            : this(bytes.AsRoSpan(start, size)) { }

        public SpanStream(ReadOnlySpan<byte> span)
        {
            _span = span;
            _offset = 0;
        }

        public void Rewind()
        {
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
            return Unsafe.ReadUnaligned<ushort>(ref CheckAdvanceRef(sizeof(ushort)));
        }

        public int ReadInt32()
        {
            return (int)ReadUInt32();
        }

        public uint ReadUInt32()
        {
            return Unsafe.ReadUnaligned<uint>(ref CheckAdvanceRef(sizeof(uint)));
        }

        public long ReadInt64()
        {
            return (long)ReadUInt64();
        }

        public ulong ReadUInt64()
        {
            return Unsafe.ReadUnaligned<ulong>(ref CheckAdvanceRef(sizeof(ulong)));
        }

        public ReadOnlySpan<byte> ReadBytes(int size)
        {
            return _span.Slice(CheckAdvance(size), size);
        }

        public T Read<T>()
            where T : struct
        {
            var size = Unsafe.SizeOf<T>();
            var offset = CheckAdvance(size);
            return MemoryMarshal.Read<T>(_span.Slice(offset, size));
        }

        //
        // Private
        //

        private ref byte CheckAdvanceRef(int size)
        {
            return ref Unsafe.Add(ref MemoryMarshal.GetReference(_span), CheckAdvance(size));
        }

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
