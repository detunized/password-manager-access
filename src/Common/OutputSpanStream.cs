// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Runtime.CompilerServices;

namespace PasswordManagerAccess.Common
{
    internal ref struct OutputSpanStream
    {
        public ReadOnlySpan<byte> Span => _span;
        public int Size => _span.Length;
        public int Position => _offset;
        public bool IsEof => Position == Size;

        public OutputSpanStream(byte[] bytes): this(bytes.AsSpan())
        {
        }

        public OutputSpanStream(Span<byte> span)
        {
            _span = span;
            _offset = 0;
        }

        public void WriteByte(byte value)
        {
            _span[CheckAdvance(1)] = value;
        }

        public void WriteInt32(int value)
        {
            Unsafe.WriteUnaligned(ref _span[CheckAdvance(4)], value);
        }

        public void WriteUInt64(ulong value)
        {
            Unsafe.WriteUnaligned(ref _span[CheckAdvance(8)], value);
        }

        public void WriteBytes(byte[] bytes)
        {
            var size = bytes.Length;
            var offset = CheckAdvance(size);
            bytes.CopyTo(_span.Slice(offset, size));
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
                throw new InternalErrorException("Writing past the end of stream");
            _offset += size;
            return o;
        }

        private readonly Span<byte> _span;
        private int _offset;
    }
}
