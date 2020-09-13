// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.IO;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.Kdbx
{
    internal class BlockStream: Stream
    {
        public BlockStream(Stream baseStream, byte[] hmacKey, int bufferSize = 4096)
        {
            _baseStream = baseStream;
            _hmacKey = hmacKey;
            _buffer = new byte[bufferSize];
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            // Start new block
            if (_blockMac == null)
            {
                _blockMac = ReadExact(32);
                _blockSize = BitConverter.ToInt32(ReadExact(4), 0);

                // End of stream
                if (_blockSize == 0)
                    return 0;

                _blockReadPointer = 0;
                _bufferActualSize = 0;
                _bufferReadPointer = 0;
            }

            // Read next piece into the buffer
            if (_bufferReadPointer >= _bufferActualSize)
            {
                var toRead = Math.Min(_buffer.Length, _blockSize - _blockReadPointer);
                _bufferActualSize = _baseStream.Read(_buffer, 0, toRead);
                _bufferReadPointer = 0;
            }

            var toCopy = Math.Min(count, _bufferActualSize - _bufferReadPointer);
            Array.Copy(_buffer, _bufferReadPointer, buffer, offset, toCopy);
            _bufferReadPointer += toCopy;
            _blockReadPointer += toCopy;

            // End of block
            if (_blockReadPointer >= _blockSize)
            {
                var blockHmacKey = Util.ComputeBlockHmacKey(_hmacKey, _blockIndex);

                // using var sha = new HMACSHA256(hmacKey);
                //
                // sha.TransformBlock(BitConverter.GetBytes(blockIndex), 0, 8, null, 0);
                // sha.TransformBlock(BitConverter.GetBytes(size), 0, 4, null, 0);
                // sha.TransformBlock(ciphertext, 0, ciphertext.Length, null, 0);
                // sha.TransformFinalBlock(Array.Empty<byte>(), 0, 0);

                _blockIndex++;
                _blockMac = null;
            }

            return toCopy;
        }

        public override void Flush() => throw new NotImplementedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotImplementedException();
        public override void SetLength(long value) => throw new NotImplementedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotImplementedException();

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotImplementedException();

        public override long Position
        {
            get => throw new NotImplementedException();
            set => throw new NotImplementedException();
        }

        //
        //
        //

        internal byte[] ReadExact(int size)
        {
            var bytes = new byte[size];
            var read = 0;

            for (;;)
            {
                var last = _baseStream.Read(bytes, read, size - read);
                read += last;

                if (read == size)
                    return bytes;

                if (last <= 0)
                    throw new InternalErrorException($"Failed to read {size} bytes from the stream");
            }
        }

        private readonly Stream _baseStream;
        private readonly byte[] _hmacKey;
        private readonly byte[] _buffer;

        private ulong _blockIndex;
        private byte[] _blockMac;
        private int _blockSize;
        private int _blockReadPointer;
        private int _bufferActualSize;
        private int _bufferReadPointer;
    }
}
