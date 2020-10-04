// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.IO;
using System.Security.Cryptography;
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
            _hmac = new HMACSHA256(hmacKey);
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            // Start new block
            if (_blockMac == null)
            {
                _blockMac = _baseStream.ReadExact(32);

                // To avoid allocations we read into the cache buffer since it's unused at this point and parse from it
                _baseStream.ReadExact(_buffer, 0, 4);
                _blockSize = BitConverter.ToInt32(_buffer, 0);

                // End of stream
                if (_blockSize == 0)
                    return 0;

                _blockReadPointer = 0;
                _bufferActualSize = 0;
                _bufferReadPointer = 0;

                // Start the MAC calculation for the new block
                _hmac = new HMACSHA256(Util.ComputeBlockHmacKey(_hmacKey, _blockIndex));

                // To avoid allocation we write into the cache buffer and then use it for hashing
                var forHashing = new OutputSpanStream(_buffer);
                forHashing.WriteUInt64(_blockIndex);
                forHashing.WriteInt32(_blockSize);
                _hmac.TransformBlock(_buffer, 0, forHashing.Position, null, 0);
            }

            // Read next piece into the buffer
            if (_bufferReadPointer >= _bufferActualSize)
            {
                var toRead = Math.Min(_buffer.Length, _blockSize - _blockReadPointer);
                _bufferActualSize = _baseStream.Read(_buffer, 0, toRead);
                _bufferReadPointer = 0;

                // Hash the read portion
                _hmac.TransformBlock(_buffer, 0, _bufferActualSize, null, 0);
            }

            var toCopy = Math.Min(count, _bufferActualSize - _bufferReadPointer);
            Array.Copy(_buffer, _bufferReadPointer, buffer, offset, toCopy);
            _bufferReadPointer += toCopy;
            _blockReadPointer += toCopy;

            // End of block
            if (_blockReadPointer >= _blockSize)
            {
                // Finalize MAC
                _hmac.TransformFinalBlock(Array.Empty<byte>(), 0, 0);

                var storedMac = _blockMac;
                var computedMac = _hmac.Hash;

                _blockIndex++;
                _blockMac = null;
                _hmac.Dispose();
                _hmac = null;

                if (!Crypto.AreEqual(storedMac, computedMac))
                    throw new InternalErrorException("Corrupted, block MAC doesn't match");
            }

            return toCopy;
        }

        public override void Flush()
        {
        }

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
        // Private
        //

        private readonly Stream _baseStream;
        private readonly byte[] _hmacKey;
        private readonly byte[] _buffer;

        private ulong _blockIndex;
        private byte[] _blockMac;
        private int _blockSize;
        private int _blockReadPointer;
        private int _bufferActualSize;
        private int _bufferReadPointer;

        // TODO: This is only disposed during normal operation at end of each block.
        //       In case the sequence is terminated early with or without an error the
        //       object stays non-disposed.
        private HMACSHA256 _hmac;
    }
}
