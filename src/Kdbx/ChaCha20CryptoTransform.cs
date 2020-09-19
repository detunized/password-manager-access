// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Buffers;
using System.Security.Cryptography;
using CSChaCha20;

namespace PasswordManagerAccess.Kdbx
{
    internal class ChaCha20CryptoTransform: ICryptoTransform
    {
        public int InputBlockSize => 1;
        public int OutputBlockSize => 1;
        public bool CanTransformMultipleBlocks => true;
        public bool CanReuseTransform => true;

        public static ChaCha20CryptoTransform CreateEncryptor(ChaCha20 engine) => new ChaCha20CryptoTransform(engine);
        public static ChaCha20CryptoTransform CreateDecryptor(ChaCha20 engine) => new ChaCha20CryptoTransform(engine);

        private ChaCha20CryptoTransform(ChaCha20 engine)
        {
            _engine = engine;
        }

        public int TransformBlock(byte[] inputBuffer,
                                  int inputOffset,
                                  int inputCount,
                                  byte[] outputBuffer,
                                  int outputOffset)
        {
            // TODO: Get rid of the copies. At the moment ChaCha20 does not support byte range on both input
            //       and output buffer, that why we need to make copies to a temp buffer and back.
            var tempInputBuffer = ArrayPool<byte>.Shared.Rent(inputCount);
            var tempOutputBuffer = ArrayPool<byte>.Shared.Rent(inputCount);
            try
            {
                Buffer.BlockCopy(inputBuffer, inputOffset, tempInputBuffer, 0, inputCount);
                _engine.DecryptBytes(tempOutputBuffer, tempInputBuffer, inputCount);
                Buffer.BlockCopy(tempOutputBuffer, 0, outputBuffer, outputOffset, inputCount);
                return inputCount;
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(tempInputBuffer);
                ArrayPool<byte>.Shared.Return(tempOutputBuffer);
            }
        }

        public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            if (inputCount == 0)
                return Array.Empty<byte>();

            var tempInputBuffer = ArrayPool<byte>.Shared.Rent(inputCount);
            try
            {
                Buffer.BlockCopy(inputBuffer, inputOffset, tempInputBuffer, 0, inputCount);
                return _engine.DecryptBytes(tempInputBuffer);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(tempInputBuffer);
            }
        }

        public void Dispose()
        {
            // Nothing to dispose of
        }

        private readonly ChaCha20 _engine;
    }
}
