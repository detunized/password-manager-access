// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Security.Cryptography;

namespace PasswordManagerAccess.Common
{
    internal class ChaCha20CryptoTransform : ICryptoTransform
    {
        public int InputBlockSize => 1;
        public int OutputBlockSize => 1;
        public bool CanTransformMultipleBlocks => true;
        public bool CanReuseTransform => true;

        public static ChaCha20CryptoTransform CreateEncryptor(ChaCha20 engine)
        {
            return new ChaCha20CryptoTransform(engine);
        }

        public static ChaCha20CryptoTransform CreateDecryptor(ChaCha20 engine)
        {
            return new ChaCha20CryptoTransform(engine);
        }

        private ChaCha20CryptoTransform(ChaCha20 engine)
        {
            _engine = engine;
        }

        public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            _engine.ProcessBytes(inputBuffer, inputOffset, inputCount, outputBuffer, inputOffset);
            return inputCount;
        }

        public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            if (inputCount == 0)
                return Array.Empty<byte>();

            var output = new byte[inputCount];
            _engine.ProcessBytes(inputBuffer, inputOffset, inputCount, output, 0);
            return output;
        }

        public void Dispose()
        {
            // Nothing to dispose of
        }

        private readonly ChaCha20 _engine;
    }
}
