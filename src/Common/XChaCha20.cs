// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Runtime.InteropServices;

namespace PasswordManagerAccess.Common
{
    internal class XChaCha20
    {
        public const int KeySize = ChaCha20.KeySize;
        public const int NonceSize = 24;

        public XChaCha20(byte[] key, byte[] nonce)
            : this(key.AsRoSpan(), nonce.AsRoSpan()) { }

        public XChaCha20(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce)
        {
            // XChaCha20 is just ChaCha20 with precomputed key and nonce. The XChaCha20 nonce is longer.
            if (key.Length != KeySize)
                throw new InternalErrorException($"Key must be {KeySize} bytes, got {key.Length}");

            if (nonce.Length != NonceSize)
                throw new InternalErrorException($"Nonce must be {NonceSize} bytes, got {nonce.Length}");

            // The ChaCha20 key is generated from the XChaCha20 key and the first 16 bytes of the nonce via HChaCha20
            Span<byte> chaCha20Key = stackalloc byte[KeySize];
            HChaCha20(key, nonce.Slice(0, 16), chaCha20Key);

            // The ChcCha20 nonce is just 4 zeros and the last 12 bytes of the nonce
            Span<byte> chaCha20Nonce = stackalloc byte[ChaCha20.NonceSize];
            chaCha20Nonce[0] = 0;
            chaCha20Nonce[1] = 0;
            chaCha20Nonce[2] = 0;
            chaCha20Nonce[3] = 0;
            nonce.Slice(16, 8).CopyTo(chaCha20Nonce.Slice(4, 8));

            // The rest is just ChaCha20
            _engine = new ChaCha20(chaCha20Key, chaCha20Nonce);
        }

        public void ProcessBytes(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            _engine.ProcessBytes(inputBuffer, inputOffset, inputCount, outputBuffer, outputOffset);
        }

        //
        // Internal
        //

        internal static void HChaCha20(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, Span<byte> outKey)
        {
            // TODO: Could there be any unaligned memory access problems?
            var keyU32 = MemoryMarshal.Cast<byte, uint>(key);
            uint x00 = ChaCha20.InitialState0;
            uint x01 = ChaCha20.InitialState1;
            uint x02 = ChaCha20.InitialState2;
            uint x03 = ChaCha20.InitialState3;
            uint x04 = keyU32[0];
            uint x05 = keyU32[1];
            uint x06 = keyU32[2];
            uint x07 = keyU32[3];
            uint x08 = keyU32[4];
            uint x09 = keyU32[5];
            uint x10 = keyU32[6];
            uint x11 = keyU32[7];

            // TODO: Could there be any unaligned memory access problems?
            var nonceU32 = MemoryMarshal.Cast<byte, uint>(nonce);
            uint x12 = nonceU32[0];
            uint x13 = nonceU32[1];
            uint x14 = nonceU32[2];
            uint x15 = nonceU32[3];

            // TODO: This is exact the same code as in ChaCha20.ChaChaCore. Could we DRY this up?
            for (var i = 0; i < ChaCha20.Rounds; i += 2)
            {
                x00 += x04;
                x12 = ChaCha20.RotateLeft(x12 ^ x00, 16);
                x08 += x12;
                x04 = ChaCha20.RotateLeft(x04 ^ x08, 12);
                x00 += x04;
                x12 = ChaCha20.RotateLeft(x12 ^ x00, 8);
                x08 += x12;
                x04 = ChaCha20.RotateLeft(x04 ^ x08, 7);
                x01 += x05;
                x13 = ChaCha20.RotateLeft(x13 ^ x01, 16);
                x09 += x13;
                x05 = ChaCha20.RotateLeft(x05 ^ x09, 12);
                x01 += x05;
                x13 = ChaCha20.RotateLeft(x13 ^ x01, 8);
                x09 += x13;
                x05 = ChaCha20.RotateLeft(x05 ^ x09, 7);
                x02 += x06;
                x14 = ChaCha20.RotateLeft(x14 ^ x02, 16);
                x10 += x14;
                x06 = ChaCha20.RotateLeft(x06 ^ x10, 12);
                x02 += x06;
                x14 = ChaCha20.RotateLeft(x14 ^ x02, 8);
                x10 += x14;
                x06 = ChaCha20.RotateLeft(x06 ^ x10, 7);
                x03 += x07;
                x15 = ChaCha20.RotateLeft(x15 ^ x03, 16);
                x11 += x15;
                x07 = ChaCha20.RotateLeft(x07 ^ x11, 12);
                x03 += x07;
                x15 = ChaCha20.RotateLeft(x15 ^ x03, 8);
                x11 += x15;
                x07 = ChaCha20.RotateLeft(x07 ^ x11, 7);
                x00 += x05;
                x15 = ChaCha20.RotateLeft(x15 ^ x00, 16);
                x10 += x15;
                x05 = ChaCha20.RotateLeft(x05 ^ x10, 12);
                x00 += x05;
                x15 = ChaCha20.RotateLeft(x15 ^ x00, 8);
                x10 += x15;
                x05 = ChaCha20.RotateLeft(x05 ^ x10, 7);
                x01 += x06;
                x12 = ChaCha20.RotateLeft(x12 ^ x01, 16);
                x11 += x12;
                x06 = ChaCha20.RotateLeft(x06 ^ x11, 12);
                x01 += x06;
                x12 = ChaCha20.RotateLeft(x12 ^ x01, 8);
                x11 += x12;
                x06 = ChaCha20.RotateLeft(x06 ^ x11, 7);
                x02 += x07;
                x13 = ChaCha20.RotateLeft(x13 ^ x02, 16);
                x08 += x13;
                x07 = ChaCha20.RotateLeft(x07 ^ x08, 12);
                x02 += x07;
                x13 = ChaCha20.RotateLeft(x13 ^ x02, 8);
                x08 += x13;
                x07 = ChaCha20.RotateLeft(x07 ^ x08, 7);
                x03 += x04;
                x14 = ChaCha20.RotateLeft(x14 ^ x03, 16);
                x09 += x14;
                x04 = ChaCha20.RotateLeft(x04 ^ x09, 12);
                x03 += x04;
                x14 = ChaCha20.RotateLeft(x14 ^ x03, 8);
                x09 += x14;
                x04 = ChaCha20.RotateLeft(x04 ^ x09, 7);
            }

            var outKeyU32 = MemoryMarshal.Cast<byte, uint>(outKey);
            outKeyU32[0] = x00;
            outKeyU32[1] = x01;
            outKeyU32[2] = x02;
            outKeyU32[3] = x03;
            outKeyU32[4] = x12;
            outKeyU32[5] = x13;
            outKeyU32[6] = x14;
            outKeyU32[7] = x15;
        }

        private readonly ChaCha20 _engine;
    }
}
