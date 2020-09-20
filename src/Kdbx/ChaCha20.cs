// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

// Copyright (c) 2000 - 2017 The Legion of the Bouncy Castle Inc. (http://www.bouncycastle.org)
// For the original license see: https://www.bouncycastle.org/csharp/licence.html

// This is a modified version of ChaCha7539Engine.cs from the Bouncy Castle library.
// The original file could be found here:
// https://github.com/bcgit/bc-csharp/blob/master/crypto/src/crypto/engines/ChaCha7539Engine.cs

using System.Runtime.CompilerServices;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.Kdbx
{
    // TODO: Add some tests. It's clear that is works because the content is decrypted and it's correct.
    //       Even if one byte was off, the checksums wouldn't match.
    //       It's good to have some smoke tests anyway for some possible refactoring in the future.
    internal class ChaCha20Engine
    {
        private const int KeySize = 32;
        private const int NonceSize = 12;
        private const int Rounds = 20;
        private const int StateSize = 16;

        private readonly uint[] _engineState = new uint[StateSize];
        private readonly uint[] _workBuffer = new uint[StateSize];
        private readonly byte[] _keyStream = new byte[StateSize * 4];
        private int _index = 0;

        public ChaCha20Engine(byte[] key, byte[] nonce)
        {
            if (key.Length != KeySize)
                throw new InternalErrorException($"Key must be {KeySize} bytes, got {key.Length}");

            if (nonce.Length != NonceSize)
                throw new InternalErrorException($"Nonce must be {NonceSize} bytes, got {nonce.Length}");

            // Bytes for "expand 32-byte k"
            _engineState[0] = 0x61707865;
            _engineState[1] = 0x3320646E;
            _engineState[2] = 0x79622D32;
            _engineState[3] = 0x6B206574;

            LE_To_UInt32(key, 0, _engineState, 4, 8);
            LE_To_UInt32(nonce, 0, _engineState, 13, 3);
        }

        public void ProcessBytes(byte[] inBytes, int inOff, int len, byte[] outBytes, int outOff)
        {
            if (len > inBytes.Length - inOff)
                throw new InternalErrorException("Input buffer is too short");

            if (len > outBytes.Length - outOff)
                throw new InternalErrorException("Output buffer is too short");

            // TODO: This should be rather slow to loop like this over each byte
            //       Profile this and see if there are some easy speed gains.
            for (var i = 0; i < len; i++)
            {
                if (_index == 0)
                {
                    GenerateKeyStream(_keyStream);
                    AdvanceCounter();
                }

                outBytes[i + outOff] = (byte)(_keyStream[_index] ^ inBytes[i + inOff]);
                _index = (_index + 1) & 63;
            }
        }

        //
        // Internal
        //

        private void GenerateKeyStream(byte[] output)
        {
            ChaChaCore(Rounds, _engineState, _workBuffer);
            UInt32_To_LE(_workBuffer, output, 0);
        }

        private void AdvanceCounter()
        {
            if (++_engineState[12] == 0)
                throw new InternalErrorException("attempt to increase counter past 2^32.");
        }

        private static void ChaChaCore(int rounds, uint[] input, uint[] x)
        {
            uint x00 = input[0];
            uint x01 = input[1];
            uint x02 = input[2];
            uint x03 = input[3];
            uint x04 = input[4];
            uint x05 = input[5];
            uint x06 = input[6];
            uint x07 = input[7];
            uint x08 = input[8];
            uint x09 = input[9];
            uint x10 = input[10];
            uint x11 = input[11];
            uint x12 = input[12];
            uint x13 = input[13];
            uint x14 = input[14];
            uint x15 = input[15];

            for (int i = rounds; i > 0; i -= 2)
            {
                x00 += x04;
                x12 = RotateLeft(x12 ^ x00, 16);
                x08 += x12;
                x04 = RotateLeft(x04 ^ x08, 12);
                x00 += x04;
                x12 = RotateLeft(x12 ^ x00, 8);
                x08 += x12;
                x04 = RotateLeft(x04 ^ x08, 7);
                x01 += x05;
                x13 = RotateLeft(x13 ^ x01, 16);
                x09 += x13;
                x05 = RotateLeft(x05 ^ x09, 12);
                x01 += x05;
                x13 = RotateLeft(x13 ^ x01, 8);
                x09 += x13;
                x05 = RotateLeft(x05 ^ x09, 7);
                x02 += x06;
                x14 = RotateLeft(x14 ^ x02, 16);
                x10 += x14;
                x06 = RotateLeft(x06 ^ x10, 12);
                x02 += x06;
                x14 = RotateLeft(x14 ^ x02, 8);
                x10 += x14;
                x06 = RotateLeft(x06 ^ x10, 7);
                x03 += x07;
                x15 = RotateLeft(x15 ^ x03, 16);
                x11 += x15;
                x07 = RotateLeft(x07 ^ x11, 12);
                x03 += x07;
                x15 = RotateLeft(x15 ^ x03, 8);
                x11 += x15;
                x07 = RotateLeft(x07 ^ x11, 7);
                x00 += x05;
                x15 = RotateLeft(x15 ^ x00, 16);
                x10 += x15;
                x05 = RotateLeft(x05 ^ x10, 12);
                x00 += x05;
                x15 = RotateLeft(x15 ^ x00, 8);
                x10 += x15;
                x05 = RotateLeft(x05 ^ x10, 7);
                x01 += x06;
                x12 = RotateLeft(x12 ^ x01, 16);
                x11 += x12;
                x06 = RotateLeft(x06 ^ x11, 12);
                x01 += x06;
                x12 = RotateLeft(x12 ^ x01, 8);
                x11 += x12;
                x06 = RotateLeft(x06 ^ x11, 7);
                x02 += x07;
                x13 = RotateLeft(x13 ^ x02, 16);
                x08 += x13;
                x07 = RotateLeft(x07 ^ x08, 12);
                x02 += x07;
                x13 = RotateLeft(x13 ^ x02, 8);
                x08 += x13;
                x07 = RotateLeft(x07 ^ x08, 7);
                x03 += x04;
                x14 = RotateLeft(x14 ^ x03, 16);
                x09 += x14;
                x04 = RotateLeft(x04 ^ x09, 12);
                x03 += x04;
                x14 = RotateLeft(x14 ^ x03, 8);
                x09 += x14;
                x04 = RotateLeft(x04 ^ x09, 7);
            }

            x[0] = x00 + input[0];
            x[1] = x01 + input[1];
            x[2] = x02 + input[2];
            x[3] = x03 + input[3];
            x[4] = x04 + input[4];
            x[5] = x05 + input[5];
            x[6] = x06 + input[6];
            x[7] = x07 + input[7];
            x[8] = x08 + input[8];
            x[9] = x09 + input[9];
            x[10] = x10 + input[10];
            x[11] = x11 + input[11];
            x[12] = x12 + input[12];
            x[13] = x13 + input[13];
            x[14] = x14 + input[14];
            x[15] = x15 + input[15];
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint RotateLeft(uint i, int shift)
        {
            return (i << shift) ^ (i >> -shift);
        }

        private static void UInt32_To_LE(uint n, byte[] bs, int off)
        {
            bs[off] = (byte)n;
            bs[off + 1] = (byte)(n >> 8);
            bs[off + 2] = (byte)(n >> 16);
            bs[off + 3] = (byte)(n >> 24);
        }

        private static void UInt32_To_LE(uint[] ns, byte[] bs, int off)
        {
            for (int i = 0; i < ns.Length; ++i)
            {
                UInt32_To_LE(ns[i], bs, off);
                off += 4;
            }
        }

        private static uint LE_To_UInt32(byte[] bs, int off)
        {
            return bs[off]
                   | (uint)bs[off + 1] << 8
                   | (uint)bs[off + 2] << 16
                   | (uint)bs[off + 3] << 24;
        }

        private static void LE_To_UInt32(byte[] bs, int bOff, uint[] ns, int nOff, int count)
        {
            for (int i = 0; i < count; ++i)
            {
                ns[nOff + i] = LE_To_UInt32(bs, bOff);
                bOff += 4;
            }
        }
    }
}
