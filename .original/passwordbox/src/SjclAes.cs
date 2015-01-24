// Copyright (C) 2015 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Linq;

namespace PasswordBox
{
    static class SjclAes
    {
        internal static byte[] ComputeDoubleTable()
        {
            var table = new byte[256];
            for (var i = 0; i < 256; ++i)
                table[i] = (byte)((i << 1) ^ (i >> 7) * 283);

            return table;
        }

        internal static byte[] ComputeTrippleTable(byte[] doubleTable)
        {
            var table = new byte[256];
            for (var i = 0; i < 256; ++i)
                table[doubleTable[i] ^ i] = (byte)i;

            return table;
        }

        internal static byte[] ComputeSboxTable(byte[] doubleTable, byte[] trippleTable)
        {
            var table = new byte[256];

            var x = 0;
            var x2 = 0;
            var xInv = 0;

            for (var i = 0; i < 256; ++i)
            {
                var s = xInv ^ (xInv << 1) ^ (xInv << 2) ^ (xInv << 3) ^ (xInv << 4);
                table[x] = (byte)((s >> 8) ^ (s & 255) ^ 99);

                x2 = Math.Max((int)doubleTable[x], 1);
                xInv = Math.Max((int)trippleTable[xInv], 1);
                x ^= x2;
            }

            return table;
        }

        internal static byte[] ComputeInverseSboxTable(byte[] sboxTable)
        {
            var table = new byte[256];
            for (var i = 0; i < 256; ++i)
                table[sboxTable[i]] = (byte)i;

            return table;
        }

        internal static uint[,] ComputeDecodeTable(byte[] doubleTable, byte[] sboxTable)
        {
            var table = new uint[4, 256];
            uint x = 0;

            for (var i = 0; i < 256; ++i)
            {
                uint x2 = doubleTable[x];
                uint x4 = doubleTable[x2];
                uint x8 = doubleTable[x4];
                uint dec = (x8 * 0x1010101) ^ (x4 * 0x10001) ^ (x2 * 0x101) ^ (x * 0x1010100);

                for (var j = 0; j < 4; ++j)
                {
                    dec = (dec << 24) ^ (dec >> 8);
                    table[j, sboxTable[x]] = dec;
                }

                x ^= Math.Max(x2, 1);
            }

            return table;
        }

        internal static uint[] ScheduleEncryptionKey(uint[] key, byte[] sboxTable)
        {
            var inputLength = key.Length;
            if (inputLength != 4 && inputLength != 6 && inputLength != 8)
                throw new Exception(string.Format("Invalid key length ({0})", inputLength)); // TODO: Use custom exception!

            var keyLength = inputLength * 4 + 28;
            var encKey = new uint[keyLength];
            uint rcon = 1;

            key.CopyTo(encKey, 0);
            for (var i = inputLength; i < keyLength; ++i)
            {
                var t = encKey[i - 1];

                // Apply sbox
                if (i % inputLength == 0 || (inputLength == 8 && i % inputLength == 4))
                {
                    t = (uint)((sboxTable[t >> 24] << 24) ^
                               (sboxTable[(t >> 16) & 255] << 16) ^
                               (sboxTable[(t >> 8) & 255] << 8) ^
                               sboxTable[t & 255]);

                    // Shift rows and add rcon
                    if (i % inputLength == 0)
                    {
                        t = (t << 8) ^ (t >> 24) ^ (rcon << 24);
                        rcon = (rcon << 1) ^ (rcon >> 7) * 283;
                    }
                }

                encKey[i] = encKey[i - inputLength] ^ t;
            }

            return encKey;
        }

        internal static uint[] ScheduleDecryptionKey(uint[] encKey, byte[] sboxTable, uint[,] decodeTable)
        {
            var decKey = new uint[encKey.Length];

            var i = encKey.Length;
            for (var j = 0; i != 0; ++j, --i)
            {
                var t = encKey[(j & 3) != 0 ? i : i - 4];
                if (i <= 4 || j < 4)
                {
                    decKey[j] = t;
                }
                else
                {
                    decKey[j] = decodeTable[0, sboxTable[(t >> 24)      ]] ^
                                decodeTable[1, sboxTable[(t >> 16) & 255]] ^
                                decodeTable[2, sboxTable[(t >>  8) & 255]] ^
                                decodeTable[3, sboxTable[ t        & 255]];
                }
            }

            return decKey;
        }
    }
}
