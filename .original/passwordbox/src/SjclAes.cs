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
    }
}
