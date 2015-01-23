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
    }
}
