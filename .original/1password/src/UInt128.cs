// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace OnePassword
{
    internal struct UInt128
    {
        public ulong High;
        public ulong Low;

        public UInt128(ulong high, ulong low)
        {
            High = high;
            Low = low;
        }

        public UInt128(byte[] bytes)
            : this(bytes, 0, bytes.Length)
        {
        }

        public UInt128(byte[] bytes, int offset, int length)
        {
            High = LoadUInt64(bytes, offset, length);
            Low = LoadUInt64(bytes, offset + 8, length);
        }

        public byte[] ToBytes()
        {
            var bytes = new byte[16];
            StoreUInt64(High, bytes, 0, 16);
            StoreUInt64(Low, bytes, 8, 16);

            return bytes;
        }

        public bool IsZero()
        {
            return (High | Low) == 0;
        }

        public bool IsOdd()
        {
            return (Low & 1) != 0;
        }

        public void XorWith(UInt128 x)
        {
            High ^= x.High;
            Low ^= x.Low;
        }

        public void ShiftLeftBy1()
        {
            High = (High << 1) | (Low >> 63);
            Low <<= 1;
        }

        public void ShiftRightBy1()
        {
            Low = (Low >> 1) | (High << 63);
            High >>= 1;
        }

        private static ulong LoadUInt64(byte[] bytes, int offset, int length)
        {
            ulong r = 0;
            for (int i = 0; i < 8; ++i)
                r = (r << 8) | (offset + i < length ? bytes[offset + i] : (byte)0);

            return r;
        }

        private static void StoreUInt64(ulong x, byte[] bytes, int offset, int length)
        {
            for (int i = 0; i < 8; ++i)
                if (offset + i < length)
                    bytes[offset + i] = (byte)((x >> ((7 - i) * 8)) & 0xFF);
        }
    };
}
