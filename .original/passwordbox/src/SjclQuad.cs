// Copyright (C) 2015 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;

namespace PasswordBox
{
    struct SjclQuad
    {
        public SjclQuad(uint a, uint b, uint c, uint d)
        {
            A = a;
            B = b;
            C = c;
            D = d;
        }

        public SjclQuad(uint[] abcd, int offset = 0): this(0, 0, 0, 0)
        {
            for (var i = Math.Max(0, -offset); i < 4 && offset + i < abcd.Length; ++i)
                this[i] = abcd[offset + i];
        }

        public SjclQuad(byte[] bytes, int offset = 0): this(0, 0, 0, 0)
        {
            for (var i = Math.Max(0, -offset); i < 16 && offset + i < bytes.Length; ++i)
                this[i / 4] |= (uint)bytes[offset + i] << (3 - i % 4) * 8;
        }

        public uint this[int index]
        {
            get
            {
                switch (index)
                {
                case 0:
                    return A;
                case 1:
                    return B;
                case 2:
                    return C;
                case 3:
                    return D;
                default:
                    throw new ArgumentOutOfRangeException("index");
                }
            }

            set
            {
                switch (index)
                {
                case 0:
                    A = value;
                    break;
                case 1:
                    B = value;
                    break;
                case 2:
                    C = value;
                    break;
                case 3:
                    D = value;
                    break;
                default:
                    throw new ArgumentOutOfRangeException("index");
                }
            }
        }

        public uint[] ToAbcd()
        {
            return new uint[4] {A, B, C, D};
        }

        public byte GetByte(int index)
        {
            if (index < 0 || index > 15)
                throw new ArgumentOutOfRangeException("index");

            return (byte)(this[index / 4] >> (3 - index % 4) * 8);
        }

        public void SetByte(int index, byte value)
        {
            if (index < 0 || index > 15)
                throw new ArgumentOutOfRangeException("index");

            var word  = index / 4;
            var shift = (3 - index % 4) * 8;

            this[word] = (this[word] & ~(0xffu << shift)) | (uint)value << shift;
        }

        public byte[] ToBytes()
        {
            return new byte[16]
            {
                (byte)((A >> 24) & 0xff), (byte)((A >> 16) & 0xff), (byte)((A >> 8) & 0xff), (byte)(A & 0xff),
                (byte)((B >> 24) & 0xff), (byte)((B >> 16) & 0xff), (byte)((B >> 8) & 0xff), (byte)(B & 0xff),
                (byte)((C >> 24) & 0xff), (byte)((C >> 16) & 0xff), (byte)((C >> 8) & 0xff), (byte)(C & 0xff),
                (byte)((D >> 24) & 0xff), (byte)((D >> 16) & 0xff), (byte)((D >> 8) & 0xff), (byte)(D & 0xff),
            };
        }

        public static SjclQuad operator ^(SjclQuad lhs, SjclQuad rhs)
        {
            return new SjclQuad(lhs.A ^ rhs.A, lhs.B ^ rhs.B, lhs.C ^ rhs.C, lhs.D ^ rhs.D);
        }

        public uint A;
        public uint B;
        public uint C;
        public uint D;
    }
}
