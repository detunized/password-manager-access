// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Linq;
using PasswordManagerAccess.TrueKey;
using Xunit;

namespace PasswordManagerAccess.Test.TrueKey
{
    public class SjclQuadTest
    {
        private const byte A0 = 0x00;
        private const byte A1 = 0x00;
        private const byte A2 = 0xF0;
        private const byte A3 = 0x0D;

        private const byte B0 = 0x00;
        private const byte B1 = 0xC0;
        private const byte B2 = 0xFF;
        private const byte B3 = 0xEE;

        private const byte C0 = 0x0D;
        private const byte C1 = 0xEF;
        private const byte C2 = 0xAC;
        private const byte C3 = 0xED;

        private const byte D0 = 0xDE;
        private const byte D1 = 0xAD;
        private const byte D2 = 0xBE;
        private const byte D3 = 0xEF;

        private const uint A = 0x0000F00D;
        private const uint B = 0x00C0FFEE;
        private const uint C = 0x0DEFACED;
        private const uint D = 0xDEADBEEF;

        private static readonly uint[] Abcd = new uint[4] {A, B, C, D};
        private static readonly byte[] AbcdBytes = new byte[16]
        {
            A0, A1, A2, A3,
            B0, B1, B2, B3,
            C0, C1, C2, C3,
            D0, D1, D2, D3,
        };

        [Fact]
        public void Constructed_from_a_b_c_d()
        {
            VerifyDeadBeefQuad(new SjclQuad(A, B, C, D));
        }

        [Fact]
        public void Constructed_from_abcd()
        {
            var abcd = new uint[] {A, B, C, D};
            VerifyDeadBeefQuad(new SjclQuad(abcd));
        }

        [Fact]
        public void Constructed_from_abcd_with_offset()
        {
            var poison = new uint[] {0xCCCCCCCC, 0xCCCCCCCC, 0xCCCCCCCC};
            var abcd = poison.Concat(Abcd).Concat(poison).ToArray();
            VerifyDeadBeefQuad(new SjclQuad(abcd, poison.Length));
        }

        [Fact]
        public void Constructed_from_empty_abcd()
        {
            var abcd = new uint[0];
            VerifyZeroQuad(new SjclQuad(abcd));
        }

        [Fact]
        public void Constructed_from_partial_abcd()
        {
            var abcd = new uint[] {A, B};
            VerifyQuad(new SjclQuad(abcd), A, B, 0, 0);
        }

        [Fact]
        public void Constructed_from_partial_abcd_with_offset()
        {
            var abcd = new uint[] {0xCCCCCCCC, 0xCCCCCCCC, A, B};
            VerifyQuad(new SjclQuad(abcd, 2), A, B, 0, 0);
        }

        [Fact]
        public void Constructed_from_partial_abcd_with_negative_offset()
        {
            VerifyQuad(new SjclQuad(Abcd, -1), 0, A, B, C);
            VerifyQuad(new SjclQuad(Abcd, -2), 0, 0, A, B);
            VerifyQuad(new SjclQuad(Abcd, -3), 0, 0, 0, A);

            VerifyZeroQuad(new SjclQuad(Abcd, -4));
        }

        [Fact]
        public void Constructed_from_partial_abcd_with_offset_past_end()
        {
            VerifyZeroQuad(new SjclQuad(Abcd, Abcd.Length * 2));
        }

        [Fact]
        public void Constructed_from_bytes()
        {
            VerifyDeadBeefQuad(new SjclQuad(AbcdBytes));
        }

        [Fact]
        public void Constructed_from_bytes_with_offset()
        {
            var poison = new byte[] {0xCC, 0xCC, 0xCC};
            var bytes = poison.Concat(AbcdBytes).Concat(poison).ToArray();
            VerifyDeadBeefQuad(new SjclQuad(bytes, poison.Length));
        }

        [Fact]
        public void Constructed_from_empty_bytes()
        {
            VerifyZeroQuad(new SjclQuad(new byte[0]));
        }

        [Fact]
        public void Constructed_from_partial_bytes()
        {
            var bytes = new byte[] {A0, A1, A2, A3, B0, B1, B2};
            VerifyQuad(new SjclQuad(bytes), A, (uint)B0 << 24 | (uint)B1 << 16 | (uint)B2 << 8, 0, 0);
        }

        [Fact]
        public void Constructed_from_partial_bytes_with_offset()
        {
            var bytes = new byte[] {0xCC, 0xCC, 0xCC, A0, A1, A2, A3, B0, B1, B2};
            VerifyQuad(new SjclQuad(bytes, 3), A, (uint)B0 << 24 | (uint)B1 << 16 | (uint)B2 << 8, 0, 0);
        }

        [Fact]
        public void Constructed_from_partial_bytes_with_negative_offset()
        {
            VerifyQuad(new SjclQuad(AbcdBytes,  -1), W( 0, A0, A1, A2),
                                                     W(A3, B0, B1, B2),
                                                     W(B3, C0, C1, C2),
                                                     W(C3, D0, D1, D2));
            VerifyQuad(new SjclQuad(AbcdBytes,  -2), W( 0,  0, A0, A1),
                                                     W(A2, A3, B0, B1),
                                                     W(B2, B3, C0, C1),
                                                     W(C2, C3, D0, D1));
            VerifyQuad(new SjclQuad(AbcdBytes,  -3), W( 0,  0,  0, A0),
                                                     W(A1, A2, A3, B0),
                                                     W(B1, B2, B3, C0),
                                                     W(C1, C2, C3, D0));
            VerifyQuad(new SjclQuad(AbcdBytes,  -4), 0,
                                                     A,
                                                     B,
                                                     C);
            VerifyQuad(new SjclQuad(AbcdBytes, -14), 0,
                                                     0,
                                                     0,
                                                     W( 0,  0,  0, A0));

            VerifyZeroQuad(new SjclQuad(AbcdBytes, -15));
        }

        [Fact]
        public void Constructed_from_partial_bytes_with_offset_past_end()
        {
            VerifyZeroQuad(new SjclQuad(AbcdBytes, AbcdBytes.Length * 2));
        }

        [Fact]
        public void Indexer_gets_correct_values()
        {
            Assert.Equal(A, Quad[0]);
            Assert.Equal(B, Quad[1]);
            Assert.Equal(C, Quad[2]);
            Assert.Equal(D, Quad[3]);
        }

        [Fact]
        public void Indexer_get_throws_on_negative_index()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => Quad[-1]);
        }

        [Fact]
        public void Indexer_get_throws_on_too_large_index()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => Quad[4]);
        }

        [Fact]
        public void Indexer_sets_correct_values()
        {
            var q = Quad;
            q[0] = D;
            q[1] = C;
            q[2] = B;
            q[3] = A;

            VerifyQuad(q, D, C, B, A);
        }

        [Fact]
        public void Indexer_set_throws_on_negative_index()
        {
            var q = Quad;
            Assert.Throws<ArgumentOutOfRangeException>(() => q[-1] = 0);
        }

        [Fact]
        public void Indexer_set_throws_on_too_large_index()
        {
            var q = Quad;
            Assert.Throws<ArgumentOutOfRangeException>(() => q[4] = 0);
        }

        [Fact]
        public void ToAbcd_returns_abcd()
        {
            var abcd = Quad.ToAbcd();
            Assert.Equal(Abcd, abcd);
        }

        [Fact]
        public void GetByte_returns_correct_bytes()
        {
            Assert.Equal(A0, Quad.GetByte(0));
            Assert.Equal(A1, Quad.GetByte(1));
            Assert.Equal(A2, Quad.GetByte(2));
            Assert.Equal(A3, Quad.GetByte(3));

            Assert.Equal(B0, Quad.GetByte(4));
            Assert.Equal(B1, Quad.GetByte(5));
            Assert.Equal(B2, Quad.GetByte(6));
            Assert.Equal(B3, Quad.GetByte(7));

            Assert.Equal(C0, Quad.GetByte(8));
            Assert.Equal(C1, Quad.GetByte(9));
            Assert.Equal(C2, Quad.GetByte(10));
            Assert.Equal(C3, Quad.GetByte(11));

            Assert.Equal(D0, Quad.GetByte(12));
            Assert.Equal(D1, Quad.GetByte(13));
            Assert.Equal(D2, Quad.GetByte(14));
            Assert.Equal(D3, Quad.GetByte(15));
        }

        [Fact]
        public void GetByte_throws_on_negative_index()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => Quad.GetByte(-1));
        }

        [Fact]
        public void GetByte_throws_on_too_large_index()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => Quad.GetByte(16));
        }

        [Fact]
        public void SetByte_sets_correct_bytes()
        {
            var q = Quad;

            q.SetByte( 0, D0);
            q.SetByte( 1, D1);
            q.SetByte( 2, D2);
            q.SetByte( 3, D3);

            q.SetByte( 4, C0);
            q.SetByte( 5, C1);
            q.SetByte( 6, C2);
            q.SetByte( 7, C3);

            q.SetByte( 8, B0);
            q.SetByte( 9, B1);
            q.SetByte(10, B2);
            q.SetByte(11, B3);

            q.SetByte(12, A0);
            q.SetByte(13, A1);
            q.SetByte(14, A2);
            q.SetByte(15, A3);

            VerifyQuad(q, D, C, B, A);
        }

        [Fact]
        public void SetByte_throws_on_negative_index()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => Quad.SetByte(-1, 0));
        }

        [Fact]
        public void SetByte_throws_on_too_large_index()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => Quad.SetByte(16, 0));
        }

        [Fact]
        public void ToBytes_returns_abcd_as_bytes()
        {
            Assert.Equal(AbcdBytes, Quad.ToBytes());
        }

        [Fact]
        public void Xor_returns_correct_result()
        {
            VerifyZeroQuad(Quad ^ Quad);
        }

        //
        // Helpers
        //

        private static SjclQuad Quad
        {
            get
            {
                return new SjclQuad(A, B, C, D);
            }
        }

        private static uint W(byte b0, byte b1 = 0, byte b2 = 0, byte b3 = 0)
        {
            return (uint)b0 << 24 | (uint)b1 << 16 | (uint)b2 << 8 | b3;
        }

        private static void VerifyDeadBeefQuad(SjclQuad quad)
        {
            VerifyQuad(quad, A, B, C, D);
        }

        private static void VerifyZeroQuad(SjclQuad quad)
        {
            VerifyQuad(quad, 0, 0, 0, 0);
        }

        private static void VerifyQuad(SjclQuad quad, uint a, uint b, uint c, uint d)
        {
            Assert.Equal(a, quad.A);
            Assert.Equal(b, quad.B);
            Assert.Equal(c, quad.C);
            Assert.Equal(d, quad.D);
        }
    }
}
