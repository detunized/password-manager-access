// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Linq;
using NUnit.Framework;

namespace TrueKey.Test
{
    [TestFixture]
    class SjclQuadTest
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

        [Test]
        public void Constructed_from_a_b_c_d()
        {
            VerifyQuad(new SjclQuad(A, B, C, D));
        }

        [Test]
        public void Constructed_from_abcd()
        {
            var abcd = new uint[] {A, B, C, D};
            VerifyQuad(new SjclQuad(abcd));
        }

        [Test]
        public void Constructed_from_abcd_with_offset()
        {
            var poison = new uint[] {0xCCCCCCCC, 0xCCCCCCCC, 0xCCCCCCCC};
            var abcd = poison.Concat(Abcd).Concat(poison).ToArray();
            VerifyQuad(new SjclQuad(abcd, poison.Length));
        }

        [Test]
        public void Constructed_from_empty_abcd()
        {
            var abcd = new uint[0];
            VerifyZeroQuad(new SjclQuad(abcd));
        }

        [Test]
        public void Constructed_from_partial_abcd()
        {
            var abcd = new uint[] {A, B};
            VerifyQuad(new SjclQuad(abcd), A, B, 0, 0);
        }

        [Test]
        public void Constructed_from_partial_abcd_with_offset()
        {
            var abcd = new uint[] {0xCCCCCCCC, 0xCCCCCCCC, A, B};
            VerifyQuad(new SjclQuad(abcd, 2), A, B, 0, 0);
        }

        [Test]
        public void Constructed_from_partial_abcd_with_negative_offset()
        {
            VerifyQuad(new SjclQuad(Abcd, -1), 0, A, B, C);
            VerifyQuad(new SjclQuad(Abcd, -2), 0, 0, A, B);
            VerifyQuad(new SjclQuad(Abcd, -3), 0, 0, 0, A);

            VerifyZeroQuad(new SjclQuad(Abcd, -4));
        }

        [Test]
        public void Constructed_from_partial_abcd_with_offset_past_end()
        {
            VerifyZeroQuad(new SjclQuad(Abcd, Abcd.Length * 2));
        }

        [Test]
        public void Constructed_from_bytes()
        {
            VerifyQuad(new SjclQuad(AbcdBytes));
        }

        [Test]
        public void Constructed_from_bytes_with_offset()
        {
            var poison = new byte[] {0xCC, 0xCC, 0xCC};
            var bytes = poison.Concat(AbcdBytes).Concat(poison).ToArray();
            VerifyQuad(new SjclQuad(bytes, poison.Length));
        }

        [Test]
        public void Constructed_from_empty_bytes()
        {
            VerifyZeroQuad(new SjclQuad(new byte[0]));
        }

        [Test]
        public void Constructed_from_partial_bytes()
        {
            var bytes = new byte[] {A0, A1, A2, A3, B0, B1, B2};
            VerifyQuad(new SjclQuad(bytes), A, (uint)B0 << 24 | (uint)B1 << 16 | (uint)B2 << 8, 0, 0);
        }

        [Test]
        public void Constructed_from_partial_bytes_with_offset()
        {
            var bytes = new byte[] {0xCC, 0xCC, 0xCC, A0, A1, A2, A3, B0, B1, B2};
            VerifyQuad(new SjclQuad(bytes, 3), A, (uint)B0 << 24 | (uint)B1 << 16 | (uint)B2 << 8, 0, 0);
        }

        [Test]
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

        [Test]
        public void Constructed_from_partial_bytes_with_offset_past_end()
        {
            VerifyZeroQuad(new SjclQuad(AbcdBytes, AbcdBytes.Length * 2));
        }

        [Test]
        public void Indexer_gets_correct_values()
        {
            Assert.That(Quad[0], Is.EqualTo(A));
            Assert.That(Quad[1], Is.EqualTo(B));
            Assert.That(Quad[2], Is.EqualTo(C));
            Assert.That(Quad[3], Is.EqualTo(D));
        }

        [Test]
        public void Indexer_get_throws_on_negative_index()
        {
            Assert.That(() => Quad[-1], Throws.TypeOf<ArgumentOutOfRangeException>());
        }

        [Test]
        public void Indexer_get_throws_on_too_large_index()
        {
            Assert.That(() => Quad[4], Throws.TypeOf<ArgumentOutOfRangeException>());
        }

        [Test]
        public void Indexer_sets_correct_values()
        {
            var q = Quad;
            q[0] = D;
            q[1] = C;
            q[2] = B;
            q[3] = A;

            VerifyQuad(q, D, C, B, A);
        }

        [Test]
        public void Indexer_set_throws_on_negative_index()
        {
            var q = Quad;
            Assert.That(() => q[-1] = 0, Throws.TypeOf<ArgumentOutOfRangeException>());
        }

        [Test]
        public void Indexer_set_throws_on_too_large_index()
        {
            var q = Quad;
            Assert.That(() => q[4] = 0, Throws.TypeOf<ArgumentOutOfRangeException>());
        }

        [Test]
        public void ToAbcd_returns_abcd()
        {
            var abcd = Quad.ToAbcd();
            Assert.That(abcd, Is.EqualTo(Abcd));
        }

        [Test]
        public void GetByte_returns_correct_bytes()
        {
            Assert.That(Quad.GetByte( 0), Is.EqualTo(A0));
            Assert.That(Quad.GetByte( 1), Is.EqualTo(A1));
            Assert.That(Quad.GetByte( 2), Is.EqualTo(A2));
            Assert.That(Quad.GetByte( 3), Is.EqualTo(A3));

            Assert.That(Quad.GetByte( 4), Is.EqualTo(B0));
            Assert.That(Quad.GetByte( 5), Is.EqualTo(B1));
            Assert.That(Quad.GetByte( 6), Is.EqualTo(B2));
            Assert.That(Quad.GetByte( 7), Is.EqualTo(B3));

            Assert.That(Quad.GetByte( 8), Is.EqualTo(C0));
            Assert.That(Quad.GetByte( 9), Is.EqualTo(C1));
            Assert.That(Quad.GetByte(10), Is.EqualTo(C2));
            Assert.That(Quad.GetByte(11), Is.EqualTo(C3));

            Assert.That(Quad.GetByte(12), Is.EqualTo(D0));
            Assert.That(Quad.GetByte(13), Is.EqualTo(D1));
            Assert.That(Quad.GetByte(14), Is.EqualTo(D2));
            Assert.That(Quad.GetByte(15), Is.EqualTo(D3));
        }

        [Test]
        public void GetByte_throws_on_negative_index()
        {
            Assert.That(() => Quad.GetByte(-1), Throws.TypeOf<ArgumentOutOfRangeException>());
        }

        [Test]
        public void GetByte_throws_on_too_large_index()
        {
            Assert.That(() => Quad.GetByte(16), Throws.TypeOf<ArgumentOutOfRangeException>());
        }

        [Test]
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

        [Test]
        public void SetByte_throws_on_negative_index()
        {
            Assert.That(() => Quad.SetByte(-1, 0), Throws.TypeOf<ArgumentOutOfRangeException>());
        }

        [Test]
        public void SetByte_throws_on_too_large_index()
        {
            Assert.That(() => Quad.SetByte(16, 0), Throws.TypeOf<ArgumentOutOfRangeException>());
        }

        [Test]
        public void ToBytes_returns_abcd_as_bytes()
        {
            Assert.That(Quad.ToBytes(), Is.EqualTo(AbcdBytes));
        }

        [Test]
        public void Xor_returns_correct_result()
        {
            VerifyZeroQuad(Quad ^ Quad);
        }

        //
        // Helpers
        //

        private SjclQuad Quad
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

        private static void VerifyQuad(SjclQuad quad)
        {
            VerifyQuad(quad, A, B, C, D);
        }

        private static void VerifyZeroQuad(SjclQuad quad)
        {
            VerifyQuad(quad, 0, 0, 0, 0);
        }

        private static void VerifyQuad(SjclQuad quad, uint a, uint b, uint c, uint d)
        {
            Assert.That(quad.A, Is.EqualTo(a));
            Assert.That(quad.B, Is.EqualTo(b));
            Assert.That(quad.C, Is.EqualTo(c));
            Assert.That(quad.D, Is.EqualTo(d));
        }
    }
}
