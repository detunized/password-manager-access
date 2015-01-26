// Copyright (C) 2015 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Linq;
using NUnit.Framework;

namespace PasswordBox.Test
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
        public void Constructed_from_partial_bytes_with_offset_past_end()
        {
            VerifyZeroQuad(new SjclQuad(AbcdBytes, AbcdBytes.Length * 2));
        }

        [Test]
        public void Indexer_gets_correct_values()
        {
            Assert.AreEqual(A, Quad[0]);
            Assert.AreEqual(B, Quad[1]);
            Assert.AreEqual(C, Quad[2]);
            Assert.AreEqual(D, Quad[3]);
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
        public void ToAbcd_returns_abcd()
        {
            var abcd = Quad.ToAbcd();
            Assert.AreEqual(Abcd, abcd);
        }

        [Test]
        public void GetByte_returns_correct_bytes()
        {
            Assert.AreEqual(A0, Quad.GetByte( 0));
            Assert.AreEqual(A1, Quad.GetByte( 1));
            Assert.AreEqual(A2, Quad.GetByte( 2));
            Assert.AreEqual(A3, Quad.GetByte( 3));

            Assert.AreEqual(B0, Quad.GetByte( 4));
            Assert.AreEqual(B1, Quad.GetByte( 5));
            Assert.AreEqual(B2, Quad.GetByte( 6));
            Assert.AreEqual(B3, Quad.GetByte( 7));

            Assert.AreEqual(C0, Quad.GetByte( 8));
            Assert.AreEqual(C1, Quad.GetByte( 9));
            Assert.AreEqual(C2, Quad.GetByte(10));
            Assert.AreEqual(C3, Quad.GetByte(11));

            Assert.AreEqual(D0, Quad.GetByte(12));
            Assert.AreEqual(D1, Quad.GetByte(13));
            Assert.AreEqual(D2, Quad.GetByte(14));
            Assert.AreEqual(D3, Quad.GetByte(15));
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
        public void ToBytes_returns_abcd_as_bytes()
        {
            Assert.AreEqual(AbcdBytes, Quad.ToBytes());
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

        private void VerifyQuad(SjclQuad quad)
        {
            VerifyQuad(quad, A, B, C, D);
        }

        private void VerifyZeroQuad(SjclQuad quad)
        {
            VerifyQuad(quad, 0, 0, 0, 0);
        }

        private void VerifyQuad(SjclQuad quad, uint a, uint b, uint c, uint d)
        {
            Assert.AreEqual(a, quad.A);
            Assert.AreEqual(b, quad.B);
            Assert.AreEqual(c, quad.C);
            Assert.AreEqual(d, quad.D);
        }
    }
}
