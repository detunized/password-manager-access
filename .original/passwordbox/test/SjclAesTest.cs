// Copyright (C) 2015 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using NUnit.Framework;

namespace PasswordBox.Test
{
    [TestFixture]
    class SjclAesTest
    {
        [Test]
        public void Decrypt_returns_correct_value()
        {
            // TODO: Add more tests!

            var expected = new uint[] {0x140f0f10, 0x11b5223d, 0x79587717, 0xffd9ec3a};
            var aes = new SjclAes(new uint[] {0, 0, 0, 0});
            var plain = aes.Decrypt(new uint[] {0, 0, 0, 0});

            Assert.AreEqual(expected, plain);
        }

        [Test]
        public void ComputeDoubleTable_returns_correct_result()
        {
            var table = SjclAes.ComputeDoubleTable();

            // Test data is generated with SJCL sources
            Assert.AreEqual(256, table.Length);

            Assert.AreEqual(0x00, table[0x00]);
            Assert.AreEqual(0x02, table[0x01]);
            Assert.AreEqual(0x04, table[0x02]);
            Assert.AreEqual(0xfe, table[0x7f]);
            Assert.AreEqual(0x1b, table[0x80]);
            Assert.AreEqual(0xe7, table[0xfe]);
            Assert.AreEqual(0xe5, table[0xff]);
        }

        [Test]
        public void ComputeTrippleTable_returns_correct_result()
        {
            var table = SjclAes.ComputeTrippleTable(SjclAes.ComputeDoubleTable());

            // Test data is generated with SJCL sources
            Assert.AreEqual(256, table.Length);

            Assert.AreEqual(0x00, table[0x00]);
            Assert.AreEqual(0xf6, table[0x01]);
            Assert.AreEqual(0xf7, table[0x02]);
            Assert.AreEqual(0xdc, table[0x7f]);
            Assert.AreEqual(0x89, table[0x80]);
            Assert.AreEqual(0xa3, table[0xfe]);
            Assert.AreEqual(0x55, table[0xff]);
        }

        [Test]
        public void ComputeSboxTable_returns_correct_result()
        {
            var dt = SjclAes.ComputeDoubleTable();
            var tt = SjclAes.ComputeTrippleTable(dt);
            var table = SjclAes.ComputeSboxTable(dt, tt);

            // Test data is generated with SJCL sources
            Assert.AreEqual(256, table.Length);

            Assert.AreEqual(0x63, table[0x00]);
            Assert.AreEqual(0x7c, table[0x01]);
            Assert.AreEqual(0x77, table[0x02]);
            Assert.AreEqual(0xd2, table[0x7f]);
            Assert.AreEqual(0xcd, table[0x80]);
            Assert.AreEqual(0xbb, table[0xfe]);
            Assert.AreEqual(0x16, table[0xff]);

            // Every value should be exactly once
            Array.Sort(table);
            for (var i = 0; i < 256; ++i)
                Assert.AreEqual(i, table[i]);
        }

        [Test]
        public void ComputeInverseSboxTable_returns_correct_result()
        {
            var dt = SjclAes.ComputeDoubleTable();
            var tt = SjclAes.ComputeTrippleTable(dt);
            var sbox = SjclAes.ComputeSboxTable(dt, tt);
            var table = SjclAes.ComputeInverseSboxTable(sbox);

            // Test data is generated with SJCL sources
            Assert.AreEqual(256, table.Length);

            Assert.AreEqual(0x52, table[0x00]);
            Assert.AreEqual(0x09, table[0x01]);
            Assert.AreEqual(0x6a, table[0x02]);
            Assert.AreEqual(0x6b, table[0x7f]);
            Assert.AreEqual(0x3a, table[0x80]);
            Assert.AreEqual(0x0c, table[0xfe]);
            Assert.AreEqual(0x7d, table[0xff]);

            // Every value should be exactly once
            Array.Sort(table);
            for (var i = 0; i < 256; ++i)
                Assert.AreEqual(i, table[i]);
        }

        [Test]
        public void ComputeEncodeTable_returns_correct_result()
        {
            var dt = SjclAes.ComputeDoubleTable();
            var sbox = SjclAes.ComputeSboxTable(dt, SjclAes.ComputeTrippleTable(dt));
            var table = SjclAes.ComputeEncodeTable(dt, sbox);

            // Test data is generated with SJCL sources
            Assert.AreEqual(4, table.GetLength(0));
            Assert.AreEqual(256, table.GetLength(1));

            // 0
            Assert.AreEqual(0xc66363a5, table[0, 0x00]);
            Assert.AreEqual(0xf87c7c84, table[0, 0x01]);
            Assert.AreEqual(0xee777799, table[0, 0x02]);
            Assert.AreEqual(0xbfd2d26d, table[0, 0x7f]);
            Assert.AreEqual(0x81cdcd4c, table[0, 0x80]);
            Assert.AreEqual(0x6dbbbbd6, table[0, 0xfe]);
            Assert.AreEqual(0x2c16163a, table[0, 0xff]);

            // 1
            Assert.AreEqual(0xa5c66363, table[1, 0x00]);
            Assert.AreEqual(0x84f87c7c, table[1, 0x01]);
            Assert.AreEqual(0x99ee7777, table[1, 0x02]);
            Assert.AreEqual(0x6dbfd2d2, table[1, 0x7f]);
            Assert.AreEqual(0x4c81cdcd, table[1, 0x80]);
            Assert.AreEqual(0xd66dbbbb, table[1, 0xfe]);
            Assert.AreEqual(0x3a2c1616, table[1, 0xff]);

            // 2
            Assert.AreEqual(0x63a5c663, table[2, 0x00]);
            Assert.AreEqual(0x7c84f87c, table[2, 0x01]);
            Assert.AreEqual(0x7799ee77, table[2, 0x02]);
            Assert.AreEqual(0xd26dbfd2, table[2, 0x7f]);
            Assert.AreEqual(0xcd4c81cd, table[2, 0x80]);
            Assert.AreEqual(0xbbd66dbb, table[2, 0xfe]);
            Assert.AreEqual(0x163a2c16, table[2, 0xff]);

            // 3
            Assert.AreEqual(0x6363a5c6, table[3, 0x00]);
            Assert.AreEqual(0x7c7c84f8, table[3, 0x01]);
            Assert.AreEqual(0x777799ee, table[3, 0x02]);
            Assert.AreEqual(0xd2d26dbf, table[3, 0x7f]);
            Assert.AreEqual(0xcdcd4c81, table[3, 0x80]);
            Assert.AreEqual(0xbbbbd66d, table[3, 0xfe]);
            Assert.AreEqual(0x16163a2c, table[3, 0xff]);
        }

        [Test]
        public void ComputeDecodeTable_returns_correct_result()
        {
            var dt = SjclAes.ComputeDoubleTable();
            var sbox = SjclAes.ComputeSboxTable(dt, SjclAes.ComputeTrippleTable(dt));
            var table = SjclAes.ComputeDecodeTable(dt, sbox);

            // Test data is generated with SJCL sources
            Assert.AreEqual(4, table.GetLength(0));
            Assert.AreEqual(256, table.GetLength(1));

            // 0
            Assert.AreEqual(0x51f4a750, table[0, 0x00]);
            Assert.AreEqual(0x7e416553, table[0, 0x01]);
            Assert.AreEqual(0x1a17a4c3, table[0, 0x02]);
            Assert.AreEqual(0x141ea9c8, table[0, 0x7f]);
            Assert.AreEqual(0x57f11985, table[0, 0x80]);
            Assert.AreEqual(0x486c5c74, table[0, 0xfe]);
            Assert.AreEqual(0xd0b85742, table[0, 0xff]);

            // 1
            Assert.AreEqual(0x5051f4a7, table[1, 0x00]);
            Assert.AreEqual(0x537e4165, table[1, 0x01]);
            Assert.AreEqual(0xc31a17a4, table[1, 0x02]);
            Assert.AreEqual(0xc8141ea9, table[1, 0x7f]);
            Assert.AreEqual(0x8557f119, table[1, 0x80]);
            Assert.AreEqual(0x74486c5c, table[1, 0xfe]);
            Assert.AreEqual(0x42d0b857, table[1, 0xff]);

            // 2
            Assert.AreEqual(0xa75051f4, table[2, 0x00]);
            Assert.AreEqual(0x65537e41, table[2, 0x01]);
            Assert.AreEqual(0xa4c31a17, table[2, 0x02]);
            Assert.AreEqual(0xa9c8141e, table[2, 0x7f]);
            Assert.AreEqual(0x198557f1, table[2, 0x80]);
            Assert.AreEqual(0x5c74486c, table[2, 0xfe]);
            Assert.AreEqual(0x5742d0b8, table[2, 0xff]);

            // 3
            Assert.AreEqual(0xf4a75051, table[3, 0x00]);
            Assert.AreEqual(0x4165537e, table[3, 0x01]);
            Assert.AreEqual(0x17a4c31a, table[3, 0x02]);
            Assert.AreEqual(0x1ea9c814, table[3, 0x7f]);
            Assert.AreEqual(0xf1198557, table[3, 0x80]);
            Assert.AreEqual(0x6c5c7448, table[3, 0xfe]);
            Assert.AreEqual(0xb85742d0, table[3, 0xff]);
        }

        [Test]
        public void ScheduleEncryptionKey_returns_correct_result()
        {
            var dt = SjclAes.ComputeDoubleTable();
            var sbox = SjclAes.ComputeSboxTable(dt, SjclAes.ComputeTrippleTable(dt));

            // TODO: Add more tests for longer/different keys

            // Test data is generated with SJCL sources
            var input = new uint[] {0, 0, 0, 0};
            var expected = new uint[]
            {
                0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x62636363, 0x62636363, 0x62636363, 0x62636363,
                0x9b9898c9, 0xf9fbfbaa, 0x9b9898c9, 0xf9fbfbaa, 0x90973450, 0x696ccffa, 0xf2f45733, 0x0b0fac99,
                0xee06da7b, 0x876a1581, 0x759e42b2, 0x7e91ee2b, 0x7f2e2b88, 0xf8443e09, 0x8dda7cbb, 0xf34b9290,
                0xec614b85, 0x1425758c, 0x99ff0937, 0x6ab49ba7, 0x21751787, 0x3550620b, 0xacaf6b3c, 0xc61bf09b,
                0x0ef90333, 0x3ba96138, 0x97060a04, 0x511dfa9f, 0xb1d4d8e2, 0x8a7db9da, 0x1d7bb3de, 0x4c664941,
                0xb4ef5bcb, 0x3e92e211, 0x23e951cf, 0x6f8f188e
            };

            var key = SjclAes.ScheduleEncryptionKey(input, sbox);
            Assert.AreEqual(expected, key);
        }

        [Test]
        public void ScheduleEncryptionKey_throws_on_incorrect_input_key_length()
        {
            var dt = SjclAes.ComputeDoubleTable();
            var sbox = SjclAes.ComputeSboxTable(dt, SjclAes.ComputeTrippleTable(dt));

            foreach (var i in new[] {0, 1, 2, 3, 5, 7, 9, 10, 1024})
            {
                var e = Assert.Throws<Exception>(() => SjclAes.ScheduleEncryptionKey(new uint[i], sbox));
                Assert.AreEqual(string.Format("Invalid key length ({0})", i), e.Message);
            }
        }

        [Test]
        public void ScheduleDecryptionKey_returns_correct_result()
        {
            var dt = SjclAes.ComputeDoubleTable();
            var sbox = SjclAes.ComputeSboxTable(dt, SjclAes.ComputeTrippleTable(dt));
            var decode = SjclAes.ComputeDecodeTable(dt, sbox);

            // TODO: Add more tests for longer/different keys

            // Test data is generated with SJCL sources
            var input = new uint[] {0, 0, 0, 0};
            var encKey = SjclAes.ScheduleEncryptionKey(input, sbox);
            var expected = new uint[]
            {
                0xb4ef5bcb, 0x6f8f188e, 0x23e951cf, 0x3e92e211, 0x5585820d, 0x258d64ee, 0x0c01b4b2, 0xeb1ceb88,
                0x6ab6f2e9, 0x298cd05c, 0xe71d5f3a, 0xbe996985, 0xefea4a8b, 0xce918f66, 0x598436bf, 0xd42f9b6c,
                0x2ae50b87, 0x9715b9d9, 0x8dabadd3, 0x3bc5d1e7, 0xb5a91ef0, 0x1abe140a, 0xb66e7c34, 0x1120da60,
                0xc27d6492, 0xacd0683e, 0xa74ea654, 0xa489c490, 0x6ead0cac, 0x0b9ece6a, 0x03c762c4, 0x66f4a002,
                0x6533c2c6, 0x0859acae, 0x6533c2c6, 0x0859acae, 0x6d6a6e68, 0x6d6a6e68, 0x6d6a6e68, 0x6d6a6e68,
                0x00000000, 0x00000000, 0x00000000, 0x00000000
            };

            var key = SjclAes.ScheduleDecryptionKey(encKey, sbox, decode);
            Assert.AreEqual(expected, key);
        }
    }
}
