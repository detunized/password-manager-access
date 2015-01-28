// Copyright (C) 2015 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using NUnit.Framework;

namespace PasswordBox.Test
{
    [TestFixture]
    class SjclAesTest
    {
        struct AesTestCase
        {
            public AesTestCase(string key, string plaintext, string ciphertext)
            {
                Key = key.DecodeHex();
                Plaintext = new SjclQuad(plaintext.DecodeHex());
                Ciphertext = new SjclQuad(ciphertext.DecodeHex());
            }

            public readonly byte[] Key;
            public readonly SjclQuad Plaintext;
            public readonly SjclQuad Ciphertext;
        };

        struct KeyTestCase
        {
            public KeyTestCase(uint[] key, uint[] encryptionKey, uint[] decryptionKey)
            {
                Key = key;
                EncryptionKey = encryptionKey;
                DecryptionKey = decryptionKey;
            }

            public readonly uint[] Key;
            public readonly uint[] EncryptionKey;
            public readonly uint[] DecryptionKey;
        };

        private static readonly AesTestCase[] AesTestCases =
        {
            // TODO: Add more tests!
            new AesTestCase(
                       key: "00000000000000000000000000000000",
                 plaintext: "00000000000000000000000000000000",
                ciphertext: "66e94bd4ef8a2c3b884cfa59ca342b2e"),

            new AesTestCase(
                       key: "10a58869d74be5a374cf867cfb473859",
                 plaintext: "00000000000000000000000000000000",
                ciphertext: "6d251e6944b051e04eaa6fb4dbf78465"),
        };

        // Test data is generated with SJCL sources
        private static readonly KeyTestCase[] KeyTestCases =
        {
            new KeyTestCase(
                          key: new uint[ 4] {0x00000000, 0x00000000, 0x00000000, 0x00000000},
                encryptionKey: new uint[44] {0x00000000, 0x00000000, 0x00000000, 0x00000000,
                                             0x62636363, 0x62636363, 0x62636363, 0x62636363,
                                             0x9b9898c9, 0xf9fbfbaa, 0x9b9898c9, 0xf9fbfbaa,
                                             0x90973450, 0x696ccffa, 0xf2f45733, 0x0b0fac99,
                                             0xee06da7b, 0x876a1581, 0x759e42b2, 0x7e91ee2b,
                                             0x7f2e2b88, 0xf8443e09, 0x8dda7cbb, 0xf34b9290,
                                             0xec614b85, 0x1425758c, 0x99ff0937, 0x6ab49ba7,
                                             0x21751787, 0x3550620b, 0xacaf6b3c, 0xc61bf09b,
                                             0x0ef90333, 0x3ba96138, 0x97060a04, 0x511dfa9f,
                                             0xb1d4d8e2, 0x8a7db9da, 0x1d7bb3de, 0x4c664941,
                                             0xb4ef5bcb, 0x3e92e211, 0x23e951cf, 0x6f8f188e},
                decryptionKey: new uint[44] {0xb4ef5bcb, 0x6f8f188e, 0x23e951cf, 0x3e92e211,
                                             0x5585820d, 0x258d64ee, 0x0c01b4b2, 0xeb1ceb88,
                                             0x6ab6f2e9, 0x298cd05c, 0xe71d5f3a, 0xbe996985,
                                             0xefea4a8b, 0xce918f66, 0x598436bf, 0xd42f9b6c,
                                             0x2ae50b87, 0x9715b9d9, 0x8dabadd3, 0x3bc5d1e7,
                                             0xb5a91ef0, 0x1abe140a, 0xb66e7c34, 0x1120da60,
                                             0xc27d6492, 0xacd0683e, 0xa74ea654, 0xa489c490,
                                             0x6ead0cac, 0x0b9ece6a, 0x03c762c4, 0x66f4a002,
                                             0x6533c2c6, 0x0859acae, 0x6533c2c6, 0x0859acae,
                                             0x6d6a6e68, 0x6d6a6e68, 0x6d6a6e68, 0x6d6a6e68,
                                             0x00000000, 0x00000000, 0x00000000, 0x00000000}),
            new KeyTestCase(
                          key: new uint[ 6] {0x00000000, 0x00000000, 0x00000000, 0x00000000,
                                             0x00000000, 0x00000000                        },
                encryptionKey: new uint[52] {0x00000000, 0x00000000, 0x00000000, 0x00000000,
                                             0x00000000, 0x00000000, 0x62636363, 0x62636363,
                                             0x62636363, 0x62636363, 0x62636363, 0x62636363,
                                             0x9b9898c9, 0xf9fbfbaa, 0x9b9898c9, 0xf9fbfbaa,
                                             0x9b9898c9, 0xf9fbfbaa, 0x90973450, 0x696ccffa,
                                             0xf2f45733, 0x0b0fac99, 0x90973450, 0x696ccffa,
                                             0xc81d19a9, 0xa171d653, 0x53858160, 0x588a2df9,
                                             0xc81d19a9, 0xa171d653, 0x7bebf49b, 0xda9a22c8,
                                             0x891fa3a8, 0xd1958e51, 0x198897f8, 0xb8f941ab,
                                             0xc26896f7, 0x18f2b43f, 0x91ed1797, 0x407899c6,
                                             0x59f00e3e, 0xe1094f95, 0x83ecbc0f, 0x9b1e0830,
                                             0x0af31fa7, 0x4a8b8661, 0x137b885f, 0xf272c7ca,
                                             0x432ac886, 0xd834c0b6, 0xd2c7df11, 0x984c5970},
                decryptionKey: new uint[52] {0x432ac886, 0x984c5970, 0xd2c7df11, 0xd834c0b6,
                                             0xc8045fd2, 0xb45c80e5, 0xa9265767, 0xc31943bf,
                                             0x6a3f14d8, 0xd2a820e7, 0xc78b5bcb, 0x1d7ad782,
                                             0x0f0cd61e, 0x0b1d1c6d, 0x1aac7f35, 0x15237b2c,
                                             0x0f8f0419, 0x7745c35a, 0x612208b5, 0x11b16358,
                                             0x70936bed, 0x1a2fad32, 0x0c4866dd, 0x1667cbef,
                                             0x70936bed, 0x1e3e6741, 0x15a0a92b, 0x1667cbef,
                                             0x03c762c4, 0x66f4a002, 0x6ead0cac, 0x0b9ece6a,
                                             0x6533c2c6, 0x66f4a002, 0x6ead0cac, 0x0859acae,
                                             0x6533c2c6, 0x0859acae, 0x6533c2c6, 0x0859acae,
                                             0x6d6a6e68, 0x6d6a6e68, 0x6d6a6e68, 0x6d6a6e68,
                                             0x00000000, 0x6d6a6e68, 0x6d6a6e68, 0x00000000,
                                             0x00000000, 0x00000000, 0x00000000, 0x00000000}),
            new KeyTestCase(
                          key: new uint[ 8] {0x00000000, 0x00000000, 0x00000000, 0x00000000,
                                             0x00000000, 0x00000000, 0x00000000, 0x00000000},
                encryptionKey: new uint[60] {0x00000000, 0x00000000, 0x00000000, 0x00000000,
                                             0x00000000, 0x00000000, 0x00000000, 0x00000000,
                                             0x62636363, 0x62636363, 0x62636363, 0x62636363,
                                             0xaafbfbfb, 0xaafbfbfb, 0xaafbfbfb, 0xaafbfbfb,
                                             0x6f6c6ccf, 0x0d0f0fac, 0x6f6c6ccf, 0x0d0f0fac,
                                             0x7d8d8d6a, 0xd7767691, 0x7d8d8d6a, 0xd7767691,
                                             0x5354edc1, 0x5e5be26d, 0x31378ea2, 0x3c38810e,
                                             0x968a81c1, 0x41fcf750, 0x3c717a3a, 0xeb070cab,
                                             0x9eaa8f28, 0xc0f16d45, 0xf1c6e3e7, 0xcdfe62e9,
                                             0x2b312bdf, 0x6acddc8f, 0x56bca6b5, 0xbdbbaa1e,
                                             0x6406fd52, 0xa4f79017, 0x553173f0, 0x98cf1119,
                                             0x6dbba90b, 0x07767584, 0x51cad331, 0xec71792f,
                                             0xe7b0e89c, 0x4347788b, 0x16760b7b, 0x8eb91a62,
                                             0x74ed0ba1, 0x739b7e25, 0x2251ad14, 0xce20d43b,
                                             0x10f80a17, 0x53bf729c, 0x45c979e7, 0xcb706385},
                decryptionKey: new uint[60] {0x10f80a17, 0xcb706385, 0x45c979e7, 0x53bf729c,
                                             0x0aa1138b, 0x68b670af, 0x0e7d0eb7, 0xd0d8a01b,
                                             0x55901cfa, 0x87a48de1, 0x32280f05, 0xa92a6713,
                                             0x1e9032c8, 0x66cb7e18, 0xdea5aeac, 0xda79b390,
                                             0x0d5f158a, 0xb58c82e4, 0x9b026816, 0xfcba7be9,
                                             0xc04f0766, 0xb86ed0b4, 0x04dc1d3c, 0xc4e98158,
                                             0xd5b9f906, 0x2e8eeaf2, 0x67b813ff, 0xf1e56e63,
                                             0x7821d7d2, 0xbcb2cd88, 0xc0359c64, 0x04a6863e,
                                             0xfb3713f4, 0x4936f90d, 0x965d7d9c, 0x245c9765,
                                             0xc4931a5a, 0x7c8751ec, 0xc4931a5a, 0x7c8751ec,
                                             0xb201eaf9, 0xdf6b8491, 0xb201eaf9, 0xdf6b8491,
                                             0xb8144bb6, 0xb8144bb6, 0xb8144bb6, 0xb8144bb6,
                                             0x6d6a6e68, 0x6d6a6e68, 0x6d6a6e68, 0x6d6a6e68,
                                             0x00000000, 0x00000000, 0x00000000, 0x00000000,
                                             0x00000000, 0x00000000, 0x00000000, 0x00000000}),
        };

        [Test]
        public void Encrypt_returns_correct_value()
        {
            foreach (var i in AesTestCases)
            {
                var ciphertext = new SjclAes(i.Key).Encrypt(i.Plaintext);
                Assert.AreEqual(i.Ciphertext, ciphertext);
            }
        }

        [Test]
        public void Decrypt_returns_correct_value()
        {
            foreach (var i in AesTestCases)
            {
                var plaintext = new SjclAes(i.Key).Decrypt(i.Ciphertext);
                Assert.AreEqual(i.Plaintext, plaintext);
            }
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

            foreach (var i in KeyTestCases)
            {
                var key = SjclAes.ScheduleEncryptionKey(i.Key, sbox);
                Assert.AreEqual(i.EncryptionKey, key);
            }
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

            foreach (var i in KeyTestCases)
            {
                var encKey = SjclAes.ScheduleEncryptionKey(i.Key, sbox);
                var key = SjclAes.ScheduleDecryptionKey(encKey, sbox, decode);
                Assert.AreEqual(i.DecryptionKey, key);
            }
        }

        [Test]
        public void ToQuads_converts_words_to_quads()
        {
            Assert.AreEqual(
                new SjclQuad[0],
                SjclAes.ToQuads(new uint[0]));

            Assert.AreEqual(
                new SjclQuad[] {new SjclQuad(1, 2, 3, 4)},
                SjclAes.ToQuads(new uint[] {1, 2, 3, 4}));

            Assert.AreEqual(
                new SjclQuad[] {new SjclQuad(1, 2, 3, 4), new SjclQuad(5, 6, 7, 8)},
                SjclAes.ToQuads(new uint[] {1, 2, 3, 4, 5, 6, 7, 8}));

            Assert.AreEqual(
                new SjclQuad[] {new SjclQuad(1, 2, 3, 4), new SjclQuad(5, 6, 7, 8), new SjclQuad(9, 10, 11, 12)},
                SjclAes.ToQuads(new uint[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}));
        }

        [Test]
        [ExpectedException(
            typeof(ArgumentException),
            ExpectedMessage = "Length must be a multiple of 4\r\nParameter name: abcds")]
        public void ToQuads_throws_on_length_that_is_not_multiple_of_4()
        {
            SjclAes.ToQuads(new uint[] {1, 2, 3});
        }
    }
}
