// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using PasswordManagerAccess.TrueKey;
using Xunit;

namespace PasswordManagerAccess.Test.TrueKey
{
    public class SjclAesTest
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
            public KeyTestCase(string key, uint[] encryptionKey, uint[] decryptionKey)
            {
                Key = key.DecodeHex();
                EncryptionKey = encryptionKey;
                DecryptionKey = decryptionKey;
            }

            public readonly byte[] Key;
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
                          key: "000102030405060708090a0b0c0d0e0f",
                encryptionKey: new uint[44] {0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f,
                                             0xd6aa74fd, 0xd2af72fa, 0xdaa678f1, 0xd6ab76fe,
                                             0xb692cf0b, 0x643dbdf1, 0xbe9bc500, 0x6830b3fe,
                                             0xb6ff744e, 0xd2c2c9bf, 0x6c590cbf, 0x0469bf41,
                                             0x47f7f7bc, 0x95353e03, 0xf96c32bc, 0xfd058dfd,
                                             0x3caaa3e8, 0xa99f9deb, 0x50f3af57, 0xadf622aa,
                                             0x5e390f7d, 0xf7a69296, 0xa7553dc1, 0x0aa31f6b,
                                             0x14f9701a, 0xe35fe28c, 0x440adf4d, 0x4ea9c026,
                                             0x47438735, 0xa41c65b9, 0xe016baf4, 0xaebf7ad2,
                                             0x549932d1, 0xf0855768, 0x1093ed9c, 0xbe2c974e,
                                             0x13111d7f, 0xe3944a17, 0xf307a78b, 0x4d2b30c5},
                decryptionKey: new uint[44] {0x13111d7f, 0x4d2b30c5, 0xf307a78b, 0xe3944a17,
                                             0x13aa29be, 0x00f7bf03, 0xf770f580, 0x9c8faff6,
                                             0x1362a463, 0xf7874a83, 0x6bff5a76, 0x8f258648,
                                             0x8d82fc74, 0x9c7810f5, 0xe4dadc3e, 0x9c47222b,
                                             0x72e3098d, 0x78a2cccb, 0x789dfe15, 0x11c5de5f,
                                             0x2ec41027, 0x003f32de, 0x6958204a, 0x6326d7d2,
                                             0xa8a2f504, 0x69671294, 0x0a7ef798, 0x4de2c7f5,
                                             0xc7c6e391, 0x6319e50c, 0x479c306d, 0xe54032f1,
                                             0xa0db0299, 0x2485d561, 0xa2dc029c, 0x2286d160,
                                             0x8c56dff0, 0x8659d7fd, 0x805ad3fc, 0x825dd3f9,
                                             0x00010203, 0x0c0d0e0f, 0x08090a0b, 0x04050607}),
            new KeyTestCase(
                          key: "101112131415161718191a1b1c1d1e1f2021222324252627",
                encryptionKey: new uint[52] {0x10111213, 0x14151617, 0x18191a1b, 0x1c1d1e1f,
                                             0x20212223, 0x24252627, 0x2ee6de25, 0x3af3c832,
                                             0x22ead229, 0x3ef7cc36, 0x1ed6ee15, 0x3af3c832,
                                             0x210efda5, 0x1bfd3597, 0x3917e7be, 0x07e02b88,
                                             0x1936c59d, 0x23c50daf, 0x83d98483, 0x9824b114,
                                             0xa13356aa, 0xa6d37d22, 0xbfe5b8bf, 0x9c20b510,
                                             0x3c0c4e5d, 0xa428ff49, 0x051ba9e3, 0xa3c8d4c1,
                                             0x1c2d6c7e, 0x800dd96e, 0xfb39d190, 0x5f112ed9,
                                             0x5a0a873a, 0xf9c253fb, 0xe5ef3f85, 0x65e2e6eb,
                                             0x43b738dd, 0x1ca61604, 0x46ac913e, 0xbf6ec2c5,
                                             0x5a81fd40, 0x3f631bab, 0xf8185aa8, 0xe4be4cac,
                                             0xa212dd92, 0x1d7c1f57, 0x47fde217, 0x789ef9bc,
                                             0x73813f14, 0x973f73b8, 0x352dae2a, 0x2851b17d},
                decryptionKey: new uint[52] {0x73813f14, 0x2851b17d, 0x352dae2a, 0x973f73b8,
                                             0x78e7e282, 0x51148d6b, 0x8b47b033, 0xad6cfd15,
                                             0x262b4d26, 0xdb141c69, 0x1fe8997c, 0xda533d58,
                                             0xde9887d0, 0xd58b1f97, 0xa3f3feeb, 0xc4fc8515,
                                             0x670f7bfe, 0xfc78707e, 0xf3a052b1, 0x7678e17c,
                                             0x85d8b3cd, 0x1a6402c5, 0x3b970c23, 0x0fd822cf,
                                             0xaff79be0, 0x11779a82, 0x7d6b793b, 0x21f30ee6,
                                             0x5c9877dd, 0x8a009102, 0x94af294f, 0x6c1ce3b9,
                                             0xf8b3caf6, 0x8e049506, 0xa8931573, 0x1eafb84d,
                                             0xc08bf2ce, 0x30849464, 0xd29ce2db, 0x26978075,
                                             0xf40b62ae, 0xe61c72bb, 0xc8375e92, 0xe21876bf,
                                             0x2a2f282d, 0xe61c72bb, 0xf8076ea2, 0x2e2b2c29,
                                             0x10111213, 0x1c1d1e1f, 0x18191a1b, 0x14151617}),
            new KeyTestCase(
                          key: "303132333435363738393a3b1c1d1e1f404142434445464748494a4b4c4d4e4f",
                encryptionKey: new uint[60] {0x30313233, 0x34353637, 0x38393a3b, 0x1c1d1e1f,
                                             0x40414243, 0x44454647, 0x48494a4b, 0x4c4d4e4f,
                                             0xd21eb61a, 0xe62b802d, 0xde12ba16, 0xc20fa409,
                                             0x65370b42, 0x21724d05, 0x693b074e, 0x25764901,
                                             0xe825ca25, 0x0e0e4a08, 0xd01cf01e, 0x12135417,
                                             0xac4a2bb2, 0x8d3866b7, 0xe40361f9, 0xc17528f8,
                                             0x71118b5d, 0x7f1fc155, 0xaf03314b, 0xbd10655c,
                                             0xd68066f8, 0x5bb8004f, 0xbfbb61b6, 0x7ece494e,
                                             0xf22aa4ae, 0x8d3565fb, 0x223654b0, 0x9f2631ec,
                                             0x0d77a136, 0x56cfa179, 0xe974c0cf, 0x97ba8981,
                                             0x168da826, 0x9bb8cddd, 0xb98e996d, 0x26a8a881,
                                             0xfab5633a, 0xac7ac243, 0x450e028c, 0xd2b48b0d,
                                             0xbbb07f93, 0x2008b24e, 0x99862b23, 0xbf2e83a2,
                                             0xf2848f00, 0x5efe4d43, 0x1bf04fcf, 0xc944c4c2,
                                             0xe0ac5a4e, 0xc0a4e800, 0x5922c323, 0xe60c4081},
                decryptionKey: new uint[60] {0xe0ac5a4e, 0xe60c4081, 0x5922c323, 0xc0a4e800,
                                             0x81c415a9, 0x43ce4345, 0x8377019e, 0xe0e8b412,
                                             0x0e271fd1, 0x312e76d9, 0xf6ca6a41, 0x204a01bf,
                                             0x90ae250d, 0xc0b942db, 0x639fb58c, 0x612ca1bb,
                                             0x48e0dc61, 0xc7e41c98, 0xd6806bfe, 0x2e6d1e6e,
                                             0xbb1bd69b, 0xa326f757, 0x02b31437, 0xf18284b6,
                                             0x0213eb28, 0x11647766, 0xf8ed7590, 0x668dc20f,
                                             0x5e7e658d, 0xa195e360, 0xf3319081, 0x4a99522d,
                                             0x0564885f, 0xe98902f6, 0x9e60b79f, 0x649e2927,
                                             0xfbef82e9, 0x52a473e1, 0xb9a8c2ac, 0x14e737a0,
                                             0xc8c9ae8d, 0x77e9b569, 0xfafe9eb8, 0x61faa178,
                                             0xa143f900, 0xeb0cb14d, 0xad4ff50c, 0xef08b549,
                                             0x970833cc, 0x8d172bd1, 0x9b043fc0, 0xa9330ff5,
                                             0x4a4f484d, 0x46434441, 0x42474045, 0x4e4b4c49,
                                             0x30313233, 0x1c1d1e1f, 0x38393a3b, 0x34353637}),
        };

        [Fact]
        public void Encrypt_returns_correct_value()
        {
            foreach (var i in AesTestCases)
            {
                var ciphertext = new SjclAes(i.Key).Encrypt(i.Plaintext);
                Assert.Equal(i.Ciphertext, ciphertext);
            }
        }

        [Fact]
        public void Decrypt_returns_correct_value()
        {
            foreach (var i in AesTestCases)
            {
                var plaintext = new SjclAes(i.Key).Decrypt(i.Ciphertext);
                Assert.Equal(i.Plaintext, plaintext);
            }
        }

        [Fact]
        public void ComputeDoubleTable_returns_correct_result()
        {
            var table = SjclAes.ComputeDoubleTable();

            // Test data is generated with SJCL sources
            Assert.Equal(256, table.Length);

            Assert.Equal(0x00, table[0x00]);
            Assert.Equal(0x02, table[0x01]);
            Assert.Equal(0x04, table[0x02]);
            Assert.Equal(0xfe, table[0x7f]);
            Assert.Equal(0x1b, table[0x80]);
            Assert.Equal(0xe7, table[0xfe]);
            Assert.Equal(0xe5, table[0xff]);
        }

        [Fact]
        public void ComputeTrippleTable_returns_correct_result()
        {
            var table = SjclAes.ComputeTrippleTable(SjclAes.ComputeDoubleTable());

            // Test data is generated with SJCL sources
            Assert.Equal(256, table.Length);

            Assert.Equal(0x00, table[0x00]);
            Assert.Equal(0xf6, table[0x01]);
            Assert.Equal(0xf7, table[0x02]);
            Assert.Equal(0xdc, table[0x7f]);
            Assert.Equal(0x89, table[0x80]);
            Assert.Equal(0xa3, table[0xfe]);
            Assert.Equal(0x55, table[0xff]);
        }

        [Fact]
        public void ComputeSboxTable_returns_correct_result()
        {
            var dt = SjclAes.ComputeDoubleTable();
            var tt = SjclAes.ComputeTrippleTable(dt);
            var table = SjclAes.ComputeSboxTable(dt, tt);

            // Test data is generated with SJCL sources
            Assert.Equal(256, table.Length);

            Assert.Equal(0x63, table[0x00]);
            Assert.Equal(0x7c, table[0x01]);
            Assert.Equal(0x77, table[0x02]);
            Assert.Equal(0xd2, table[0x7f]);
            Assert.Equal(0xcd, table[0x80]);
            Assert.Equal(0xbb, table[0xfe]);
            Assert.Equal(0x16, table[0xff]);

            // Every value should be exactly once
            Array.Sort(table);
            for (var i = 0; i < 256; ++i)
                Assert.Equal(i, table[i]);
        }

        [Fact]
        public void ComputeInverseSboxTable_returns_correct_result()
        {
            var dt = SjclAes.ComputeDoubleTable();
            var tt = SjclAes.ComputeTrippleTable(dt);
            var sbox = SjclAes.ComputeSboxTable(dt, tt);
            var table = SjclAes.ComputeInverseSboxTable(sbox);

            // Test data is generated with SJCL sources
            Assert.Equal(256, table.Length);

            Assert.Equal(0x52, table[0x00]);
            Assert.Equal(0x09, table[0x01]);
            Assert.Equal(0x6a, table[0x02]);
            Assert.Equal(0x6b, table[0x7f]);
            Assert.Equal(0x3a, table[0x80]);
            Assert.Equal(0x0c, table[0xfe]);
            Assert.Equal(0x7d, table[0xff]);

            // Every value should be exactly once
            Array.Sort(table);
            for (var i = 0; i < 256; ++i)
                Assert.Equal(i, table[i]);
        }

        [Fact]
        public void ComputeEncodeTable_returns_correct_result()
        {
            var dt = SjclAes.ComputeDoubleTable();
            var sbox = SjclAes.ComputeSboxTable(dt, SjclAes.ComputeTrippleTable(dt));
            var table = SjclAes.ComputeEncodeTable(dt, sbox);

            // Test data is generated with SJCL sources
            Assert.Equal(4, table.GetLength(0));
            Assert.Equal(256, table.GetLength(1));

            // 0
            Assert.Equal(0xc66363a5U, table[0, 0x00]);
            Assert.Equal(0xf87c7c84U, table[0, 0x01]);
            Assert.Equal(0xee777799U, table[0, 0x02]);
            Assert.Equal(0xbfd2d26dU, table[0, 0x7f]);
            Assert.Equal(0x81cdcd4cU, table[0, 0x80]);
            Assert.Equal(0x6dbbbbd6U, table[0, 0xfe]);
            Assert.Equal(0x2c16163aU, table[0, 0xff]);

            // 1
            Assert.Equal(0xa5c66363U, table[1, 0x00]);
            Assert.Equal(0x84f87c7cU, table[1, 0x01]);
            Assert.Equal(0x99ee7777U, table[1, 0x02]);
            Assert.Equal(0x6dbfd2d2U, table[1, 0x7f]);
            Assert.Equal(0x4c81cdcdU, table[1, 0x80]);
            Assert.Equal(0xd66dbbbbU, table[1, 0xfe]);
            Assert.Equal(0x3a2c1616U, table[1, 0xff]);

            // 2
            Assert.Equal(0x63a5c663U, table[2, 0x00]);
            Assert.Equal(0x7c84f87cU, table[2, 0x01]);
            Assert.Equal(0x7799ee77U, table[2, 0x02]);
            Assert.Equal(0xd26dbfd2U, table[2, 0x7f]);
            Assert.Equal(0xcd4c81cdU, table[2, 0x80]);
            Assert.Equal(0xbbd66dbbU, table[2, 0xfe]);
            Assert.Equal(0x163a2c16U, table[2, 0xff]);

            // 3
            Assert.Equal(0x6363a5c6U, table[3, 0x00]);
            Assert.Equal(0x7c7c84f8U, table[3, 0x01]);
            Assert.Equal(0x777799eeU, table[3, 0x02]);
            Assert.Equal(0xd2d26dbfU, table[3, 0x7f]);
            Assert.Equal(0xcdcd4c81U, table[3, 0x80]);
            Assert.Equal(0xbbbbd66dU, table[3, 0xfe]);
            Assert.Equal(0x16163a2cU, table[3, 0xff]);
        }

        [Fact]
        public void ComputeDecodeTable_returns_correct_result()
        {
            var dt = SjclAes.ComputeDoubleTable();
            var sbox = SjclAes.ComputeSboxTable(dt, SjclAes.ComputeTrippleTable(dt));
            var table = SjclAes.ComputeDecodeTable(dt, sbox);

            // Test data is generated with SJCL sources
            Assert.Equal(4, table.GetLength(0));
            Assert.Equal(256, table.GetLength(1));

            // 0
            Assert.Equal(0x51f4a750U, table[0, 0x00]);
            Assert.Equal(0x7e416553U, table[0, 0x01]);
            Assert.Equal(0x1a17a4c3U, table[0, 0x02]);
            Assert.Equal(0x141ea9c8U, table[0, 0x7f]);
            Assert.Equal(0x57f11985U, table[0, 0x80]);
            Assert.Equal(0x486c5c74U, table[0, 0xfe]);
            Assert.Equal(0xd0b85742U, table[0, 0xff]);

            // 1
            Assert.Equal(0x5051f4a7U, table[1, 0x00]);
            Assert.Equal(0x537e4165U, table[1, 0x01]);
            Assert.Equal(0xc31a17a4U, table[1, 0x02]);
            Assert.Equal(0xc8141ea9U, table[1, 0x7f]);
            Assert.Equal(0x8557f119U, table[1, 0x80]);
            Assert.Equal(0x74486c5cU, table[1, 0xfe]);
            Assert.Equal(0x42d0b857U, table[1, 0xff]);

            // 2
            Assert.Equal(0xa75051f4U, table[2, 0x00]);
            Assert.Equal(0x65537e41U, table[2, 0x01]);
            Assert.Equal(0xa4c31a17U, table[2, 0x02]);
            Assert.Equal(0xa9c8141eU, table[2, 0x7f]);
            Assert.Equal(0x198557f1U, table[2, 0x80]);
            Assert.Equal(0x5c74486cU, table[2, 0xfe]);
            Assert.Equal(0x5742d0b8U, table[2, 0xff]);

            // 3
            Assert.Equal(0xf4a75051U, table[3, 0x00]);
            Assert.Equal(0x4165537eU, table[3, 0x01]);
            Assert.Equal(0x17a4c31aU, table[3, 0x02]);
            Assert.Equal(0x1ea9c814U, table[3, 0x7f]);
            Assert.Equal(0xf1198557U, table[3, 0x80]);
            Assert.Equal(0x6c5c7448U, table[3, 0xfe]);
            Assert.Equal(0xb85742d0U, table[3, 0xff]);
        }

        [Fact]
        public void ScheduleEncryptionKey_returns_correct_result()
        {
            var dt = SjclAes.ComputeDoubleTable();
            var sbox = SjclAes.ComputeSboxTable(dt, SjclAes.ComputeTrippleTable(dt));

            foreach (var i in KeyTestCases)
            {
                var key = SjclAes.ScheduleEncryptionKey(i.Key, sbox);
                Assert.Equal(i.EncryptionKey, key);
            }
        }

        [Fact]
        public void ScheduleEncryptionKey_throws_on_incorrect_input_key_length()
        {
            var dt = SjclAes.ComputeDoubleTable();
            var sbox = SjclAes.ComputeSboxTable(dt, SjclAes.ComputeTrippleTable(dt));

            foreach (var i in new[] {0, 1, 2, 3, 4, 15, 17, 23, 25, 31, 33, 1024})
            {
                var e = Assert.Throws<ArgumentException>(() => SjclAes.ScheduleEncryptionKey(new byte[i], sbox));
                Assert.StartsWith("Invalid key length", e.Message);
            }
        }

        [Fact]
        public void ScheduleDecryptionKey_returns_correct_result()
        {
            var dt = SjclAes.ComputeDoubleTable();
            var sbox = SjclAes.ComputeSboxTable(dt, SjclAes.ComputeTrippleTable(dt));
            var decode = SjclAes.ComputeDecodeTable(dt, sbox);

            foreach (var i in KeyTestCases)
            {
                var encKey = SjclAes.ScheduleEncryptionKey(i.Key, sbox);
                var key = SjclAes.ScheduleDecryptionKey(encKey, sbox, decode);
                Assert.Equal(i.DecryptionKey, key);
            }
        }

        [Fact]
        public void ToQuads_converts_words_to_quads()
        {
            Assert.Equal(new SjclQuad[0], SjclAes.ToQuads(new uint[0]));

            Assert.Equal(new SjclQuad[]{new SjclQuad(1, 2, 3, 4)}, SjclAes.ToQuads(new uint[]{1, 2, 3, 4}));

            Assert.Equal(new SjclQuad[]{new SjclQuad(1, 2, 3, 4), new SjclQuad(5, 6, 7, 8)}, SjclAes.ToQuads(new uint[]{1, 2, 3, 4, 5, 6, 7, 8}));

            Assert.Equal(new SjclQuad[]{new SjclQuad(1, 2, 3, 4), new SjclQuad(5, 6, 7, 8), new SjclQuad(9, 10, 11, 12)}, SjclAes.ToQuads(new uint[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}));
        }

        [Fact]
        public void ToQuads_throws_on_length_that_is_not_multiple_of_4()
        {
            var e = Assert.Throws<ArgumentException>(() => SjclAes.ToQuads(new uint[] {1, 2, 3}));
            Assert.StartsWith("Length must be a multiple of 4", e.Message);
        }
    }
}
