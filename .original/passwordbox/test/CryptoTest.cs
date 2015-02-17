// Copyright (C) 2015 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using NUnit.Framework;

namespace PasswordBox.Test
{
    [TestFixture]
    class CryptoTest
    {
        private struct KekTestCase
        {
            public KekTestCase(int clientIterationCount, int serverIterationCount, string expected)
            {
                ClientIterationCount = clientIterationCount;
                ServerIterationCount = serverIterationCount;
                Expected = expected;
            }

            public readonly int ClientIterationCount;
            public readonly int ServerIterationCount;
            public readonly string Expected;
        }

        // Test data is generated with the PasswordBox JavaScript sources
        private const string Username = "username";
        private const string Password = "password";
        private const string PasswordHash = "bb5eeb368dd3d7ba5ab371c76ba5073e0a91f55697b81790bb34846d3e25f8e4";

        private const string KeyHex = "bc0d63541710541e493d1077e49e92523a4b7c53af1883266ed6c5be2f1b9562";
        private const string CiphertextBase64 = "AATXkbQnk41DJzqyfcFtcTaYE+ptuHwtC9TCmVdsK8/uXA==";
        private static readonly byte[] Ciphertext = CiphertextBase64.Decode64();
        private static readonly byte[] Plaintext = "password".ToBytes();
        private static readonly byte[] Key = KeyHex.DecodeHex();

        // Test data is generated with the PasswordBox JavaScript sources
        private const string KekPassword = "password";
        private const string KekSalt = "salt";
        private static readonly KekTestCase[] KekTestData = new KekTestCase[]
        {
            new KekTestCase(0, 0, "4d30606be4afc1f3f37d52b6c69c068661dd6cf0afdf2f3fc102797f336c5133" +
                                  "3f6cf517ab5adb7b78d9cdd295ba6d8b04ef7ec406e53a5b062cec4a3dffb4ef"),

            new KekTestCase(1,  0, "49f3b020c9311e6e37bd608ef8963b1d369e8d4df28c4d99d1f91d9cacf2240b" +
                                   "45e20d746dcb6daa53fb0217755982bddc76483edaed608842b6578f798a17ac"),

            new KekTestCase(0,  1, "4d30606be4afc1f3f37d52b6c69c068661dd6cf0afdf2f3fc102797f336c5133" +
                                   "3f6cf517ab5adb7b78d9cdd295ba6d8b04ef7ec406e53a5b062cec4a3dffb4ef"),

            new KekTestCase(1,  1, "49f3b020c9311e6e37bd608ef8963b1d369e8d4df28c4d99d1f91d9cacf2240b" +
                                   "45e20d746dcb6daa53fb0217755982bddc76483edaed608842b6578f798a17ac"),

            new KekTestCase(10,  0, "76ea6ae400308d72ceb56f223a44a31a552bdf03598f5fd39387467b618ce245" +
                                    "ecb1877528ca94f3e9e720dfdbd9f85af68f13346c3f9dfaed7417a4ea2dbeba"),

            new KekTestCase(0, 10, "57ffc1876b96dab3f8d3daed9455547f3f7c692de3684d34ea27f7b36143e2d2" +
                                   "03480a01370ba30ea03f6b1cb8fe89db63f1adec34913a7def56e194ed1b0a6a"),

            new KekTestCase(13, 42, "3f64e210cb30e46672e74a6c63e73201183a4fec4279480df4163882dd4ac1b2" +
                                    "6fd1333ba819dfb4f97381b93c65ba6b768034019113470db0356206f1bb9708"),
        };

        [Test]
        public void Decrypt_strings_returns_correct_result()
        {
            var decrypted = Crypto.Decrypt(KeyHex, CiphertextBase64);
            Assert.AreEqual(Plaintext, decrypted);
        }

        [Test]
        public void Decrypt_binary_returns_correct_result()
        {
            var decrypted = Crypto.Decrypt(Key, Ciphertext);
            Assert.AreEqual(Plaintext, decrypted);
        }

        [Test]
        public void Decrypt_returns_empty_on_empty_base64_input()
        {
            var decrypted = Crypto.Decrypt(KeyHex, "");
            Assert.IsEmpty(decrypted);
        }

        [Test]
        public void Decrypt_returns_empty_on_empty_binary_input()
        {
            var decrypted = Crypto.Decrypt(Key, "".ToBytes());
            Assert.IsEmpty(decrypted);
        }

        [Test]
        public void Decrypt_uses_first_256_bits_of_key_only()
        {
            var decrypted = Crypto.Decrypt(KeyHex + "0102030405060708", CiphertextBase64);
            Assert.AreEqual(Plaintext, decrypted);
        }

        [Test]
        [ExpectedException(typeof(CryptoException),
                           ExpectedMessage = "Encryption key should be at least 16 bytes long")]
        public void Decrypt_throws_on_too_short_key()
        {
            Crypto.Decrypt(new byte[15], Ciphertext);
        }

        [Test]
        [ExpectedException(typeof(CryptoException),
                           ExpectedMessage = "Ciphertext is too short (version byte is missing)")]
        public void Decrypt_throws_on_missing_format_byte()
        {
            Crypto.Decrypt(Key, "00".DecodeHex());
        }

        [Test]
        [ExpectedException(typeof(CryptoException),
                           ExpectedMessage = "Ciphertext is too short (IV is missing)")]
        public void Decrypt_throws_on_missing_iv()
        {
            Crypto.Decrypt(Key, "0004".DecodeHex());
        }

        [Test]
        [ExpectedException(typeof(CryptoException),
                           ExpectedMessage = "Unsupported cipher format version (5)")]
        public void Decrypt_throws_on_unsupported_version()
        {
            Crypto.Decrypt(Key, "0005".DecodeHex());
        }

        [Test]
        public void ComputePasswordHash_returns_correct_result()
        {
            // Test data is generated with the PasswordBox JavaScript sources
            var hash = Crypto.ComputePasswordHash(Username, Password);
            Assert.AreEqual(PasswordHash, hash);
        }

        [Test]
        public void ComputeKek_returns_correct_result()
        {
            foreach (var i in KekTestData)
            {
                var kek = Crypto.ComputeKek(
                    KekPassword,
                    KekSalt,
                    new Fetcher.DerivationRules(i.ClientIterationCount, i.ServerIterationCount));

                Assert.AreEqual(i.Expected, kek);
            }
        }

        [Test]
        public void HexSha1_returns_correct_result()
        {
            // Test data is from http://www.nsrl.nist.gov/testdata/
            var hash = Crypto.Sha1Hex("abc");
            Assert.AreEqual("a9993e364706816aba3e25717850c26c9cd0d89d", hash);
        }

        [Test]
        public void Pbkdf2Sha1_returns_correct_result()
        {
            // PBKDF2-SHA1 implemetation is tested elsewhere. This test
            // here is just to make sure the calls are chained correctly.

            // Test data from https://www.ietf.org/rfc/rfc6070.txt
            Assert.AreEqual("ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957",
                            Crypto.Pbkdf2Sha1("password", "salt", 2, 160));
        }

        [Test]
        public void Pbkdf2Sha1_returns_input_on_zero_iteration_count()
        {
            Assert.AreEqual("password", Crypto.Pbkdf2Sha1("password", "salt", 0, 160));
        }

        [Test]
        public void Pbkdf2Sha256_returns_correct_result()
        {
            // PBKDF2-SHA256 implemetation is tested elsewhere. This test
            // here is just to make sure the calls are chained correctly.

            // Test data from http://stackoverflow.com/a/5136918/362938
            Assert.AreEqual("ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43",
                            Crypto.Pbkdf2Sha256("password", "salt", 2, 256));
        }

        [Test]
        public void Pbkdf2Sha256_returns_input_on_zero_iteration_count()
        {
            Assert.AreEqual("password", Crypto.Pbkdf2Sha256("password", "salt", 0, 256));
        }
    }
}
