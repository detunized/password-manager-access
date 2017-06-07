// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using NUnit.Framework;

namespace OnePassword.Test
{
    [TestFixture]
    public class CryptoTest
    {
        [Test]
        public void RandomBytes_returns_array_of_requested_size()
        {
            foreach (var size in new[] { 0, 1, 2, 3, 4, 15, 255, 1024, 1337 })
                Assert.That(Crypto.RandomBytes(size).Length, Is.EqualTo(size));
        }

        [Test]
        public void Hkdf_returns_expected_values()
        {
            foreach (var i in HkdfTestCases)
            {
                var result = Crypto.Hkdf(i.Ikm.DecodeHex(),
                                         i.Salt.DecodeHex(),
                                         i.Info.DecodeHex(),
                                         i.ByteCount);
                Assert.That(result, Is.EqualTo(i.Expected.DecodeHex()));
            }
        }

        //
        // Data
        //

        private struct HkdfTestCase
        {
            public string Ikm;
            public string Salt;
            public string Info;
            public int ByteCount;
            public string Expected;
        }

        // Test vectors from https://tools.ietf.org/html/rfc5869
        private static readonly HkdfTestCase[] HkdfTestCases =
        {
            new HkdfTestCase
            {
                Ikm = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
                Salt = "000102030405060708090a0b0c",
                Info = "f0f1f2f3f4f5f6f7f8f9",
                ByteCount = 42,
                Expected = "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34" +
                           "007208d5b887185865"
            },
            new HkdfTestCase
            {
                Ikm = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222" +
                      "32425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40414243444546" +
                      "4748494a4b4c4d4e4f",
                Salt = "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182" +
                       "838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5" +
                       "a6a7a8a9aaabacadaeaf",
                Info = "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2" +
                       "d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5" +
                       "f6f7f8f9fafbfcfdfeff",
                ByteCount = 82,
                Expected = "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59" +
                           "045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30" +
                           "c58179ec3e87c14c01d5c1f3434f1d87"
            },
        };
    }
}
