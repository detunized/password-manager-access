// Copyright (C) 2015 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Security.Cryptography;
using NUnit.Framework;

namespace PasswordBox.Test
{
    [TestFixture]
    class Pbkdf2Test
    {
        private struct TestData
        {
            public TestData(string password, string salt, int iterationCount, string expected)
            {
                Password = password;
                Salt = salt;
                IterationCount = iterationCount;
                Expected = expected;
            }

            public readonly string Password;
            public readonly string Salt;
            public readonly int IterationCount;
            public readonly string Expected;
        };

        // Test data for PBKDF2 HMAC-SHA1 is from https://www.ietf.org/rfc/rfc6070.txt
        private readonly TestData[] _testDataSha1 =
        {
            new TestData("password", "salt", 1, ""),
            new TestData("password", "salt", 1, "0c60c80f961f0e71f3a9b524af6012062fe037a6"),
            new TestData("password", "salt", 2, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"),
            new TestData("password", "salt", 4096, "4b007901b765489abead49d926f721d065a429c1"),
            new TestData("passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038"),
            new TestData("pass\0word", "sa\0lt", 4096, "56fa6aa75548099dcc37d7f03425e0c3")
        };

        // Test data for PBKDF2 HMAC-SHA256 is from http://stackoverflow.com/a/5136918/362938
        private readonly TestData[] _testDataSha256 =
        {
            new TestData("password", "salt", 1, ""),
            new TestData("password", "salt", 1, "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"),
            new TestData("password", "salt", 2, "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"),
            new TestData("password", "salt", 4096, "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"),
            new TestData("passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9"),
            new TestData("pass\0word", "sa\0lt", 4096, "89b69d0516f829893c696226650a8687")
        };

        [Test]
        public void GenerateSha1_returns_correct_result()
        {
            foreach (var i in _testDataSha1)
            {
                var expected = i.Expected.DecodeHex();
                Assert.AreEqual(expected,
                                Pbkdf2.GenerateSha1(i.Password, i.Salt, i.IterationCount, expected.Length));
                Assert.AreEqual(expected,
                                Pbkdf2.Generate<HMACSHA1>(i.Password, i.Salt, i.IterationCount, expected.Length));
            }
        }

        [Test]
        public void GenerateSha256_returns_correct_result()
        {
            foreach (var i in _testDataSha256)
            {
                var expected = i.Expected.DecodeHex();
                Assert.AreEqual(expected,
                                Pbkdf2.GenerateSha256(i.Password, i.Salt, i.IterationCount, expected.Length));
                Assert.AreEqual(expected,
                                Pbkdf2.Generate<HMACSHA256>(i.Password, i.Salt, i.IterationCount, expected.Length));
            }
        }

        [Test]
        [ExpectedException(typeof(ArgumentOutOfRangeException), ExpectedMessage = "Iteration count should be positive\r\nParameter name: iterationCount")]
        public void GenerateSha1_throws_on_zero_iterationCount()
        {
            Pbkdf2.GenerateSha1("password", "salt", 0, 32);
        }

        [Test]
        [ExpectedException(typeof(ArgumentOutOfRangeException), ExpectedMessage = "Iteration count should be positive\r\nParameter name: iterationCount")]
        public void GenerateSha1_throws_on_negative_iterationCount()
        {
            Pbkdf2.GenerateSha1("password", "salt", -1, 32);
        }

        [Test]
        [ExpectedException(typeof(ArgumentOutOfRangeException), ExpectedMessage = "Byte count should be nonnegative\r\nParameter name: byteCount")]
        public void GenerateSha1_throws_on_negative_byteCount()
        {
            Pbkdf2.GenerateSha1("password", "salt", 1, -1);
        }

        [Test]
        [ExpectedException(typeof(ArgumentOutOfRangeException), ExpectedMessage = "Iteration count should be positive\r\nParameter name: iterationCount")]
        public void GenerateSha256_throws_on_zero_iterationCount()
        {
            Pbkdf2.GenerateSha256("password", "salt", 0, 32);
        }

        [Test]
        [ExpectedException(typeof(ArgumentOutOfRangeException), ExpectedMessage = "Iteration count should be positive\r\nParameter name: iterationCount")]
        public void GenerateSha256_throws_on_negative_iterationCount()
        {
            Pbkdf2.GenerateSha256("password", "salt", -1, 32);
        }

        [Test]
        [ExpectedException(typeof(ArgumentOutOfRangeException), ExpectedMessage = "Byte count should be nonnegative\r\nParameter name: byteCount")]
        public void GenerateSha256_throws_on_negative_byteCount()
        {
            Pbkdf2.GenerateSha1("password", "salt", 1, -1);
        }
    }
}
