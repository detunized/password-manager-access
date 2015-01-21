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
            new TestData("password", "salt", 1, "Eg+2z/z4syxD5yJSVsT4N6hlSMkszDVICAWYfLcL4Xs="),
            new TestData("password", "salt", 2, "rk0Mla9rRtMtCt/5KPBt0CowP47zwlHf1uLYWpVHTEM="),
            new TestData("password", "salt", 4096, "xeR41ZKIyEGqUw22hFxMjZYok6ABzk4RpJY4c6qYE0o="),
            new TestData("passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, "NIyJ28vTKy8y2BS4EW6EzysXNH68GAAYHE4qH7jdU+HGNVGMfaxH6Q=="),
            new TestData("pass\0word", "sa\0lt", 4096, "ibadBRb4KYk8aWImZQqGhw==")
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
                var expected = i.Expected.Decode64();
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
