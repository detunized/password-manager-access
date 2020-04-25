// Copyright (C) 2013 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using NUnit.Framework;

namespace LastPass.Test
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

        // Test data for PBKDF2 HMAC-SHA256 is from http://stackoverflow.com/a/5136918/362938
        private readonly TestData[] _testData =
        {
            new TestData("password", "salt", 1, ""),
            new TestData("password", "salt", 1, "Eg+2z/z4syxD5yJSVsT4N6hlSMkszDVICAWYfLcL4Xs="),
            new TestData("password", "salt", 2, "rk0Mla9rRtMtCt/5KPBt0CowP47zwlHf1uLYWpVHTEM="),
            new TestData("password", "salt", 4096, "xeR41ZKIyEGqUw22hFxMjZYok6ABzk4RpJY4c6qYE0o="),
            new TestData("passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, "NIyJ28vTKy8y2BS4EW6EzysXNH68GAAYHE4qH7jdU+HGNVGMfaxH6Q=="),
            new TestData("pass\0word", "sa\0lt", 4096, "ibadBRb4KYk8aWImZQqGhw==")
        };

        [Test]
        public void Generate_returns_correct_result()
        {
            foreach (var i in _testData)
            {
                var expected = i.Expected.Decode64();
                Assert.AreEqual(expected,
                                Pbkdf2.Generate(i.Password, i.Salt, i.IterationCount, expected.Length));
                Assert.AreEqual(expected,
                                Pbkdf2.Generate(i.Password.ToBytes(), i.Salt, i.IterationCount, expected.Length));
                Assert.AreEqual(expected,
                                Pbkdf2.Generate(i.Password, i.Salt.ToBytes(), i.IterationCount, expected.Length));
                Assert.AreEqual(expected,
                                Pbkdf2.Generate(i.Password.ToBytes(), i.Salt.ToBytes(), i.IterationCount, expected.Length));
            }
        }

        [Test]
        [ExpectedException(typeof(ArgumentOutOfRangeException), ExpectedMessage = "Iteration count should be positive\r\nParameter name: iterationCount")]
        public void Generate_throws_on_zero_iterationCount()
        {
            Pbkdf2.Generate(_testData[0].Password, _testData[0].Salt, 0, _testData[0].Expected.Decode64().Length);
        }

        [Test]
        [ExpectedException(typeof(ArgumentOutOfRangeException), ExpectedMessage = "Iteration count should be positive\r\nParameter name: iterationCount")]
        public void Generate_throws_on_negative_iterationCount()
        {
            Pbkdf2.Generate(_testData[0].Password, _testData[0].Salt, -1, _testData[0].Expected.Decode64().Length);
        }

        [Test]
        [ExpectedException(typeof(ArgumentOutOfRangeException), ExpectedMessage = "Byte count should be nonnegative\r\nParameter name: byteCount")]
        public void Generate_throws_on_negative_byteCount()
        {
            Pbkdf2.Generate(_testData[0].Password, _testData[0].Salt, _testData[0].IterationCount, -1);
        }
    }
}
