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
            new TestData("password", "salt", 1, "Eg+2z/z4syxD5yJSVsT4N6hlSMkszDVICAWYfLcL4Xs="),
            new TestData("password", "salt", 2, "rk0Mla9rRtMtCt/5KPBt0CowP47zwlHf1uLYWpVHTEM="),
            new TestData("password", "salt", 4096, "xeR41ZKIyEGqUw22hFxMjZYok6ABzk4RpJY4c6qYE0o="),
            new TestData("passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, "NIyJ28vTKy8y2BS4EW6EzysXNH68GAAYHE4qH7jdU+HGNVGMfaxH6Q=="),
            new TestData("pass\0word", "sa\0lt", 4096, "ibadBRb4KYk8aWImZQqGhw==")
        };

        [Test]
        public void GetBytesSha256()
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
    }
}
