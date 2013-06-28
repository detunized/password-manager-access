using System;
using System.Security.Cryptography;
using System.Text;
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

        // Test data for PBKDF2 HMAC-SHA1 is from http://tools.ietf.org/html/rfc6070
        private readonly TestData[] _testDataSha1 =
        {
            new TestData("password", "salt", 1, "DGDID5YfDnHzqbUkr2ASBi/gN6Y="),
            new TestData("password", "salt", 2, "6mwBTcctb4zNHtkqzh1B8NjeiVc="),
            new TestData("password", "salt", 4096, "SwB5AbdlSJq+rUnZJvch0GWkKcE="),
            new TestData("passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, "PS7sT+QchJuAyNg2YsDkSospGpZM8vBwOA=="),
            new TestData("pass\0word", "sa\0lt", 4096, "Vvpqp1VICZ3MN9fwNCXgww==")
        };

        // Test data for PBKDF2 HMAC-SHA256 is from http://stackoverflow.com/a/5136918/362938
        private readonly TestData[] _testDataSha256 =
        {
            new TestData("password", "salt", 1, "Eg+2z/z4syxD5yJSVsT4N6hlSMkszDVICAWYfLcL4Xs="),
            new TestData("password", "salt", 2, "rk0Mla9rRtMtCt/5KPBt0CowP47zwlHf1uLYWpVHTEM="),
            new TestData("password", "salt", 4096, "xeR41ZKIyEGqUw22hFxMjZYok6ABzk4RpJY4c6qYE0o="),
            new TestData("passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, "NIyJ28vTKy8y2BS4EW6EzysXNH68GAAYHE4qH7jdU+HGNVGMfaxH6Q=="),
            new TestData("pass\0word", "sa\0lt", 4096, "ibadBRb4KYk8aWImZQqGhw==")
        };

        [Test]
        public void PropertiesAreSet()
        {
            var hashFunction = new HMACSHA1();
            const string password = "password";
            var passwordBytes = password.ToBytes();
            const string salt = "salt";
            var saltBytes = salt.ToBytes();
            const int iterationCount = 1000;

            var generator = new Pbkdf2(hashFunction, password, salt, iterationCount);

            Assert.AreEqual(hashFunction, generator.HashFunction);
            Assert.AreEqual(passwordBytes, generator.Password);
            Assert.AreEqual(saltBytes, generator.Salt);
            Assert.AreEqual(iterationCount, generator.IterationCount);
        }

        [Test]
        public void GetBytesSha1()
        {
            using (var hmac = new HMACSHA1())
            {
                foreach (var i in _testDataSha1)
                {
                    var expected = Convert.FromBase64String(i.Expected);
                    byte[][] results =
                    {
                        new Pbkdf2(hmac, i.Password, i.Salt, i.IterationCount).GetBytes(expected.Length),
                        new Pbkdf2(hmac, i.Password.ToBytes(), i.Salt, i.IterationCount).GetBytes(expected.Length),
                        new Pbkdf2(hmac, i.Password, i.Salt.ToBytes(), i.IterationCount).GetBytes(expected.Length),
                        new Pbkdf2(hmac, i.Password.ToBytes(), i.Salt.ToBytes(), i.IterationCount).GetBytes(expected.Length)
                    };

                    foreach (var j in results)
                    {
                        Assert.AreEqual(expected, j);
                    }
                }
            }
        }

        [Test]
        public void GetBytesSha256()
        {
            using (var hmac = new HMACSHA256())
            {
                foreach (var i in _testDataSha256)
                {
                    var expected = Convert.FromBase64String(i.Expected);
                    byte[][] results =
                    {
                        new Pbkdf2(hmac, i.Password, i.Salt, i.IterationCount).GetBytes(expected.Length),
                        new Pbkdf2(hmac, i.Password.ToBytes(), i.Salt, i.IterationCount).GetBytes(expected.Length),
                        new Pbkdf2(hmac, i.Password, i.Salt.ToBytes(), i.IterationCount).GetBytes(expected.Length),
                        new Pbkdf2(hmac, i.Password.ToBytes(), i.Salt.ToBytes(), i.IterationCount).GetBytes(expected.Length)
                    };

                    foreach (var j in results)
                    {
                        Assert.AreEqual(expected, j);
                    }
                }
            }
        }
    }
}
