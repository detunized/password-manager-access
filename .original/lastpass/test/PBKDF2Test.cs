using System;
using System.Security.Cryptography;
using System.Text;
using LastPass;

namespace LastPass.Test
{
    using NUnit.Framework;

    [TestFixture]
    class PBKDF2Test
    {
        private struct TestData
        {
            public string password;
            public string salt;
            public int iterationCount;
            public byte[] expected;
        };

        // Test data for PBKDF2 HMAC-SHA1 is from http://tools.ietf.org/html/rfc6070
        private TestData[] testDataSHA1 = new TestData[]
        {
            new TestData
            {
                password = "password",
                salt = "salt",
                iterationCount = 1,
                expected = new byte[] {0x0c, 0x60, 0xc8, 0x0f, 0x96, 0x1f, 0x0e, 0x71, 0xf3, 0xa9, 0xb5, 0x24, 0xaf, 0x60, 0x12, 0x06, 0x2f, 0xe0, 0x37, 0xa6}
            },

            new TestData
            {
                password = "password",
                salt = "salt",
                iterationCount = 2,
                expected = new byte[] {0xea, 0x6c, 0x01, 0x4d, 0xc7, 0x2d, 0x6f, 0x8c, 0xcd, 0x1e, 0xd9, 0x2a, 0xce, 0x1d, 0x41, 0xf0, 0xd8, 0xde, 0x89, 0x57}
            },

            new TestData
            {
                password = "password",
                salt = "salt",
                iterationCount = 4096,
                expected = new byte[] {0x4b, 0x00, 0x79, 0x01, 0xb7, 0x65, 0x48, 0x9a, 0xbe, 0xad, 0x49, 0xd9, 0x26, 0xf7, 0x21, 0xd0, 0x65, 0xa4, 0x29, 0xc1}
            },

            new TestData
            {
                password = "passwordPASSWORDpassword",
                salt = "saltSALTsaltSALTsaltSALTsaltSALTsalt",
                iterationCount = 4096,
                expected = new byte[] {0x3d, 0x2e, 0xec, 0x4f, 0xe4, 0x1c, 0x84, 0x9b, 0x80, 0xc8, 0xd8, 0x36, 0x62, 0xc0, 0xe4, 0x4a, 0x8b, 0x29, 0x1a, 0x96, 0x4c, 0xf2, 0xf0, 0x70, 0x38}
            },

            new TestData
            {
                password = "pass\0word",
                salt = "sa\0lt",
                iterationCount = 4096,
                expected = new byte[] {0x56, 0xfa, 0x6a, 0xa7, 0x55, 0x48, 0x09, 0x9d, 0xcc, 0x37, 0xd7, 0xf0, 0x34, 0x25, 0xe0, 0xc3}
            },
        };

        // Test data for PBKDF2 HMAC-SHA256 is from http://stackoverflow.com/a/5136918/362938
        private TestData[] testDataSHA256 = new TestData[]
        {
            new TestData
            {
                password = "password",
                salt = "salt",
                iterationCount = 1,
                expected = new byte[] {0x12, 0x0f, 0xb6, 0xcf, 0xfc, 0xf8, 0xb3, 0x2c, 0x43, 0xe7, 0x22, 0x52, 0x56, 0xc4, 0xf8, 0x37, 0xa8, 0x65, 0x48, 0xc9, 0x2c, 0xcc, 0x35, 0x48, 0x08, 0x05, 0x98, 0x7c, 0xb7, 0x0b, 0xe1, 0x7b}
            },

            new TestData
            {
                password = "password",
                salt = "salt",
                iterationCount = 2,
                expected = new byte[] {0xae, 0x4d, 0x0c, 0x95, 0xaf, 0x6b, 0x46, 0xd3, 0x2d, 0x0a, 0xdf, 0xf9, 0x28, 0xf0, 0x6d, 0xd0, 0x2a, 0x30, 0x3f, 0x8e, 0xf3, 0xc2, 0x51, 0xdf, 0xd6, 0xe2, 0xd8, 0x5a, 0x95, 0x47, 0x4c, 0x43}
            },

            new TestData
            {
                password = "password",
                salt = "salt",
                iterationCount = 4096,
                expected = new byte[] {0xc5, 0xe4, 0x78, 0xd5, 0x92, 0x88, 0xc8, 0x41, 0xaa, 0x53, 0x0d, 0xb6, 0x84, 0x5c, 0x4c, 0x8d, 0x96, 0x28, 0x93, 0xa0, 0x01, 0xce, 0x4e, 0x11, 0xa4, 0x96, 0x38, 0x73, 0xaa, 0x98, 0x13, 0x4a}
            },

            new TestData
            {
                password = "passwordPASSWORDpassword",
                salt = "saltSALTsaltSALTsaltSALTsaltSALTsalt",
                iterationCount = 4096,
                expected = new byte[] {0x34, 0x8c, 0x89, 0xdb, 0xcb, 0xd3, 0x2b, 0x2f, 0x32, 0xd8, 0x14, 0xb8, 0x11, 0x6e, 0x84, 0xcf, 0x2b, 0x17, 0x34, 0x7e, 0xbc, 0x18, 0x00, 0x18, 0x1c, 0x4e, 0x2a, 0x1f, 0xb8, 0xdd, 0x53, 0xe1, 0xc6, 0x35, 0x51, 0x8c, 0x7d, 0xac, 0x47, 0xe9}
            },

            new TestData
            {
                password = "pass\0word",
                salt = "sa\0lt",
                iterationCount = 4096,
                expected = new byte[] {0x89, 0xb6, 0x9d, 0x05, 0x16, 0xf8, 0x29, 0x89, 0x3c, 0x69, 0x62, 0x26, 0x65, 0x0a, 0x86, 0x87}
            },
        };

        [Test]
        public void PropertiesAreSet()
        {
            var hashFunction = new HMACSHA1();
            var password = "password";
            var passwordBytes = UTF8Encoding.UTF8.GetBytes(password);
            var salt = "salt";
            var saltBytes = UTF8Encoding.UTF8.GetBytes(salt);
            var iterationCount = 1000;

            var generator = new PBKDF2(hashFunction, password, salt, iterationCount);

            Assert.AreEqual(hashFunction, generator.HashFunction);
            Assert.AreEqual(passwordBytes, generator.Password);
            Assert.AreEqual(saltBytes, generator.Salt);
            Assert.AreEqual(iterationCount, generator.IterationCount);
        }

        [Test]
        public void GetBytesSHA1()
        {
            using (var hmac = new HMACSHA1())
            {
                foreach (var i in testDataSHA1)
                {
                    byte[][] results =
                    {
                        new PBKDF2(hmac, i.password, i.salt, i.iterationCount).GetBytes(i.expected.Length),
                        new PBKDF2(hmac, UTF8Encoding.UTF8.GetBytes(i.password), i.salt, i.iterationCount).GetBytes(i.expected.Length),
                        new PBKDF2(hmac, i.password, UTF8Encoding.UTF8.GetBytes(i.salt), i.iterationCount).GetBytes(i.expected.Length),
                        new PBKDF2(hmac, UTF8Encoding.UTF8.GetBytes(i.password), UTF8Encoding.UTF8.GetBytes(i.salt), i.iterationCount).GetBytes(i.expected.Length),
                    };

                    foreach (var j in results)
                    {
                        Assert.AreEqual(j, i.expected);
                    }
                }
            }
        }

        [Test]
        public void GetBytesSHA256()
        {
            using (var hmac = new HMACSHA256())
            {
                foreach (var i in testDataSHA256)
                {
                    byte[][] results =
                    {
                        new PBKDF2(hmac, i.password, i.salt, i.iterationCount).GetBytes(i.expected.Length),
                        new PBKDF2(hmac, UTF8Encoding.UTF8.GetBytes(i.password), i.salt, i.iterationCount).GetBytes(i.expected.Length),
                        new PBKDF2(hmac, i.password, UTF8Encoding.UTF8.GetBytes(i.salt), i.iterationCount).GetBytes(i.expected.Length),
                        new PBKDF2(hmac, UTF8Encoding.UTF8.GetBytes(i.password), UTF8Encoding.UTF8.GetBytes(i.salt), i.iterationCount).GetBytes(i.expected.Length),
                    };

                    foreach (var j in results)
                    {
                        Assert.AreEqual(j, i.expected);
                    }
                }
            }
        }
    }
}
