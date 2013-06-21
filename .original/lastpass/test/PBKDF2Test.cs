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

        private TestData[] testData = new TestData[]
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
        public void GetBytes()
        {
            foreach (var i in testData)
            {
                var generator = new PBKDF2(new HMACSHA1(), i.password, i.salt, i.iterationCount);
                var bytes = generator.GetBytes(i.expected.Length);

                Assert.AreEqual(bytes, i.expected);
            }
        }
    }
}
