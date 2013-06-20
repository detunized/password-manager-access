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
            var hashFunction = new HMACSHA1();
            var password = "password";
            var passwordBytes = UTF8Encoding.UTF8.GetBytes(password);
            var salt = "salt";
            var saltBytes = UTF8Encoding.UTF8.GetBytes(salt);
            var iterationCount = 1000;
            var byteCount = 97; // Use a prime number to make sure it's not a multiple of anything

            var generator = new PBKDF2(hashFunction, password, salt, iterationCount);
            var bytes = generator.GetBytes(byteCount);

            Assert.AreEqual(byteCount, bytes.Length);
        }
    }
}
