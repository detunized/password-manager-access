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

            var genrator = new PBKDF2(hashFunction, password, salt, iterationCount);

            Assert.AreEqual(hashFunction, genrator.HashFunction);
            Assert.AreEqual(passwordBytes, genrator.Password);
            Assert.AreEqual(saltBytes, genrator.Salt);
            Assert.AreEqual(iterationCount, genrator.IterationCount);
        }
    }
}
