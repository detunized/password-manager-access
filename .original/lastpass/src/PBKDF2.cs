using System;
using System.Security.Cryptography;
using System.Text;

namespace LastPass
{
    public class PBKDF2: DeriveBytes
    {
        public PBKDF2(HMAC hashFunction, string password, string salt, int iterationCount)
        {
            HashFunction = hashFunction;
            Password = UTF8Encoding.UTF8.GetBytes(password);
            Salt = UTF8Encoding.UTF8.GetBytes(salt);
            IterationCount = iterationCount;
        }

        public override byte[] GetBytes(int byteCount)
        {
            return new byte[0];
        }

        public override void Reset()
        {
        }

        public HMAC HashFunction { get; private set; }
        public byte[] Password { get; private set; }
        public byte[] Salt { get; private set; }
        public int IterationCount { get; private set; }
    }
}
