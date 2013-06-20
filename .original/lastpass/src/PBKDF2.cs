using System;
using System.Security.Cryptography;
using System.Text;
using System.Diagnostics;

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
            var bytes = new byte[byteCount];
            var hashSize = HashFunction.HashSize / 8;
            var blockCount = (byteCount + hashSize - 1) / hashSize;
            for (int i = 0; i < blockCount; ++i)
            {
                var block = CalculateBlock();
                var offset = i * hashSize;
                var size = Math.Min(hashSize, byteCount - offset);
                Buffer.BlockCopy(block, 0, bytes, offset, size);
            }

            return bytes;
        }

        public override void Reset()
        {
        }

        public HMAC HashFunction { get; private set; }
        public byte[] Password { get; private set; }
        public byte[] Salt { get; private set; }
        public int IterationCount { get; private set; }

        private byte[] CalculateBlock()
        {
            return new byte[HashFunction.HashSize / 8];
        }
    }
}
