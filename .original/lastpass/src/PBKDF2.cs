using System;
using System.Security.Cryptography;
using System.Text;
using System.Diagnostics;

namespace LastPass
{
    class PBKDF2: DeriveBytes
    {
        public PBKDF2(HMAC hashFunction, string password, string salt, int iterationCount)
        {
            HashFunction = hashFunction;
            Password = UTF8Encoding.UTF8.GetBytes(password);
            Salt = UTF8Encoding.UTF8.GetBytes(salt);
            IterationCount = iterationCount;

            HashFunction.Key = Password;
        }

        public override byte[] GetBytes(int byteCount)
        {
            var bytes = new byte[byteCount];
            var hashSize = HashFunction.HashSize / 8;
            var blockCount = (byteCount + hashSize - 1) / hashSize;
            for (int i = 0; i < blockCount; ++i)
            {
                var block = CalculateBlock(i + 1);
                var offset = i * hashSize;
                var size = Math.Min(hashSize, byteCount - offset);
                Array.Copy(block, 0, bytes, offset, size);
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

        private byte[] CalculateBlock(int blockIndex)
        {
            var hashInput = new byte[Salt.Length + 4];
            Salt.CopyTo(hashInput, 0);

            var indexBytes = BitConverter.GetBytes(blockIndex);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(indexBytes);
            }
            indexBytes.CopyTo(hashInput, Salt.Length);

            var hashed = HashFunction.ComputeHash(hashInput);
            var result = hashed;
            for (int i = 1; i < IterationCount; ++i)
            {
                hashed = HashFunction.ComputeHash(hashed);
                for (int j = 0; j < hashed.Length; ++j)
                {
                    result[j] ^= hashed[j];
                }
            }

            return result;
        }
    }
}
