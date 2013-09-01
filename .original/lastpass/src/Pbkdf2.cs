using System;
using System.Security.Cryptography;

namespace LastPass
{
    static class Pbkdf2
    {
        public static byte[] Generate(string password, string salt, int iterationCount, int byteCount)
        {
            return Generate(password.ToBytes(), salt.ToBytes(), iterationCount, byteCount);
        }

        public static byte[] Generate(string password, byte[] salt, int iterationCount, int byteCount)
        {
            return Generate(password.ToBytes(), salt, iterationCount, byteCount);
        }

        public static byte[] Generate(byte[] password, string salt, int iterationCount, int byteCount)
        {
            return Generate(password, salt.ToBytes(), iterationCount, byteCount);
        }

        public static byte[] Generate(byte[] password, byte[] salt, int iterationCount, int byteCount)
        {
            if (iterationCount <= 0)
                throw new ArgumentOutOfRangeException("iterationCount", "Iteration count should be positive");

            if (byteCount < 0)
                throw new ArgumentOutOfRangeException("byteCount", "Byte count should be nonnegative");

            using (var hmac = new HMACSHA256())
            {
                hmac.Key = password;

                var bytes = new byte[byteCount];
                var hashSize = hmac.HashSize / 8;
                var blockCount = (byteCount + hashSize - 1) / hashSize;
                for (var i = 0; i < blockCount; ++i)
                {
                    // TODO: Calculate the value in-place
                    var block = CalculateBlock(i + 1, hmac, salt, iterationCount);
                    var offset = i * hashSize;
                    var size = Math.Min(hashSize, byteCount - offset);
                    Array.Copy(block, 0, bytes, offset, size);
                }

                return bytes;
            }
        }

        private static byte[] CalculateBlock(int blockIndex, HMAC hmac, byte[] salt, int iterationCount)
        {
            // TODO: Get rid if the temporary
            var hashInput = new byte[salt.Length + 4];
            salt.CopyTo(hashInput, 0);

            // TODO: Get rid if the temporary
            var indexBytes = BitConverter.GetBytes(blockIndex);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(indexBytes);
            }
            indexBytes.CopyTo(hashInput, salt.Length);

            var hashed = hmac.ComputeHash(hashInput);
            var result = hashed;
            for (var i = 1; i < iterationCount; ++i)
            {
                hashed = hmac.ComputeHash(hashed);
                for (var j = 0; j < hashed.Length; ++j)
                {
                    result[j] ^= hashed[j];
                }
            }

            return result;
        }
    }
}
