using System;
using System.Security.Cryptography;
using System.Text;

namespace LastPass
{
    class Pbkdf2
    {
        // TODO: Don't really need this Microsoft interface, just make it a static function

        public Pbkdf2(HMAC hashFunction, string password, string salt, int iterationCount)
            : this(hashFunction, password.ToBytes(), salt.ToBytes(), iterationCount)
        {
        }

        public Pbkdf2(HMAC hashFunction, byte[] password, string salt, int iterationCount)
            : this(hashFunction, password, salt.ToBytes(), iterationCount)
        {
        }

        public Pbkdf2(HMAC hashFunction, string password, byte[] salt, int iterationCount)
            : this(hashFunction, password.ToBytes(), salt, iterationCount)
        {
        }

        public Pbkdf2(HMAC hashFunction, byte[] password, byte[] salt, int iterationCount)
        {
            // TODO: Check arguments and throw exceptions
            HashFunction = hashFunction;
            Password = password;
            Salt = salt;
            IterationCount = iterationCount;

            HashFunction.Key = Password;
        }

        public byte[] GetBytes(int byteCount)
        {
            // TODO: Check for byteCount being too big
            var bytes = new byte[byteCount];
            var hashSize = HashFunction.HashSize / 8;
            var blockCount = (byteCount + hashSize - 1) / hashSize;
            for (var i = 0; i < blockCount; ++i)
            {
                // TODO: Calculate the value in-place
                var block = CalculateBlock(i + 1);
                var offset = i * hashSize;
                var size = Math.Min(hashSize, byteCount - offset);
                Array.Copy(block, 0, bytes, offset, size);
            }

            return bytes;
        }

        public HMAC HashFunction { get; private set; }
        public byte[] Password { get; private set; }
        public byte[] Salt { get; private set; }
        public int IterationCount { get; private set; }

        private byte[] CalculateBlock(int blockIndex)
        {
            // TODO: Get rid if the temporary
            var hashInput = new byte[Salt.Length + 4];
            Salt.CopyTo(hashInput, 0);

            // TODO: Get rid if the temporary
            var indexBytes = BitConverter.GetBytes(blockIndex);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(indexBytes);
            }
            indexBytes.CopyTo(hashInput, Salt.Length);

            var hashed = HashFunction.ComputeHash(hashInput);
            var result = hashed;
            for (var i = 1; i < IterationCount; ++i)
            {
                hashed = HashFunction.ComputeHash(hashed);
                for (var j = 0; j < hashed.Length; ++j)
                {
                    result[j] ^= hashed[j];
                }
            }

            return result;
        }
    }
}
