// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Security.Cryptography;

namespace OnePassword
{
    internal static class Pbkdf2
    {
        public static byte[] GenerateSha1(byte[] password,
                                          byte[] salt,
                                          int iterationCount,
                                          int byteCount)
        {
            return Generate<HMACSHA1>(password, salt, iterationCount, byteCount);
        }

        public static byte[] GenerateSha256(byte[] password,
                                            byte[] salt,
                                            int iterationCount,
                                            int byteCount)
        {
            return Generate<HMACSHA256>(password, salt, iterationCount, byteCount);
        }

        public static byte[] GenerateSha512(byte[] password,
                                            byte[] salt,
                                            int iterationCount,
                                            int byteCount)
        {
            return Generate<HMACSHA512>(password, salt, iterationCount, byteCount);
        }

        public static byte[] Generate<T>(byte[] password,
                                         byte[] salt,
                                         int iterationCount,
                                         int byteCount) where T : HMAC, new()
        {
            if (iterationCount <= 0)
                throw new ArgumentOutOfRangeException("iterationCount",
                                                      "Iteration count should be positive");

            if (byteCount < 0)
                throw new ArgumentOutOfRangeException("byteCount",
                                                      "Byte count should be nonnegative");

            using (var hmac = new T())
            {
                hmac.Key = password;

                // Prepare hash input (salt + block index)
                var hashInputSize = salt.Length + 4;
                var hashInput = new byte[hashInputSize];
                salt.CopyTo(hashInput, 0);
                hashInput[hashInputSize - 4] = 0;
                hashInput[hashInputSize - 3] = 0;
                hashInput[hashInputSize - 2] = 0;
                hashInput[hashInputSize - 1] = 0;

                var bytes = new byte[byteCount];
                var hashSize = hmac.HashSize / 8;
                var blockCount = (byteCount + hashSize - 1) / hashSize;

                for (var i = 0; i < blockCount; ++i)
                {
                    // Increase 32-bit big-endian block index at the end of the hash input buffer
                    if (++hashInput[hashInputSize - 1] == 0)
                        if (++hashInput[hashInputSize - 2] == 0)
                            if (++hashInput[hashInputSize - 3] == 0)
                                ++hashInput[hashInputSize - 4];

                    var hashed = hmac.ComputeHash(hashInput);
                    var block = hashed;
                    for (var j = 1; j < iterationCount; ++j)
                    {
                        hashed = hmac.ComputeHash(hashed);
                        for (var k = 0; k < hashed.Length; ++k)
                        {
                            block[k] ^= hashed[k];
                        }
                    }

                    var offset = i * hashSize;
                    var size = Math.Min(hashSize, byteCount - offset);
                    Array.Copy(block, 0, bytes, offset, size);
                }

                return bytes;
            }
        }
    }
}
