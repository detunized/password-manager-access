// Copyright (C) 2016 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Linq;
using System.Security.Cryptography;

namespace ZohoVault
{
    public static class Crypto
    {
        public static byte[] Decrypt(byte[] ctrCiphertext, byte[] key)
        {
            if (ctrCiphertext.Length < 8 + 1)
                return new byte[] {};

            var ctr = ctrCiphertext.Take(8).Concat(new byte[8]).ToArray();
            var ciphertext = ctrCiphertext.Skip(8).ToArray();
            var ctrKey = ComputeAesCtrKey(key);

            return ciphertext;
        }

        internal static byte[] ComputeAesCtrKey(byte[] key)
        {
            using (
                var aes = new AesManaged
                {
                    BlockSize = 128,
                    KeySize = 256,
                    Key = key,
                    Mode = CipherMode.ECB,
                    Padding = PaddingMode.None
                })
            using (var encryptor = aes.CreateEncryptor())
            {
                var ctrKey = encryptor.TransformFinalBlock(key, 0, 16);
                return ctrKey.Concat(ctrKey).ToArray();
            }
        }

        internal static byte[] DecryptAes256Ctr(byte[] ciphertext, byte[] key, byte[] initialCounter)
        {
            var length = ciphertext.Length;
            var plaintext = new byte[length];

            using (
                var aes = new AesManaged
                {
                    BlockSize = 128,
                    KeySize = 256,
                    Key = key,
                    Mode = CipherMode.ECB,
                    Padding = PaddingMode.None
                })
            using (var encryptor = aes.CreateEncryptor())
            {
                // For AES block size is always 16 bytes
                const int blockSize = 16;

                // Clone the counter not to modify the input
                var counter = initialCounter.Take(blockSize).ToArray();

                // Number of blocks in the input. The last block extends past
                // the input buffer, when the size is not aligned.
                var blockCount = (length + blockSize - 1) / blockSize;

                // XOR mask, allocate once and reuse
                var xor = new byte[blockSize];

                for (var block = 0; block < blockCount; block += 1)
                {
                    // XOR mask is simply the AES-ECB encrypted counter value
                    encryptor.TransformBlock(counter, 0, blockSize, xor, 0);
                    IncrementCounter(counter);

                    // Need to pay attention no to poke outside of the buffers
                    var blockStartIndex = block * blockSize;
                    var thisBlockSize = Math.Min(blockSize, length - blockStartIndex);

                    // XOR input with the mask. That's all there is to CTR mode.
                    for (var i = 0; i < thisBlockSize; i += 1)
                        plaintext[blockStartIndex + i] = (byte)(ciphertext[blockStartIndex + i] ^ xor[i]);
                }
            }

            return plaintext;
        }

        internal static void IncrementCounter(byte[] counter)
        {
            var n = counter.Length;
            for (int i = 0, carry = 1; i < n && carry > 0; i += 1)
            {
                var index = n - 1 - i;
                int inc = counter[index] + carry;
                counter[index] = (byte) (inc & 0xff);
                carry = inc >> 8;
            }
        }
    }
}
