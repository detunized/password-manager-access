// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Linq;
using System.Security.Cryptography;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.ZohoVault
{
    internal static class Util
    {
        // For AES block size is always 16 bytes
        public const int BlockSize = 16;

        public static byte[] ComputeKey(string passphrase, byte[] salt, int iterationCount)
        {
            // Regular PBKDF2 with HMAC-SHA256
            var key = Crypto.Pbkdf2Sha256(passphrase, salt, iterationCount, 32);

            // They actual key is the hex bytes, not the key itself
            return key.ToHex().Substring(0, 32).ToBytes();
        }

        public static string DecryptStringLoose(string ctrCiphertextBase64, byte[] key)
        {
            return ctrCiphertextBase64.IsNullOrEmpty() ? "" : DecryptString(ctrCiphertextBase64, key);
        }

        public static string DecryptString(string ctrCiphertextBase64, byte[] key)
        {
            return Decrypt(ctrCiphertextBase64.Decode64(), key).ToUtf8();
        }

        public static byte[] Decrypt(string ctrCiphertextBase64, byte[] key)
        {
            return Decrypt(ctrCiphertextBase64.Decode64(), key);
        }

        // TODO: See if this "key derivation" could be moved out of here
        //       not to recalculate it every time.
        public static byte[] Decrypt(byte[] ctrCiphertext, byte[] key)
        {
            if (ctrCiphertext.Length < 8 + 1)
                return new byte[] { };

            // First 8 bytes of the ciphertext is the ctr initial value. Has to be padded with zeros.
            var ctr = ctrCiphertext.Take(8).Concat(new byte[8]).ToArray();

            // The rest is the ciphertext.
            var ciphertext = ctrCiphertext.Skip(8).ToArray();

            // Have to produce a decryption key out of a decryption key. Weird.
            var ctrKey = ComputeAesCtrKey(key);

            // Now decrypt using regular AES-256 CTR
            return DecryptAes256Ctr(ciphertext, ctrKey, ctr);
        }

        public static byte[] ComputeAesCtrKey(byte[] key)
        {
            // The actual encryption key is the original key encrypted with AES-ECB
            // using itself as a key. Then it's duplicated and pasted together.
            using var aes = CreateAes256Ecb(key);
            using var encryptor = aes.CreateEncryptor();

            var ctrKey = new byte[BlockSize * 2];
            encryptor.TransformBlock(key, 0, BlockSize, ctrKey, 0);
            Array.Copy(ctrKey, 0, ctrKey, BlockSize, BlockSize);

            return ctrKey;
        }

        // TODO: Move this to the common crypto module
        public static byte[] DecryptAes256Ctr(byte[] ciphertext, byte[] key, byte[] initialCounter)
        {
            var length = ciphertext.Length;
            var plaintext = new byte[length];

            using var aes = CreateAes256Ecb(key);
            using var encryptor = aes.CreateEncryptor();

            // Clone the counter not to modify the input
            var counter = initialCounter.Take(BlockSize).ToArray();

            // Number of blocks in the input. The last block extends past
            // the input buffer, when the size is not aligned.
            var blockCount = (length + BlockSize - 1) / BlockSize;

            // XOR mask, allocate once and reuse
            var xor = new byte[BlockSize];

            for (var block = 0; block < blockCount; block += 1)
            {
                // XOR mask is simply the AES-ECB encrypted counter value
                encryptor.TransformBlock(counter, 0, BlockSize, xor, 0);
                IncrementCounter(counter);

                // Need to pay attention no to poke outside of the buffers
                var blockStartIndex = block * BlockSize;
                var thisBlockSize = Math.Min(BlockSize, length - blockStartIndex);

                // XOR input with the mask. That's all there is to CTR mode.
                for (var i = 0; i < thisBlockSize; i += 1)
                    plaintext[blockStartIndex + i] = (byte)(ciphertext[blockStartIndex + i] ^ xor[i]);
            }

            return plaintext;
        }

        public static void IncrementCounter(byte[] counter)
        {
            var n = counter.Length;
            for (int i = 0, carry = 1; i < n && carry > 0; i += 1)
            {
                var index = n - 1 - i;
                int inc = counter[index] + carry;
                counter[index] = (byte)(inc & 0xff);
                carry = inc >> 8;
            }
        }

        // TODO: Move to common crypto module
        private static Aes CreateAes256Ecb(byte[] key)
        {
            var aes = Aes.Create();
            aes.BlockSize = 128;
            aes.KeySize = 256;
            aes.Key = key;
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.None;

            return aes;
        }
    }
}
