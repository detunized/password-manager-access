// Copyright (C) 2016 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

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

        internal static byte[] DecryptAes256Ctr(byte[] ciphertext, byte[] key, byte[] ctr)
        {
            byte[] plaintext = new byte[ciphertext.Length];

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
                // TODO: Loop over the entire input

                var xor = new byte[16];
                encryptor.TransformBlock(ctr, 0, 16, xor, 0);
                for (var i = 0; i < 16; ++i)
                {
                    plaintext[i] = (byte)(ciphertext[i] ^ xor[i]);
                }
            }

            return plaintext;
        }

        internal static void IncrementCounter(byte[] counter)
        {
            int n = counter.Length;
            for (int i = 0, carry = 1; i < n && carry > 0; i += 1)
            {
                int index = n - 1 - i;
                int inc = counter[index] + carry;
                counter[index] = (byte) (inc & 0xff);
                carry = inc >> 8;
            }
        }
    }
}
