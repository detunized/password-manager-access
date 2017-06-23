// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Linq;
using System.Security.Cryptography;

namespace OnePassword
{
    class AesGcm
    {
        public static byte[] Encrypt(byte[] key, byte[] plaintext, byte[] iv, byte[] authData)
        {
            if (key.Length != 32)
                throw new InvalidOperationException("key must be 32 bytes long");

            if (iv.Length != 12)
                throw new InvalidOperationException("iv must be 12 bytes long");

            var counter = new byte[16];
            iv.CopyTo(counter, 0);
            counter[15] = 1;

            var ciphertext = new byte[plaintext.Length + 16];
            plaintext.CopyTo(ciphertext, 0);

            var hashKey = new byte[16];
            var hashSalt = new byte[16];

            using (var aes = Aes.Create())
            {
                aes.Mode = CipherMode.ECB;
                aes.Key = key;

                using (var aesEnc = aes.CreateEncryptor())
                {
                    aesEnc.TransformBlock(new byte[16], 0, 16, hashKey, 0);
                    aesEnc.TransformBlock(counter, 0, 16, hashSalt, 0);

                    var block = new byte[16];
                    for (int i = 0; i < (plaintext.Length + 15) / 16; ++i)
                    {
                        IncrementCounter(counter);
                        aesEnc.TransformBlock(counter, 0, 16, block, 0);

                        for (int j = 0; j < 16; ++j)
                            ciphertext[i * 16 + j] ^= block[j];
                    }
                }
            }

            for (int i = 0; i < 16; ++i)
                ciphertext[plaintext.Length + i] = 0;

            var hash = GHash(hashKey, authData, authData.Length, ciphertext, plaintext.Length);
            hash.CopyTo(ciphertext, plaintext.Length);

            for (int i = 0; i < 16; ++i)
                ciphertext[plaintext.Length + i] ^= hashSalt[i];

            return ciphertext;
        }

        public static byte[] Decrypt(byte[] key, byte[] ciphertext, byte[] iv, byte[] authData)
        {
            if (key.Length != 32)
                throw new InvalidOperationException("key must be 32 bytes long");

            if (ciphertext.Length < 16)
                throw new InvalidOperationException("ciphertext must be at least 16 bytes long");

            if (iv.Length != 12)
                throw new InvalidOperationException("iv must be 12 bytes long");

            var length = ciphertext.Length - 16;
            var plaintext = new byte[length];
            Array.Copy(ciphertext, plaintext, length);

            var counter = InitializeCounter(iv);
            var hashKey = new byte[16];
            var hashSalt = new byte[16];

            using (var aes = Aes.Create())
            {
                aes.Mode = CipherMode.ECB;
                aes.Key = key;

                using (var aesEnc = aes.CreateEncryptor())
                {
                    aesEnc.TransformBlock(new byte[16], 0, 16, hashKey, 0);
                    aesEnc.TransformBlock(counter, 0, 16, hashSalt, 0);

                    var block = new byte[16];
                    for (int i = 0; i < length; i += 16)
                    {
                        IncrementCounter(counter);
                        aesEnc.TransformBlock(counter, 0, 16, block, 0);

                        for (int j = 0; j < Math.Min(length - i, 16); ++j)
                            plaintext[i + j] ^= block[j];
                    }
                }
            }

            var tag = GHash(hashKey, authData, authData.Length, ciphertext, length);
            for (int i = 0; i < 16; ++i)
                tag[i] ^= hashSalt[i];

            if (!tag.SequenceEqual(ciphertext.Skip(length).Take(16)))
                throw new InvalidOperationException("Auth tag doesn't match");

            return plaintext;
        }

        //
        // Internal
        //

        internal static byte[] InitializeCounter(byte[] iv)
        {
            var counter = new byte[16];
            iv.CopyTo(counter, 0);
            counter[15] = 1;

            return counter;
        }

        internal static void IncrementCounter(byte[] counter)
        {
            ++counter[15];
            if (counter[15] == 0)
            {
                ++counter[14];
                if (counter[14] == 0)
                {
                    ++counter[13];
                    if (counter[13] == 0)
                        ++counter[12];
                }
            }
        }

        internal static byte[] GHash(byte[] key,
                                     byte[] authData,
                                     int authDataLength,
                                     byte[] ciphertext,
                                     int ciphertextLength)
        {
            if (key.Length != 16)
                throw new InvalidOperationException("key must be 16 bytes long");

            var key128 = new UInt128(key);
            var x = new UInt128();

            for (int i = 0; i < authDataLength; i += 16)
                x = XorMultiply(key128, x, new UInt128(authData, i, authDataLength));

            for (int i = 0; i < ciphertextLength; i += 16)
                x = XorMultiply(key128, x, new UInt128(ciphertext, i, ciphertextLength));

            var l = new UInt128(low: (ulong)ciphertextLength * 8, high: (ulong)authDataLength * 8);

            return XorMultiply(key128, x, l).ToBytes();
        }

        internal static UInt128 XorMultiply(UInt128 key, UInt128 x, UInt128 y)
        {
            x.XorWith(y);
            return MultiplyGf2(key, x);
        }

        internal static UInt128 MultiplyGf2(UInt128 x, UInt128 y)
        {
            var z = new UInt128 { High = 0, Low = 0 };

            while (!y.IsZero())
            {
                if ((y.High & (1UL << 63)) != 0)
                    z.XorWith(x);

                y.ShiftLeftBy1();

                bool odd = x.IsOdd();
                x.ShiftRightBy1();
                if (odd)
                    x.High ^= (0xE1UL << 56);
            }

            return z;
        }
    }
}
