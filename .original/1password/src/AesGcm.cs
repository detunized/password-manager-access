// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Diagnostics;
using System.Security.Cryptography;

namespace OnePassword
{
    // TODO: Write some comments here. Nothing is obvious in this file.
    class AesGcm
    {
        public static byte[] Encrypt(byte[] key, byte[] plaintext, byte[] iv, byte[] authData)
        {
            var length = plaintext.Length;
            var ciphertext = new byte[length + 16];
            var hashKey = new byte[16];
            var hashSalt = new byte[16];

            Crypt(key, plaintext, length, iv, authData, ciphertext, hashKey, hashSalt);

            // Put the tag at the end of the ciphertext
            var tag = ComputeTag(hashKey, hashSalt, authData, ciphertext, length);
            tag.CopyTo(ciphertext, length);

            return ciphertext;
        }

        public static byte[] Decrypt(byte[] key, byte[] ciphertext, byte[] iv, byte[] authData)
        {
            if (ciphertext.Length < 16)
                throw new InvalidOperationException("ciphertext must be at least 16 bytes long");

            var length = ciphertext.Length - 16;
            var plaintext = new byte[length];
            var hashKey = new byte[16];
            var hashSalt = new byte[16];

            Crypt(key, ciphertext, length, iv, authData, plaintext, hashKey, hashSalt);
            var tag = ComputeTag(hashKey, hashSalt, authData, ciphertext, length);

            // Timing attack resistant (not that anyone cares in this case) array comparison.
            // XOR two arrays and bitwise sum up all the bytes. Should evaluate to 0 when
            // and only when the arrays are the same.
            int sum = 0;
            for (int i = 0; i < 16; ++i)
                sum |= tag[i] ^ ciphertext[length + i];

            if (sum != 0)
                throw new InvalidOperationException("Auth tag doesn't match");

            return plaintext;
        }

        //
        // Internal
        //

        internal static void Crypt(byte[] key,
                                   byte[] input,
                                   int length,
                                   byte[] iv,
                                   byte[] authData,

                                   // output
                                   byte[] output,
                                   byte[] hashKey,
                                   byte[] hashSalt)
        {
            if (key.Length != 32)
                throw new InvalidOperationException("key must be 32 bytes long");

            if (iv.Length != 12)
                throw new InvalidOperationException("iv must be 12 bytes long");

            Debug.Assert(input.Length >= length);
            Debug.Assert(output.Length >= length);
            Debug.Assert(hashKey.Length == 16);
            Debug.Assert(hashSalt.Length == 16);

            var counter = InitializeCounter(iv);
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
                            output[i + j] = (byte)(input[i + j] ^ block[j]);
                    }
                }
            }
        }

        internal static byte[] ComputeTag(byte[] hashKey,
                                          byte[] hashSalt,
                                          byte[] authData,
                                          byte[] ciphertext,
                                          int ciphertextLength)
        {
            var tag = GHash(hashKey, authData, authData.Length, ciphertext, ciphertextLength);

            for (int i = 0; i < 16; ++i)
                tag[i] ^= hashSalt[i];

            return tag;
        }

        internal static byte[] InitializeCounter(byte[] iv)
        {
            var counter = new byte[16];
            iv.CopyTo(counter, 0);
            counter[15] = 1;

            return counter;
        }

        internal static void IncrementCounter(byte[] counter)
        {
            if (++counter[15] != 0) return;
            if (++counter[14] != 0) return;
            if (++counter[13] != 0) return;
            ++counter[12];
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
