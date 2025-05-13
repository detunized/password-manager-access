// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Security.Cryptography;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.OnePassword;

// TODO: Write some comments here. Nothing is obvious in this file.
// TODO: Call to the native functions on the platforms where they are available
class AesGcm
{
    public static byte[] Encrypt(byte[] key, byte[] plaintext, byte[] iv, byte[] adata)
    {
        var length = plaintext.Length;
        var ciphertext = new byte[length + 16];
        var hashKey = new byte[16];
        var hashSalt = new byte[16];

        Crypt(key, plaintext, length, iv, ciphertext, hashKey, hashSalt);

        // Put the tag at the end of the ciphertext
        var tag = ComputeTag(hashKey, hashSalt, adata, ciphertext, length);
        tag.CopyTo(ciphertext, length);

        return ciphertext;
    }

    public static byte[] Decrypt(byte[] key, byte[] ciphertext, byte[] iv, byte[] adata)
    {
        if (ciphertext.Length < 16)
            throw new InternalErrorException("The ciphertext must be at least 16 bytes long");

        var length = ciphertext.Length - 16;
        var plaintext = new byte[length];
        var hashKey = new byte[16];
        var hashSalt = new byte[16];

        Crypt(key, ciphertext, length, iv, plaintext, hashKey, hashSalt);
        var tag = ComputeTag(hashKey, hashSalt, adata, ciphertext, length);

        // Timing attack resistant (not that anyone cares in this case) array comparison.
        // XOR two arrays and bitwise sum up all the bytes. Should evaluate to 0 when
        // and only when the arrays are the same.
        var sum = 0;
        for (var i = 0; i < 16; ++i)
            sum |= tag[i] ^ ciphertext[length + i];

        if (sum != 0)
            throw new InternalErrorException("The auth tag doesn't match");

        return plaintext;
    }

    //
    // Internal
    //

    internal static void Crypt(
        byte[] key,
        byte[] input,
        int length,
        byte[] iv,
        // output
        byte[] output,
        byte[] hashKey,
        byte[] hashSalt
    )
    {
        if (key.Length != 32)
            throw new InternalErrorException("The key must be 32 bytes long");

        if (iv.Length != 12)
            throw new InternalErrorException("The iv must be 12 bytes long");

        using var aes = CreateAes256Ecb(key);
        using var encryptor = aes.CreateEncryptor();
        var counter = InitializeCounter(iv);

        encryptor.TransformBlock(new byte[16], 0, 16, hashKey, 0);
        encryptor.TransformBlock(counter, 0, 16, hashSalt, 0);

        var block = new byte[16];
        for (var i = 0; i < length; i += 16)
        {
            IncrementCounter(counter);
            encryptor.TransformBlock(counter, 0, 16, block, 0);

            for (int j = 0; j < Math.Min(length - i, 16); ++j)
                output[i + j] = (byte)(input[i + j] ^ block[j]);
        }
    }

    // TODO: Move to common crypto module (also this code is duplicated)
    internal static Aes CreateAes256Ecb(byte[] key)
    {
        var aes = Aes.Create();
        aes.BlockSize = 128;
        aes.KeySize = 256;
        aes.Key = key;
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;

        return aes;
    }

    internal static byte[] ComputeTag(byte[] hashKey, byte[] hashSalt, byte[] adata, byte[] ciphertext, int ciphertextLength)
    {
        var tag = GHash(hashKey, adata, adata.Length, ciphertext, ciphertextLength);

        for (var i = 0; i < 16; ++i)
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
        if (++counter[15] != 0)
            return;
        if (++counter[14] != 0)
            return;
        if (++counter[13] != 0)
            return;
        ++counter[12];
    }

    internal static byte[] GHash(byte[] key, byte[] adata, int adataLength, byte[] ciphertext, int ciphertextLength)
    {
        if (key.Length != 16)
            throw new InternalErrorException("The key must be 16 bytes long");

        var key128 = new UInt128(key);
        var x = new UInt128();

        for (var i = 0; i < adataLength; i += 16)
            x = XorMultiply(key128, x, new UInt128(adata, i, adataLength));

        for (var i = 0; i < ciphertextLength; i += 16)
            x = XorMultiply(key128, x, new UInt128(ciphertext, i, ciphertextLength));

        var l = new UInt128(low: (ulong)ciphertextLength * 8, high: (ulong)adataLength * 8);

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

            var odd = x.IsOdd();
            x.ShiftRightBy1();
            if (odd)
                x.High ^= (0xE1UL << 56);
        }

        return z;
    }
}
