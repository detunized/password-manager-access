// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.IO;
using System.Security.Cryptography;

namespace PasswordManagerAccess.Common
{
    internal static class Crypto
    {
        //
        // Random
        //

        public static byte[] RandomBytes(int size)
        {
            using (var random = new RNGCryptoServiceProvider())
            {
                var bytes = new byte[size];
                random.GetBytes(bytes);
                return bytes;
            }
        }

        public static string RandomHex(int length)
        {
            if (length % 2 != 0)
                throw new InternalErrorException("length must be multiple of 2");

            return RandomBytes(length / 2).ToHex();
        }

        public static uint RandonUInt32()
        {
            return BitConverter.ToUInt32(RandomBytes(sizeof(uint)), 0);
        }

        //
        // SHA
        //

        public static byte[] Sha1(string message)
        {
            return Sha1(message.ToBytes());
        }

        public static byte[] Sha1(byte[] message)
        {
            using (var sha = SHA1.Create())
                return sha.ComputeHash(message);
        }

        public static byte[] Sha256(string message)
        {
            return Sha256(message.ToBytes());
        }

        public static byte[] Sha256(byte[] message)
        {
            using (var sha = SHA256.Create())
                return sha.ComputeHash(message);
        }

        public static byte[] Sha512(string message)
        {
            return Sha512(message.ToBytes());
        }

        public static byte[] Sha512(byte[] message)
        {
            using (var sha = SHA512.Create())
                return sha.ComputeHash(message);
        }

        //
        // HMAC
        //

        public static byte[] HmacSha256(string message, byte[] key)
        {
            return HmacSha256(message.ToBytes(), key);
        }

        public static byte[] HmacSha256(byte[] message, byte[] key)
        {
            using (var hmac = new HMACSHA256() { Key = key })
                return hmac.ComputeHash(message);
        }

        //
        // PBKDF2
        //

        public static byte[] Pbkdf2Sha1(string password, byte[] salt, int iterations, int byteCount)
        {
            return Pbkdf2.GenerateSha1(password.ToBytes(), salt, iterations, byteCount);
        }

        public static byte[] Pbkdf2Sha256(string password, byte[] salt, int iterations, int byteCount)
        {
            return Pbkdf2.GenerateSha256(password.ToBytes(), salt, iterations, byteCount);
        }

        public static byte[] Pbkdf2Sha512(string password, byte[] salt, int iterations, int byteCount)
        {
            return Pbkdf2.GenerateSha512(password.ToBytes(), salt, iterations, byteCount);
        }

        //
        // AES
        //

        public static byte[] DecryptAes256Cbc(byte[] ciphertext, byte[] iv, byte[] key)
        {
            return DecryptAes256Cbc(ciphertext, iv, key, PaddingMode.PKCS7);
        }

        public static byte[] DecryptAes256CbcNoPadding(byte[] ciphertext, byte[] iv, byte[] key)
        {
            return DecryptAes256Cbc(ciphertext, iv, key, PaddingMode.None);
        }

        //
        // Private
        //

        private static byte[] DecryptAes256Cbc(byte[] ciphertext, byte[] iv, byte[] key, PaddingMode padding)
        {
            try
            {
                using (var aes = Aes.Create())
                {
                    aes.KeySize = 256;
                    aes.Key = key;
                    aes.Mode = CipherMode.CBC;
                    aes.IV = iv;
                    aes.Padding = padding;

                    using (var decryptor = aes.CreateDecryptor())
                    using (var cryptoStream = new CryptoStream(new MemoryStream(ciphertext, false),
                                                               decryptor,
                                                               CryptoStreamMode.Read))
                    using (var outputStream = new MemoryStream())
                    {
                        cryptoStream.CopyTo(outputStream);
                        return outputStream.ToArray();
                    }
                }
            }
            catch (CryptographicException e)
            {
                throw new CryptoException("AES decryption failed", e);
            }
        }
    }
}
