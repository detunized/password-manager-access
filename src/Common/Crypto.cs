// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
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
            using var random = new RNGCryptoServiceProvider();
            var bytes = new byte[size];
            random.GetBytes(bytes);
            return bytes;
        }

        public static string RandomHex(int length)
        {
            if (length % 2 != 0)
                throw new InternalErrorException("length must be multiple of 2");

            return RandomBytes(length / 2).ToHex();
        }

        public static uint RandomUInt32()
        {
            return BitConverter.ToUInt32(RandomBytes(sizeof(uint)), 0);
        }

        //
        // MD5
        //

        public static byte[] Md5(string message)
        {
            return Md5(message.ToBytes());
        }

        public static byte[] Md5(byte[] message)
        {
            using var md5 = MD5.Create();
            return md5.ComputeHash(message);
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
            using var sha = SHA1.Create();
            return sha.ComputeHash(message);
        }

        public static byte[] Sha256(string message)
        {
            return Sha256(message.ToBytes());
        }

        public static byte[] Sha256(byte[] message)
        {
            using var sha = SHA256.Create();
            return sha.ComputeHash(message);
        }

        public static byte[] Sha512(string message)
        {
            return Sha512(message.ToBytes());
        }

        public static byte[] Sha512(byte[] message)
        {
            using var sha = SHA512.Create();
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
            using var hmac = new HMACSHA256() { Key = key };
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

        //
        // ECB
        //

        public static byte[] DecryptAes256Ecb(byte[] ciphertext,
                                              byte[] iv,
                                              byte[] key,
                                              PaddingMode paddingMode = PaddingMode.PKCS7)
        {
            return DecryptAes256(ciphertext, iv, key, CipherMode.ECB, paddingMode);
        }

        public static byte[] DecryptAes256EcbNoPadding(byte[] ciphertext, byte[] iv, byte[] key)
        {
            return DecryptAes256Ecb(ciphertext, iv, key, PaddingMode.None);
        }

        public static byte[] EncryptAes256Ecb(byte[] plaintext,
                                              byte[] iv,
                                              byte[] key,
                                              PaddingMode padding = PaddingMode.PKCS7)
        {
            return EncryptAes256(plaintext, iv, key, CipherMode.ECB, padding);
        }

        public static byte[] EncryptAes256EcbNoPadding(byte[] plaintext, byte[] iv, byte[] key)
        {
            return EncryptAes256Ecb(plaintext, iv, key, PaddingMode.None);
        }

        //
        // CBC
        //

        public static byte[] DecryptAes256Cbc(byte[] ciphertext,
                                              byte[] iv,
                                              byte[] key,
                                              PaddingMode padding = PaddingMode.PKCS7)
        {
            return DecryptAes256(ciphertext, iv, key, CipherMode.CBC, padding);
        }

        public static byte[] DecryptAes256CbcNoPadding(byte[] ciphertext, byte[] iv, byte[] key)
        {
            return DecryptAes256Cbc(ciphertext, iv, key, PaddingMode.None);
        }

        public static byte[] EncryptAes256Cbc(byte[] plaintext,
                                              byte[] iv,
                                              byte[] key,
                                              PaddingMode padding = PaddingMode.PKCS7)
        {
            return EncryptAes256(plaintext, iv, key, CipherMode.CBC, padding);
        }

        public static byte[] EncryptAes256CbcNoPadding(byte[] plaintext, byte[] iv, byte[] key)
        {
            return EncryptAes256Cbc(plaintext, iv, key, PaddingMode.None);
        }

        //
        // Generic
        //

        public static byte[] DecryptAes256(byte[] ciphertext,
                                           byte[] iv,
                                           byte[] key,
                                           CipherMode cipherMode,
                                           PaddingMode padding)
        {
            return CryptAes256(ciphertext, iv, key, cipherMode, padding, aes => aes.CreateDecryptor());
        }

        public static byte[] EncryptAes256(byte[] plaintext,
                                           byte[] iv,
                                           byte[] key,
                                           CipherMode cipherMode,
                                           PaddingMode padding)
        {
            return CryptAes256(plaintext, iv, key, cipherMode, padding, aes => aes.CreateEncryptor());
        }

        private static byte[] CryptAes256(byte[] text,
                                          byte[] iv,
                                          byte[] key,
                                          CipherMode cipherMode,
                                          PaddingMode padding,
                                          Func<SymmetricAlgorithm, ICryptoTransform> createCryptor)
        {
            static CryptoException MakeError(Exception e) => new CryptoException("AES decryption failed", e);

            try
            {
                using var aes = Aes.Create();
                aes.KeySize = 256;
                aes.Key = key;
                aes.Mode = cipherMode;
                aes.IV = iv;
                aes.Padding = padding;

                // TOOD: Look into performance of this thing. Sometimes there's a lot of these
                // operations happening while the vault is being open. This is epecially true for
                // large vaults with tousands of items in them. There's a lot of (unnecessary)
                // temporary objects and memory copying here!
                using var cryptor = createCryptor(aes);
                using var inputStream = new MemoryStream(text, false);
                using var cryptoStream = new CryptoStream(inputStream, cryptor, CryptoStreamMode.Read);

                // Here we use quite a small buffer, since most of the time the encrypted data is
                // quite short.
                //
                // TODO: See if it makes sense to base the buffer size on the input size. Definitely
                // it doesn't make sense to have a buffer that is lager than the input.
                return cryptoStream.ReadAll(256);
            }
            catch (CryptographicException e)
            {
                throw MakeError(e);
            }
            // This should not be needed. But due to some bug in Mono the CryptographicException is not getting
            // thrown on all occasions, sometimes we get ArgumentException instead.
            catch (ArgumentException e)
            {
                throw MakeError(e);
            }
        }

        //
        // RSA
        //

        public static byte[] DecryptRsaPkcs1(byte[] ciphertext, RSAParameters privateKey)
        {
            return DecryptRsa(ciphertext, privateKey, RSAEncryptionPadding.Pkcs1);
        }

        public static byte[] DecryptRsaSha1(byte[] ciphertext, RSAParameters privateKey)
        {
            return DecryptRsa(ciphertext, privateKey, RSAEncryptionPadding.OaepSHA1);
        }

        // TODO: Test this function. One .NET 4.7.2 it throws "unsupported" or something like that.
        public static byte[] DecryptRsaSha256(byte[] ciphertext, RSAParameters privateKey)
        {
            return DecryptRsa(ciphertext, privateKey, RSAEncryptionPadding.OaepSHA256);
        }

        public static byte[] DecryptRsa(byte[] ciphertext, RSAParameters privateKey, RSAEncryptionPadding padding)
        {
            try
            {
                using var rsa = new RSACryptoServiceProvider();
                rsa.ImportParameters(privateKey);
                return rsa.Decrypt(ciphertext, padding);
            }
            catch (CryptographicException e)
            {
                throw new CryptoException("RSA decryption failed", e);
            }
        }
    }
}
