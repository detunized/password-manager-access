// Copyright (C) 2015 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Linq;
using System.Security.Cryptography;

namespace PasswordBox
{
    internal static class Crypto
    {
        // Decrypts a piece of data. Encrypted data is base64 encoded.
        // The key is hex encoded. Only first 256 bits of key are used.
        // Decrypted data is binary.
        //
        // Encrypted data is made up of the following parts:
        // 1 byte at 0: ignored
        // 1 byte at 1: format version (only 4 is supported)
        // 16 bytes at 2: IV - initialized vector for AES-CCM encryption
        // the rest at 18: ciphertext (encrypted data)
        public static byte[] Decrypt(string keyHex, string encryptedBase64)
        {
            // Decode to binary
            var encrypted = encryptedBase64.Decode64();
            var key = keyHex.DecodeHex();

            return Decrypt(key, encrypted);
        }

        public static byte[] Decrypt(byte[] key, byte[] encrypted)
        {
            if (key.Length < 16)
                throw new ArgumentException("Encryption key should be at least 16 bytes long", "key");

            // Use only first 256 bits
            if (key.Length > 32)
                key = key.Take(32).ToArray();

            if (encrypted.Length == 0)
                return new byte[0];

            if (encrypted.Length < 2)
                throw new Exception("Ciphertext is too short (version byte is missing)"); // TODO: Use custom exception!

            // Version byte is at offset 1.
            // We only support version 4 which seems to be the current.
            var version = encrypted[1];
            if (version != 4)
                throw new Exception(String.Format("Unsupported cipher format version ({0})", version)); // TODO: Use custom exception!

            if (encrypted.Length < 18)
                throw new Exception("Ciphertext is too short (IV is missing)"); // TODO: Use custom exception!

            // Split encrypted into IV and cipher
            var ciphertext = encrypted.Skip(18).ToArray();
            var iv = encrypted.Skip(2).Take(16).ToArray();

            return DecryptAes256Ccm(key, ciphertext, iv);
        }

        // TODO: See how this could be optimzed to reuse aes object w/o recreating it every time!
        public static byte[] DecryptAes256Ccm(byte[] key, byte[] ciphertext, byte[] iv)
        {
            var aes = new SjclAes(key);
            return SjclCcm.Decrypt(aes, ciphertext, iv, new byte[0], 8);
        }

        // Computes password hash that is sent to the PB server instead of the plain text password
        public static string ComputePasswordHash(string username, string password)
        {
            return Pbkdf2Sha256(password, Sha1Hex(username), 10000, 256);
        }

        // Computes the KEK (key encryption key) which is used to encrypt/decrypt the actual key
        // with which all the data is encrypted.
        public static string ComputeKek(string password, string salt, Fetcher.DerivationRules derivationRules)
        {
            var client = Math.Max(0, derivationRules.ClientIterationCount);
            var server = Math.Max(1, derivationRules.ServerIterationCount);

            var step1 = Pbkdf2Sha1  (        password, salt,      1, 512);
            var step2 = Pbkdf2Sha256(           step1, salt, client, 512);
            var step3 = Pbkdf2Sha256(           step2, salt, server, 256);
            var step4 = Pbkdf2Sha1  (step3 + password, salt,      1, 512);

            return step4;
        }

        public static string Sha1Hex(string text)
        {
            using (var sha = new SHA1Managed())
                return sha.ComputeHash(text.ToBytes()).ToHex();
        }

        public static string Pbkdf2Sha1(string password, string salt, int iterationCount, int bits)
        {
            return Pbkdf2Hex(password, salt, iterationCount, bits, Pbkdf2.GenerateSha1);
        }

        public static string Pbkdf2Sha256(string password, string salt, int iterationCount, int bits)
        {
            return Pbkdf2Hex(password, salt, iterationCount, bits, Pbkdf2.GenerateSha256);
        }

        private static string Pbkdf2Hex(string password,
                                        string salt,
                                        int iterationCount,
                                        int bits,
                                        Func<string, string, int, int, byte[]> pbkdf2)
        {
            if (iterationCount <= 0)
                return password;

            return pbkdf2(password, salt, iterationCount, bits / 8).ToHex();
        }
    }
}
