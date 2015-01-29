// Copyright (C) 2015 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Linq;

namespace PasswordBox
{
    static class Crypto
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
                throw new Exception(string.Format("Unsupported cipher format version ({0})", version)); // TODO: Use custom exception!

            if (encrypted.Length < 18)
                throw new Exception("Ciphertext is too short (IV is missing)"); // TODO: Use custom exception!

            // Split encrypted into IV and cipher
            var ciphertext = encrypted.Skip(18).ToArray();
            var iv = encrypted.Skip(2).Take(16).ToArray();

            return DecryptAes256Ccm(key, ciphertext, iv);
        }

        public static byte[] DecryptAes256Ccm(byte[] key, byte[] ciphertext, byte[] iv)
        {
            var aes = new SjclAes(key);
            return SjclCcm.Decrypt(aes, ciphertext, iv, new byte[0], 8);
        }
    }
}
