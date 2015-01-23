// Copyright (C) 2015 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Linq;

namespace PasswordBox
{
    static class Crypto
    {
        public static byte[] Decrypt(string encryptedBase64, string keyHex)
        {
            // Decode to binary
            var encrypted = encryptedBase64.Decode64();
            var key = keyHex.DecodeHex();

            return Decrypt(encrypted, key);
        }

        public static byte[] Decrypt(byte[] encrypted, byte[] key)
        {
            if (encrypted.Length == 0)
                return new byte[0];

            if (encrypted.Length < 2)
                throw new Exception("Cipher text is too short (version byte is missing)"); // TODO: Use custom exception!

            // Version byte is at offset 1.
            // We only support version 4 which seems to be the current.
            var version = encrypted[1];
            if (version != 4)
                throw new Exception(string.Format("Unsupported cipher format version ({0})", version)); // TODO: Use custom exception!

            if (encrypted.Length < 18)
                throw new Exception("Cipher text is too short (IV is missing)"); // TODO: Use custom exception!

            // Split encrypted into IV and cipher
            var iv = encrypted.Skip(2).Take(16).ToArray();
            var cipher = encrypted.Skip(18).ToArray();

            return DecryptAes256Ccm(cipher, iv, key);
        }

        public static byte[] DecryptAes256Ccm(byte[] cipher, byte[] iv, byte[] key)
        {
            return new byte[0];
        }
    }
}
