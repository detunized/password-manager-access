// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Linq;
using System.Security.Cryptography;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.LastPass
{
    internal static class Util
    {
        public static byte[] DeriveKey(string username, string password, int iterationCount)
        {
            if (iterationCount <= 0)
                throw new InternalErrorException("Iteration count should be positive");

            return iterationCount == 1
                ? Crypto.Sha256(username + password)
                : Pbkdf2.GenerateSha256(password.ToBytes(), username.ToBytes(), iterationCount, 32);
        }

        public static byte[] DeriveKeyHash(string username, string password, int iterationCount)
        {
            var key = DeriveKey(username, password, iterationCount);
            return iterationCount == 1 ? Crypto.Sha256(key.ToHex() + password) : Pbkdf2.GenerateSha256(key, password.ToBytes(), 1, 32);
        }

        public static string DecryptAes256Plain(byte[] data, byte[] encryptionKey, string defaultValue)
        {
            return DecryptAes256WithDefaultValue(data, encryptionKey, defaultValue, DecryptAes256Plain);
        }

        public static string DecryptAes256Base64(byte[] data, byte[] encryptionKey, string defaultValue)
        {
            return DecryptAes256WithDefaultValue(data, encryptionKey, defaultValue, DecryptAes256Base64);
        }

        public static string DecryptAes256Plain(byte[] data, byte[] encryptionKey)
        {
            var length = data.Length;
            if (length == 0)
                return "";

            if (data[0] == '!' && length % 16 == 1 && length > 32)
                return DecryptAes256CbcPlain(data, encryptionKey);

            return DecryptAes256EcbPlain(data, encryptionKey);
        }

        public static string DecryptAes256Base64(byte[] data, byte[] encryptionKey)
        {
            var length = data.Length;
            if (length == 0)
                return "";

            if (data[0] == '!')
                return DecryptAes256CbcBase64(data, encryptionKey);

            return DecryptAes256EcbBase64(data, encryptionKey);
        }

        public static string DecryptAes256EcbPlain(byte[] data, byte[] encryptionKey)
        {
            return DecryptAes256(data, encryptionKey, CipherMode.ECB);
        }

        public static string DecryptAes256EcbBase64(byte[] data, byte[] encryptionKey)
        {
            return DecryptAes256(data.ToUtf8().Decode64(), encryptionKey, CipherMode.ECB);
        }

        public static string DecryptAes256CbcPlain(byte[] data, byte[] encryptionKey)
        {
            return DecryptAes256(data.Skip(17).ToArray(), encryptionKey, CipherMode.CBC, data.Skip(1).Take(16).ToArray());
        }

        public static string DecryptAes256CbcBase64(byte[] data, byte[] encryptionKey)
        {
            return DecryptAes256(
                data.Skip(26).ToArray().ToUtf8().Decode64(),
                encryptionKey,
                CipherMode.CBC,
                data.Skip(1).Take(24).ToArray().ToUtf8().Decode64()
            );
        }

        public static string DecryptAes256(byte[] data, byte[] encryptionKey, CipherMode mode)
        {
            return DecryptAes256(data, encryptionKey, mode, new byte[16]);
        }

        public static string DecryptAes256(byte[] data, byte[] encryptionKey, CipherMode mode, byte[] iv)
        {
            if (data.Length == 0)
                return "";

            return Crypto.DecryptAes256(data, iv, encryptionKey, mode, PaddingMode.PKCS7).ToUtf8();
        }

        private static string DecryptAes256WithDefaultValue(
            byte[] data,
            byte[] encryptionKey,
            string defaultValue,
            Func<byte[], byte[], string> decrypt
        )
        {
            try
            {
                return decrypt(data, encryptionKey);
            }
            catch (CryptoException)
            {
                return defaultValue;
            }
        }
    }
}
