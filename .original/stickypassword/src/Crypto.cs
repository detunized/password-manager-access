// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.IO;
using System.Security.Cryptography;

namespace StickyPassword
{
    public static class Crypto
    {
        public static byte[] DecryptToken(string username, string password, byte[] encryptedToken)
        {
            var key = DeriveTokenKey(username, password);
            return DecryptAes256(encryptedToken, key);
        }

        public static byte[] DeriveTokenKey(string username, string password)
        {
            var salt = Md5(username.ToLower());
            var kdf = new Rfc2898DeriveBytes(password, salt, 5000);
            return kdf.GetBytes(32);
        }

        public static byte[] DeriveDbKey(string password, byte[] salt)
        {
            var kdf = new Rfc2898DeriveBytes(password, salt, 10000);
            return kdf.GetBytes(32);
        }

        public static byte[] Md5(string text)
        {
            using (var md5 = MD5.Create())
                return md5.ComputeHash(text.ToBytes());
        }

        public static byte[] DecryptAes256(byte[] ciphertext, byte[] key, PaddingMode padding = PaddingMode.None)
        {
            using (var aes = CreateAes256Cbc(key, padding))
            using (var decryptor = aes.CreateDecryptor())
            using (var stream = new MemoryStream(ciphertext, false))
            using (var cryptoStream = new CryptoStream(stream, decryptor, CryptoStreamMode.Read))
                return cryptoStream.ReadAll(256);
        }

        public static byte[] EncryptAes256(byte[] plaintext, byte[] key, PaddingMode padding = PaddingMode.None)
        {
            using (var aes = CreateAes256Cbc(key, padding))
            using (var encryptor = aes.CreateEncryptor())
            using (var stream = new MemoryStream(plaintext, false))
            using (var cryptoStream = new CryptoStream(stream, encryptor, CryptoStreamMode.Read))
                return cryptoStream.ReadAll(256);
        }

        private static AesManaged CreateAes256Cbc(byte[] key, PaddingMode padding)
        {
            return new AesManaged
            {
                BlockSize = 128,
                KeySize = 256,
                Key = key,
                IV = new byte[16],
                Mode = CipherMode.CBC,
                Padding = padding
            };
        }
    }
}
