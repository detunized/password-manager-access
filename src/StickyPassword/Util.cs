// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.IO;
using System.Security.Cryptography;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.StickyPassword
{
    internal static class Util
    {
        public static byte[] DecryptToken(string username, string password, byte[] encryptedToken)
        {
            var key = DeriveTokenKey(username, password);
            return Crypto.DecryptAes256CbcNoPadding(encryptedToken, AesIv, key);
        }

        public static byte[] DeriveTokenKey(string username, string password)
        {
            var salt = Crypto.Md5(username.ToLowerInvariant());
            return Crypto.Pbkdf2Sha1(password, salt, 5000, 32);
        }

        public static byte[] DeriveDbKey(string password, byte[] salt)
        {
            return Crypto.Pbkdf2Sha1(password, salt, 10000, 32);
        }

        // TODO: Move to Common
        public static byte[] EncryptAes256(byte[] plaintext, byte[] key, PaddingMode padding = PaddingMode.None)
        {
            using (var aes = CreateAes256Cbc(key, padding))
            using (var encryptor = aes.CreateEncryptor())
            using (var stream = new MemoryStream(plaintext, false))
            using (var cryptoStream = new CryptoStream(stream, encryptor, CryptoStreamMode.Read))
                return cryptoStream.ReadAll(256);
        }

        //
        // Private
        //

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

        //
        // Data
        //

        // Secutity fuckup: StickyPassword uses static zero IV in their encryption everywhere!
        public static readonly byte[] AesIv = new byte[16];
    }
}
