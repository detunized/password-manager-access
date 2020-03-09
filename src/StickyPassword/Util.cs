// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

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

        public static byte[] Decrypt(byte[] ciphertext, byte[] key)
        {
            return Crypto.DecryptAes256Cbc(ciphertext, AesIv, key);
        }

        public static byte[] Encrypt(byte[] plaintext, byte[] key)
        {
            return Crypto.EncryptAes256Cbc(plaintext, AesIv, key);
        }

        //
        // Data
        //

        // Secutity fuckup: StickyPassword uses static zero IV in their encryption everywhere!
        private static readonly byte[] AesIv = new byte[16];
    }
}
