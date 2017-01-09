// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.IO;
using System.Security.Cryptography;

namespace StickyPassword
{
    static class Crypto
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

        public static byte[] Md5(string text)
        {
            using (var md5 = MD5.Create())
                return md5.ComputeHash(text.ToBytes());
        }

        public static byte[] DecryptAes256(byte[] ciphertext, byte[] key)
        {
            using (var aes = CreateAes256Cbc(key))
            using (var decryptor = aes.CreateDecryptor())
            using (var stream = new MemoryStream(ciphertext, false))
            using (var cryptoStream = new CryptoStream(stream, decryptor, CryptoStreamMode.Read))
            using (var plaintext = new MemoryStream())
            {
                var buffer = new byte[256];
                int bytesRead;
                while ((bytesRead = cryptoStream.Read(buffer, 0, buffer.Length)) > 0)
                    plaintext.Write(buffer, 0, bytesRead);

                return plaintext.ToArray();
            }
        }

        private static AesManaged CreateAes256Cbc(byte[] key)
        {
            return new AesManaged
            {
                BlockSize = 128,
                KeySize = 256,
                Key = key,
                IV = new byte[16],
                Mode = CipherMode.CBC,
                Padding = PaddingMode.None
            };
        }
    }
}
