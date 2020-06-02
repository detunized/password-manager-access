// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.IO;
using System.Security.Cryptography;

namespace PasswordManagerAccess.OpVault
{
    internal static class Crypto
    {
        public static KeyMac DeriveKek(byte[] password, byte[] salt, int iterations)
        {
            return new KeyMac(Pbkdf2.GenerateSha512(password, salt, iterations, 64));
        }

        public static byte[] Sha512(byte[] data)
        {
            using (var sha = new SHA512Managed())
                return sha.ComputeHash(data);
        }

        public static byte[] Hmac(byte[] message, KeyMac key)
        {
            using (var hmac = new HMACSHA256 {Key = key.MacKey})
                return hmac.ComputeHash(message);
        }

        public static byte[] DecryptAes(byte[] ciphertext, byte[] iv, KeyMac key)
        {
            using (var aes = CreateAes256Cbc(key, iv))
            using (var decryptor = aes.CreateDecryptor())
            using (var cryptoStream = new CryptoStream(new MemoryStream(ciphertext, false),
                                                       decryptor,
                                                       CryptoStreamMode.Read))
            using (var plaintextStream = new MemoryStream())
            {
                cryptoStream.CopyTo(plaintextStream);
                return plaintextStream.ToArray();
            }
        }

        private static AesManaged CreateAes256Cbc(KeyMac key, byte[] iv)
        {
            return new AesManaged
            {
                BlockSize = 128,
                KeySize = 256,
                Key = key.Key,
                IV = iv,
                Mode = CipherMode.CBC,
                Padding = PaddingMode.None
            };
        }
    }
}
