// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.IO;
using System.Security.Cryptography;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.RoboForm
{
    internal static class Crypto
    {
        public static byte[] RandomBytes(int size)
        {
            using (var random = new RNGCryptoServiceProvider())
            {
                var bytes = new byte[size];
                random.GetBytes(bytes);
                return bytes;
            }
        }

        public static string RandomDeviceId()
        {
            // All the device ids returned by the server seem to be in this format.
            // Example: B57192ee77db5e5989c5ef7e091b119ea
            return "B" + RandomBytes(16).ToHex();
        }

        public static byte[] ComputeClientKey(string password, AuthInfo authInfo)
        {
            return Hmac(HashPassword(password, authInfo), "Client Key".ToBytes());
        }

        public static byte[] Hmac(byte[] salt, byte[] message)
        {
            using (var hmac = new HMACSHA256 {Key = salt})
                return hmac.ComputeHash(message);
        }

        public static byte[] Md5(byte[] data)
        {
            using (var md5 = MD5.Create())
                return md5.ComputeHash(data);
        }

        public static byte[] DecryptAes256(byte[] ciphertext,
                                           byte[] key,
                                           byte[] iv,
                                           PaddingMode padding)
        {
            using (var aes = CreateAes256Cbc(key, iv, padding))
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

        //
        // Internal
        //

        internal static byte[] HashPassword(string password, AuthInfo authInfo)
        {
            var passwordBytes = password.ToBytes();
            if (authInfo.IsMd5)
                passwordBytes = Md5(passwordBytes);

            return Pbkdf2.GenerateSha256(passwordBytes, authInfo.Salt, authInfo.IterationCount, 32);
        }

        internal static byte[] Sha256(byte[] data)
        {
            using (var sha = new SHA256Managed())
                return sha.ComputeHash(data);
        }

        internal static AesManaged CreateAes256Cbc(byte[] key, byte[] iv, PaddingMode padding)
        {
            return new AesManaged
            {
                BlockSize = 128,
                KeySize = 256,
                Key = key,
                IV = iv,
                Mode = CipherMode.CBC,
                Padding = padding
            };
        }
    }
}
