// Copyright (C) 2018 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace Bitwarden
{
    internal static class Crypto
    {
        public static byte[] DeriveKey(string username, string password, int iterations)
        {
            return Pbkdf2.GenerateSha256(password.ToBytes(), username.ToLower().Trim().ToBytes(), iterations, 32);
        }

        public static byte[] HashPassword(string password, byte[] key)
        {
            return Pbkdf2.GenerateSha256(key, password.ToBytes(), 1, 32);
        }

        public static byte[] Hmac(byte[] key, byte[] message)
        {
            using (var hmac = new HMACSHA256 {Key = key})
                return hmac.ComputeHash(message);
        }

        // This is the "expand" half of the "extract-expand" HKDF algorithm.
        // The length is fixed to 32 not to complicate things.
        // See https://tools.ietf.org/html/rfc5869
        public static byte[] HkdfExpand(byte[] prk, byte[] info)
        {
            return Hmac(prk, info.Concat(new byte[] {1}).ToArray());
        }

        public static byte[] ExpandKey(byte[] key)
        {
            var enc = HkdfExpand(key, "enc".ToBytes());
            var mac = HkdfExpand(key, "mac".ToBytes());
            return enc.Concat(mac).ToArray();
        }

        public static byte[] DecryptAes256(byte[] ciphertext, byte[] iv, byte[] key)
        {
            var mode = System.Security.Cryptography.CipherMode.CBC;
            try
            {
                using (var aes = new AesManaged {KeySize = 256, Key = key, Mode = mode, IV = iv})
                using (var decryptor = aes.CreateDecryptor())
                using (var inputStream = new MemoryStream(ciphertext, false))
                using (var cryptoStream = new CryptoStream(inputStream, decryptor, CryptoStreamMode.Read))
                using (var outputStream = new MemoryStream())
                {
                    cryptoStream.CopyTo(outputStream);
                    return outputStream.ToArray();
                }
            }
            catch (CryptographicException e)
            {
                throw new ClientException(ClientException.FailureReason.CryptoError, "Decryption failed", e);
            }
        }
    }
}
