// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.Bitwarden
{
    internal static class Util
    {
        public static byte[] DeriveKey(string username, string password, int iterations)
        {
            return Pbkdf2.GenerateSha256(password.ToBytes(), username.ToLower().Trim().ToBytes(), iterations, 32);
        }

        public static byte[] HashPassword(string password, byte[] key)
        {
            return Pbkdf2.GenerateSha256(key, password.ToBytes(), 1, 32);
        }

        // This is the "expand" half of the "extract-expand" HKDF algorithm.
        // The length is fixed to 32 not to complicate things.
        // See https://tools.ietf.org/html/rfc5869
        public static byte[] HkdfExpand(byte[] prk, byte[] info)
        {
            return Crypto.HmacSha256(info.Concat(new byte[] { 1 }).ToArray(), prk);
        }

        public static byte[] ExpandKey(byte[] key)
        {
            var enc = HkdfExpand(key, "enc".ToBytes());
            var mac = HkdfExpand(key, "mac".ToBytes());

            return enc.Concat(mac).ToArray();
        }

        public static byte[] DecryptRsaSha1(byte[] ciphertext, byte[] privateKey)
        {
            return Crypto.DecryptRsaSha1(ciphertext, Pem.ParsePrivateKeyPkcs8(privateKey));
        }

        public static byte[] DecryptRsaSha256(byte[] ciphertext, byte[] privateKey)
        {
            return Crypto.DecryptRsaSha256(ciphertext, Pem.ParsePrivateKeyPkcs8(privateKey));
        }
    }
}
