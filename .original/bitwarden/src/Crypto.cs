// Copyright (C) 2018 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

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
    }
}
