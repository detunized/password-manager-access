// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Security.Cryptography;

namespace TrueKey
{
    internal static class Crypto
    {
        public static string HashPassword(string username, string password)
        {
            var salt = Sha256(username);
            var derived = Pbkdf2.Generate(password, salt, 10000, 32);
            return "tk-v1-" + derived.ToHex();
        }

        //
        // private
        //

        private static byte[] Sha256(string data)
        {
            using (var sha = new SHA256Managed())
                return sha.ComputeHash(data.ToBytes());
        }
    }
}
