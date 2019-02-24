// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Security.Cryptography;

namespace PasswordManagerAccess.Common
{
    internal static class Crypto
    {
        public static byte[] Pbkdf2Sha1(string password, byte[] salt, int iterations, int byteCount)
        {
            return Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA1, byteCount);
        }

        public static byte[] Pbkdf2Sha256(string password, byte[] salt, int iterations, int byteCount)
        {
            return Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA256, byteCount);
        }

        public static byte[] Pbkdf2Sha512(string password, byte[] salt, int iterations, int byteCount)
        {
            return Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA512, byteCount);
        }

        //
        // Private
        //

        private static byte[] Pbkdf2(string password,
                                     byte[] salt,
                                     int iterations,
                                     HashAlgorithmName hash,
                                     int byteCount)
        {
            using (var db = new Rfc2898DeriveBytes(password, salt, iterations, hash))
                return db.GetBytes(byteCount);
        }
    }
}
